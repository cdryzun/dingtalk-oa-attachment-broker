package attachments

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

const maxDownloadRedirects = 5

type Download struct {
	Attachment    domain.Attachment
	Body          io.ReadCloser
	ContentType   string
	ContentLength int64
	MaxBytes      int64
}

type Downloader struct {
	client   *http.Client
	maxBytes int64
}

type ipResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type networkDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type secureDialer struct {
	resolver ipResolver
	dialer   networkDialer
}

func NewSecureDownloader(timeout time.Duration, maxBytes int64) (*Downloader, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("%w: download timeout must be positive", domain.ErrInvalidInput)
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("%w: download limit must be positive", domain.ErrInvalidInput)
	}
	dialer := secureDialer{
		resolver: net.DefaultResolver,
		dialer: &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return &Downloader{
		client: &http.Client{
			Transport:     transport,
			Timeout:       timeout,
			CheckRedirect: validateRedirect,
		},
		maxBytes: maxBytes,
	}, nil
}

func newDownloaderForTest(client *http.Client, maxBytes int64) *Downloader {
	if client.CheckRedirect == nil {
		client.CheckRedirect = validateRedirect
	}
	return &Downloader{client: client, maxBytes: maxBytes}
}

func (downloader *Downloader) Open(
	ctx context.Context,
	downloadURL *url.URL,
) (*Download, error) {
	if err := validateDownloadURL(downloadURL); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: create attachment request: %v", domain.ErrInvalidInput, err)
	}
	request.Header.Set("Accept", "application/octet-stream, */*")
	request.Header.Set("Accept-Encoding", "identity")

	response, err := downloader.client.Do(request)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: download request: %v", domain.ErrUnavailable, err)
		}
		if errors.Is(err, domain.ErrForbidden) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: download request failed", domain.ErrUpstream)
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		switch response.StatusCode {
		case http.StatusNotFound:
			return nil, fmt.Errorf("%w: attachment download", domain.ErrNotFound)
		case http.StatusUnauthorized, http.StatusForbidden:
			return nil, fmt.Errorf("%w: attachment download", domain.ErrForbidden)
		case http.StatusTooManyRequests:
			return nil, fmt.Errorf("%w: attachment download", domain.ErrRateLimited)
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return nil, fmt.Errorf("%w: attachment download", domain.ErrUnavailable)
		default:
			return nil, fmt.Errorf(
				"%w: attachment download returned status %d",
				domain.ErrUpstream,
				response.StatusCode,
			)
		}
	}
	contentEncoding := strings.TrimSpace(response.Header.Get("Content-Encoding"))
	if response.Uncompressed || contentEncoding != "" && !strings.EqualFold(contentEncoding, "identity") {
		_ = response.Body.Close()
		return nil, fmt.Errorf("%w: attachment download returned encoded content", domain.ErrUpstream)
	}
	if response.ContentLength > downloader.maxBytes {
		_ = response.Body.Close()
		return nil, fmt.Errorf("%w: attachment exceeds configured limit", domain.ErrTooLarge)
	}
	return &Download{
		Body:          &limitedReadCloser{body: response.Body, remaining: downloader.maxBytes},
		ContentType:   response.Header.Get("Content-Type"),
		ContentLength: response.ContentLength,
		MaxBytes:      downloader.maxBytes,
	}, nil
}

func (dialer secureDialer) DialContext(
	ctx context.Context,
	network string,
	address string,
) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("%w: unsupported download network", domain.ErrForbidden)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid download address", domain.ErrForbidden)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return nil, fmt.Errorf("%w: invalid download port", domain.ErrForbidden)
	}

	var addresses []net.IPAddr
	if literal := net.ParseIP(host); literal != nil {
		addresses = []net.IPAddr{{IP: literal}}
	} else {
		addresses, err = dialer.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("%w: resolve download host: %v", domain.ErrUnavailable, err)
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("%w: download host has no addresses", domain.ErrUnavailable)
	}
	for _, candidate := range addresses {
		if err := validatePublicIP(candidate.IP); err != nil {
			return nil, err
		}
	}

	var dialErrors []error
	for _, candidate := range addresses {
		connection, dialErr := dialer.dialer.DialContext(
			ctx,
			network,
			net.JoinHostPort(candidate.IP.String(), port),
		)
		if dialErr == nil {
			return connection, nil
		}
		dialErrors = append(dialErrors, dialErr)
	}
	return nil, fmt.Errorf("%w: connect download host: %v", domain.ErrUnavailable, errors.Join(dialErrors...))
}

func validatePublicIP(ip net.IP) error {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() {
		return fmt.Errorf("%w: download target is not a public IP address", domain.ErrForbidden)
	}
	if ip.To4() == nil && !publicIPv6Network.Contains(ip) {
		return fmt.Errorf("%w: download target is outside the public IPv6 allocation", domain.ErrForbidden)
	}
	for _, network := range reservedNetworks {
		if network.Contains(ip) {
			return fmt.Errorf("%w: download target is a reserved IP address", domain.ErrForbidden)
		}
	}
	return nil
}

var publicIPv6Network = mustNetworks("2000::/3")[0]

var reservedNetworks = mustNetworks(
	"0.0.0.0/8",
	"100.64.0.0/10",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"240.0.0.0/4",
	"2001::/23",
	"2001:db8::/32",
	"2002::/16",
	"3fff::/20",
)

func mustNetworks(values ...string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic("invalid built-in IP network: " + value)
		}
		networks = append(networks, network)
	}
	return networks
}

func validateRedirect(request *http.Request, previous []*http.Request) error {
	if len(previous) >= maxDownloadRedirects {
		return fmt.Errorf("%w: too many attachment redirects", domain.ErrUpstream)
	}
	return validateDownloadURL(request.URL)
}

func validateDownloadURL(downloadURL *url.URL) error {
	if downloadURL == nil || downloadURL.Scheme != "https" || downloadURL.Hostname() == "" ||
		downloadURL.User != nil {
		return fmt.Errorf("%w: unsafe attachment download URL", domain.ErrForbidden)
	}
	return nil
}

type limitedReadCloser struct {
	body        io.ReadCloser
	remaining   int64
	terminalErr error
}

func (reader *limitedReadCloser) Read(buffer []byte) (int, error) {
	if reader.terminalErr != nil {
		return 0, reader.terminalErr
	}
	if len(buffer) == 0 {
		return 0, nil
	}
	if reader.remaining > 0 {
		if int64(len(buffer)) > reader.remaining {
			buffer = buffer[:reader.remaining]
		}
		count, err := reader.body.Read(buffer)
		reader.remaining -= int64(count)
		if count > 0 && err == io.EOF {
			reader.terminalErr = io.EOF
			_ = reader.body.Close()
			return count, nil
		}
		if err != nil {
			reader.terminalErr = err
			_ = reader.body.Close()
		}
		return count, err
	}

	var probe [1]byte
	count, err := reader.body.Read(probe[:])
	if count > 0 {
		reader.terminalErr = fmt.Errorf("%w: attachment exceeds configured limit", domain.ErrTooLarge)
		_ = reader.body.Close()
		return 0, reader.terminalErr
	}
	if err != nil {
		reader.terminalErr = err
		_ = reader.body.Close()
		return 0, err
	}
	reader.terminalErr = io.ErrNoProgress
	_ = reader.body.Close()
	return 0, reader.terminalErr
}

func (reader *limitedReadCloser) Close() error {
	return reader.body.Close()
}
