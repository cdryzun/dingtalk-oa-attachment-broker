package attachments

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

func TestValidatePublicIPRejectsNonPublicDestinations(t *testing.T) {
	testCases := []struct {
		address string
		wantErr bool
	}{
		{address: "8.8.8.8"},
		{address: "1.1.1.1"},
		{address: "2606:4700:4700::1111"},
		{address: "127.0.0.1", wantErr: true},
		{address: "10.0.0.1", wantErr: true},
		{address: "172.16.0.1", wantErr: true},
		{address: "192.168.1.1", wantErr: true},
		{address: "169.254.1.1", wantErr: true},
		{address: "0.0.0.0", wantErr: true},
		{address: "::1", wantErr: true},
		{address: "fc00::1", wantErr: true},
		{address: "fe80::1", wantErr: true},
		{address: "ff02::1", wantErr: true},
		{address: "64:ff9b::808:808", wantErr: true},
		{address: "100:0:0:1::1", wantErr: true},
		{address: "2001::1", wantErr: true},
		{address: "2002:0808:0808::1", wantErr: true},
		{address: "3fff::1", wantErr: true},
		{address: "5f00::1", wantErr: true},
		{address: "fec0::1", wantErr: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.address, func(t *testing.T) {
			err := validatePublicIP(net.ParseIP(testCase.address))
			if (err != nil) != testCase.wantErr {
				t.Errorf("validatePublicIP(%q) error = %v; wantErr %v", testCase.address, err, testCase.wantErr)
			}
		})
	}
}

func TestSecureDownloaderPreservesEncodedAttachmentBytes(t *testing.T) {
	downloader, err := NewSecureDownloader(time.Minute, 1024)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := downloader.client.Transport.(*http.Transport)
	if !ok || !transport.DisableCompression {
		t.Fatalf("download transport = %#v; want compression disabled", downloader.client.Transport)
	}

	var acceptEncoding string
	downloader = newDownloaderForTest(
		&http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			acceptEncoding = request.Header.Get("Accept-Encoding")
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("attachment")),
				Request:    request,
			}, nil
		})},
		1024,
	)
	download, err := downloader.Open(
		context.Background(),
		mustURL(t, "https://download.example.test/file"),
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = download.Body.Close()
	if acceptEncoding != "identity" {
		t.Errorf("Accept-Encoding = %q; want identity", acceptEncoding)
	}
}

func TestSecureDialerRejectsPrivateDNSAnswers(t *testing.T) {
	dialer := secureDialer{
		resolver: staticResolver{addresses: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}},
		dialer:   &net.Dialer{Timeout: time.Second},
	}
	_, err := dialer.DialContext(context.Background(), "tcp", "download.example.test:443")
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("DialContext() error = %v; want forbidden", err)
	}
}

func TestDownloaderRejectsUnsafeURLAndOversizedContentLength(t *testing.T) {
	body := &trackingReadCloser{Reader: strings.NewReader("unused")}
	downloader := newDownloaderForTest(
		&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{"Content-Length": []string{"6"}},
				Body:          body,
				ContentLength: 6,
			}, nil
		})},
		5,
	)
	if _, err := downloader.Open(
		context.Background(),
		mustURL(t, "http://download.example.test/file"),
	); !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("insecure URL error = %v; want forbidden", err)
	}
	if _, err := downloader.Open(
		context.Background(),
		mustURL(t, "https://download.example.test/file"),
	); !errors.Is(err, domain.ErrTooLarge) {
		t.Errorf("oversized content error = %v; want too large", err)
	}
	if !body.closed {
		t.Error("oversized response body was not closed")
	}
}

func TestDownloaderStopsBeforeWritingMoreThanLimit(t *testing.T) {
	downloader := newDownloaderForTest(
		&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        make(http.Header),
				Body:          io.NopCloser(strings.NewReader("123456")),
				ContentLength: -1,
			}, nil
		})},
		5,
	)
	download, err := downloader.Open(
		context.Background(),
		mustURL(t, "https://download.example.test/file"),
	)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer download.Body.Close()

	var output bytes.Buffer
	_, err = io.Copy(&output, download.Body)
	if !errors.Is(err, domain.ErrTooLarge) {
		t.Fatalf("Copy() error = %v; want too large", err)
	}
	if output.String() != "12345" {
		t.Errorf("streamed bytes = %q; want exactly limit", output.String())
	}
}

func TestDownloaderPropagatesStreamingCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	body := &cancellableBody{ctx: ctx}
	downloader := newDownloaderForTest(
		&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        make(http.Header),
				Body:          body,
				ContentLength: -1,
			}, nil
		})},
		1024,
	)
	download, err := downloader.Open(ctx, mustURL(t, "https://download.example.test/file"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	cancel()
	buffer := make([]byte, 1)
	if _, err := download.Body.Read(buffer); !errors.Is(err, context.Canceled) {
		t.Fatalf("Read() error = %v; want context canceled", err)
	}
}

func TestSecureDownloaderValidatesConfiguration(t *testing.T) {
	if _, err := NewSecureDownloader(0, 1); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("zero timeout error = %v", err)
	}
	if _, err := NewSecureDownloader(time.Second, 0); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("zero limit error = %v", err)
	}
	downloader, err := NewSecureDownloader(time.Second, 1)
	if err != nil {
		t.Fatalf("NewSecureDownloader() error = %v", err)
	}
	if downloader.client == nil || downloader.maxBytes != 1 {
		t.Errorf("downloader = %#v", downloader)
	}
}

func TestDownloaderMapsResponseAndTransportFailures(t *testing.T) {
	testCases := []struct {
		name      string
		status    int
		transport error
		want      error
	}{
		{name: "not found", status: http.StatusNotFound, want: domain.ErrNotFound},
		{name: "unauthorized", status: http.StatusUnauthorized, want: domain.ErrForbidden},
		{name: "forbidden", status: http.StatusForbidden, want: domain.ErrForbidden},
		{name: "rate limited", status: http.StatusTooManyRequests, want: domain.ErrRateLimited},
		{name: "bad gateway", status: http.StatusBadGateway, want: domain.ErrUnavailable},
		{name: "service unavailable", status: http.StatusServiceUnavailable, want: domain.ErrUnavailable},
		{name: "gateway timeout", status: http.StatusGatewayTimeout, want: domain.ErrUnavailable},
		{name: "other status", status: http.StatusTeapot, want: domain.ErrUpstream},
		{name: "transport", transport: errors.New("network failed"), want: domain.ErrUpstream},
		{name: "forbidden transport", transport: domain.ErrForbidden, want: domain.ErrForbidden},
		{name: "cancelled", transport: context.Canceled, want: domain.ErrUnavailable},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			body := &trackingReadCloser{Reader: strings.NewReader("error")}
			downloader := newDownloaderForTest(
				&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
					if testCase.transport != nil {
						return nil, testCase.transport
					}
					return &http.Response{
						StatusCode:    testCase.status,
						Header:        make(http.Header),
						Body:          body,
						ContentLength: 5,
					}, nil
				})},
				10,
			)
			_, err := downloader.Open(
				context.Background(),
				mustURL(t, "https://download.example.test/file"),
			)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("Open() error = %v; want %v", err, testCase.want)
			}
			if testCase.transport == nil && !body.closed {
				t.Error("non-success response body was not closed")
			}
		})
	}
}

func TestDownloaderReturnsResponseMetadata(t *testing.T) {
	downloader := newDownloaderForTest(
		&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type": []string{"application/pdf"},
				},
				Body:          io.NopCloser(strings.NewReader("data")),
				ContentLength: 4,
			}, nil
		})},
		10,
	)
	download, err := downloader.Open(
		context.Background(),
		mustURL(t, "https://download.example.test/file"),
	)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer download.Body.Close()
	if download.ContentType != "application/pdf" || download.ContentLength != 4 {
		t.Errorf("download metadata = %#v", download)
	}
}

func TestSecureDialerValidatesResolutionAndConnectsOnlyToPublicIP(t *testing.T) {
	publicAddress := net.ParseIP("8.8.8.8")
	connection := &stubConnection{}
	dialer := secureDialer{
		resolver: staticResolver{addresses: []net.IPAddr{{IP: publicAddress}}},
		dialer: &stubNetworkDialer{
			connection: connection,
		},
	}
	got, err := dialer.DialContext(
		context.Background(),
		"tcp",
		"download.example.test:443",
	)
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if got != connection {
		t.Errorf("DialContext() connection = %#v", got)
	}

	testCases := []struct {
		name     string
		network  string
		address  string
		resolver staticResolver
		dialer   *stubNetworkDialer
		want     error
	}{
		{
			name:    "network",
			network: "udp",
			address: "download.example.test:443",
			want:    domain.ErrForbidden,
		},
		{
			name:    "address",
			network: "tcp",
			address: "missing-port",
			want:    domain.ErrForbidden,
		},
		{
			name:     "resolution",
			network:  "tcp",
			address:  "download.example.test:443",
			resolver: staticResolver{err: errors.New("DNS failed")},
			want:     domain.ErrUnavailable,
		},
		{
			name:     "empty resolution",
			network:  "tcp",
			address:  "download.example.test:443",
			resolver: staticResolver{},
			want:     domain.ErrUnavailable,
		},
		{
			name:    "connection failure",
			network: "tcp",
			address: "8.8.8.8:443",
			dialer:  &stubNetworkDialer{err: errors.New("connect failed")},
			want:    domain.ErrUnavailable,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			networkDialer := testCase.dialer
			if networkDialer == nil {
				networkDialer = &stubNetworkDialer{}
			}
			candidate := secureDialer{
				resolver: testCase.resolver,
				dialer:   networkDialer,
			}
			_, err := candidate.DialContext(
				context.Background(),
				testCase.network,
				testCase.address,
			)
			if !errors.Is(err, testCase.want) {
				t.Errorf("DialContext() error = %v; want %v", err, testCase.want)
			}
		})
	}
}

func TestRedirectValidation(t *testing.T) {
	request := &http.Request{URL: mustURL(t, "https://download.example.test/next")}
	if err := validateRedirect(request, nil); err != nil {
		t.Errorf("validateRedirect() error = %v", err)
	}
	previous := make([]*http.Request, maxDownloadRedirects)
	if err := validateRedirect(request, previous); !errors.Is(err, domain.ErrUpstream) {
		t.Errorf("redirect limit error = %v", err)
	}
	request.URL = mustURL(t, "http://download.example.test/next")
	if err := validateRedirect(request, nil); !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("insecure redirect error = %v", err)
	}
}

func TestLimitedReaderHandlesExactLimitAndUnderlyingErrors(t *testing.T) {
	reader := &limitedReadCloser{
		body:      io.NopCloser(strings.NewReader("12345")),
		remaining: 5,
	}
	if count, err := reader.Read(nil); count != 0 || err != nil {
		t.Errorf("empty Read() = %d, %v", count, err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("exact limit ReadAll() error = %v", err)
	}
	if string(output) != "12345" {
		t.Errorf("exact output = %q", output)
	}

	expected := errors.New("stream failed")
	erroringBody := &erroringReadCloser{err: expected}
	reader = &limitedReadCloser{
		body:      erroringBody,
		remaining: 5,
	}
	buffer := make([]byte, 1)
	if _, err := reader.Read(buffer); !errors.Is(err, expected) {
		t.Errorf("underlying Read() error = %v", err)
	}
	if !erroringBody.closed {
		t.Error("underlying body was not closed after read failure")
	}
	if _, err := reader.Read(buffer); !errors.Is(err, expected) {
		t.Errorf("terminal Read() error = %v; want original failure", err)
	}

	oversizedBody := &erroringReadCloser{reader: strings.NewReader("12")}
	reader = &limitedReadCloser{body: oversizedBody, remaining: 1}
	if _, err := io.ReadAll(reader); !errors.Is(err, domain.ErrTooLarge) {
		t.Errorf("oversized ReadAll() error = %v; want too large", err)
	}
	if !oversizedBody.closed {
		t.Error("underlying body was not closed after size limit")
	}

	noProgressBody := &erroringReadCloser{reader: noProgressReader{}}
	reader = &limitedReadCloser{body: noProgressBody}
	if _, err := reader.Read(buffer); !errors.Is(err, io.ErrNoProgress) {
		t.Errorf("no-progress Read() error = %v", err)
	}
	if !noProgressBody.closed {
		t.Error("underlying body was not closed after no-progress read")
	}
}

type staticResolver struct {
	addresses []net.IPAddr
	err       error
}

type stubNetworkDialer struct {
	connection net.Conn
	err        error
}

func (dialer *stubNetworkDialer) DialContext(
	context.Context,
	string,
	string,
) (net.Conn, error) {
	return dialer.connection, dialer.err
}

type stubConnection struct{}

func (*stubConnection) Read([]byte) (int, error)         { return 0, io.EOF }
func (*stubConnection) Write(buffer []byte) (int, error) { return len(buffer), nil }
func (*stubConnection) Close() error                     { return nil }
func (*stubConnection) LocalAddr() net.Addr              { return stubAddress("local") }
func (*stubConnection) RemoteAddr() net.Addr             { return stubAddress("remote") }
func (*stubConnection) SetDeadline(time.Time) error      { return nil }
func (*stubConnection) SetReadDeadline(time.Time) error  { return nil }
func (*stubConnection) SetWriteDeadline(time.Time) error { return nil }

type stubAddress string

func (address stubAddress) Network() string { return "tcp" }
func (address stubAddress) String() string  { return string(address) }

func (resolver staticResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return resolver.addresses, resolver.err
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type trackingReadCloser struct {
	io.Reader
	closed bool
}

func (reader *trackingReadCloser) Close() error {
	reader.closed = true
	return nil
}

type cancellableBody struct {
	ctx context.Context
}

type erroringReadCloser struct {
	reader io.Reader
	err    error
	closed bool
}

type noProgressReader struct{}

func (noProgressReader) Read([]byte) (int, error) {
	return 0, nil
}

func (reader *erroringReadCloser) Read(buffer []byte) (int, error) {
	if reader.reader != nil {
		return reader.reader.Read(buffer)
	}
	return 0, reader.err
}

func (reader *erroringReadCloser) Close() error {
	reader.closed = true
	return nil
}

func (body *cancellableBody) Read([]byte) (int, error) {
	<-body.ctx.Done()
	return 0, body.ctx.Err()
}

func (body *cancellableBody) Close() error {
	return nil
}

func mustURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL %q: %v", rawURL, err)
	}
	return parsed
}
