package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

const (
	userCodeAlphabet                  = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	authorizationRejectionTimeout     = 5 * time.Second
	authorizationRejectionRetryDelay  = 100 * time.Millisecond
	deviceAuthorizationCreateAttempts = 5
)

type DeviceAuthorization struct {
	DeviceCodeHash []byte
	UserCode       string
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

type SessionSeed struct {
	AccessTokenHash  []byte
	RefreshTokenHash []byte
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}

type Repository interface {
	CreateDeviceAuthorization(context.Context, DeviceAuthorization) error
	BindOAuthState(context.Context, string, []byte, time.Time) error
	RejectOAuthState(context.Context, []byte, time.Time) error
	ClaimOAuthState(context.Context, []byte, time.Time) ([]byte, error)
	RejectDeviceAuthorization(context.Context, []byte, time.Time) error
	CompleteDeviceAuthorization(context.Context, []byte, domain.User, time.Time) error
	ExchangeDeviceAuthorization(context.Context, []byte, SessionSeed, time.Time) (domain.User, error)
	GetSessionByAccessToken(context.Context, []byte, time.Time) (domain.User, error)
	RotateSession(context.Context, []byte, SessionSeed, time.Time) (domain.User, error)
	RevokeSession(context.Context, []byte, time.Time) error
}

type IdentityToken struct {
	AccessToken string
	CorpID      string
}

type IdentityProfile struct {
	UnionID     string
	DisplayName string
}

type IdentityProvider interface {
	ExchangeAuthorizationCode(context.Context, string) (IdentityToken, error)
	CurrentUser(context.Context, string) (IdentityProfile, error)
	UserIDByUnionID(context.Context, string) (string, error)
}

type TokenGenerator interface {
	Token() (string, error)
	UserCode() (string, error)
}

type Options struct {
	Repository       Repository
	IdentityProvider IdentityProvider
	Hasher           *Hasher
	PublicBaseURL    *url.URL
	AuthorizeURL     *url.URL
	ClientID         string
	CorpID           string
	DeviceCodeTTL    time.Duration
	AccessTokenTTL   time.Duration
	RefreshTokenTTL  time.Duration
	PollInterval     time.Duration
	Now              func() time.Time
}

type Service struct {
	repository       Repository
	identityProvider IdentityProvider
	hasher           *Hasher
	publicBaseURL    *url.URL
	authorizeURL     *url.URL
	clientID         string
	corpID           string
	deviceCodeTTL    time.Duration
	accessTokenTTL   time.Duration
	refreshTokenTTL  time.Duration
	pollInterval     time.Duration
	now              func() time.Time
	generator        TokenGenerator
}

type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	ExpiresIn               int64  `json:"expiresIn"`
	Interval                int64  `json:"interval"`
}

type SessionResponse struct {
	AccessToken      string `json:"accessToken"`
	TokenType        string `json:"tokenType"`
	ExpiresIn        int64  `json:"expiresIn"`
	RefreshToken     string `json:"refreshToken"`
	RefreshExpiresIn int64  `json:"refreshExpiresIn"`
}

func NewService(options Options) (*Service, error) {
	if options.Repository == nil {
		return nil, fmt.Errorf("repository is required")
	}
	if options.IdentityProvider == nil {
		return nil, fmt.Errorf("identity provider is required")
	}
	if options.Hasher == nil {
		return nil, fmt.Errorf("hasher is required")
	}
	if options.PublicBaseURL == nil {
		return nil, fmt.Errorf("public base URL is required")
	}
	if options.AuthorizeURL == nil {
		return nil, fmt.Errorf("authorize URL is required")
	}
	if strings.TrimSpace(options.ClientID) == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	if strings.TrimSpace(options.CorpID) == "" {
		return nil, fmt.Errorf("corp ID is required")
	}
	if options.DeviceCodeTTL < time.Second || options.AccessTokenTTL < time.Second ||
		options.RefreshTokenTTL < time.Second || options.PollInterval < time.Second {
		return nil, fmt.Errorf("authorization durations must be at least one second")
	}
	if options.DeviceCodeTTL%time.Second != 0 || options.AccessTokenTTL%time.Second != 0 ||
		options.RefreshTokenTTL%time.Second != 0 || options.PollInterval%time.Second != 0 {
		return nil, fmt.Errorf("authorization durations must use whole seconds")
	}
	if options.PollInterval >= options.DeviceCodeTTL {
		return nil, fmt.Errorf("poll interval must be less than device code lifetime")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Service{
		repository:       options.Repository,
		identityProvider: options.IdentityProvider,
		hasher:           options.Hasher,
		publicBaseURL:    cloneURL(options.PublicBaseURL),
		authorizeURL:     cloneURL(options.AuthorizeURL),
		clientID:         options.ClientID,
		corpID:           options.CorpID,
		deviceCodeTTL:    options.DeviceCodeTTL,
		accessTokenTTL:   options.AccessTokenTTL,
		refreshTokenTTL:  options.RefreshTokenTTL,
		pollInterval:     options.PollInterval,
		now:              now,
		generator:        newCryptoGenerator(rand.Reader),
	}, nil
}

func (service *Service) CreateDeviceAuthorization(
	ctx context.Context,
) (DeviceAuthorizationResponse, error) {
	var deviceCode string
	var userCode string
	for attempt := range deviceAuthorizationCreateAttempts {
		var err error
		deviceCode, err = service.generator.Token()
		if err != nil {
			return DeviceAuthorizationResponse{}, fmt.Errorf("generate device code: %w", err)
		}
		userCode, err = service.generator.UserCode()
		if err != nil {
			return DeviceAuthorizationResponse{}, fmt.Errorf("generate user code: %w", err)
		}
		deviceCodeHash, err := service.hasher.Hash(deviceCode)
		if err != nil {
			return DeviceAuthorizationResponse{}, fmt.Errorf("hash device code: %w", err)
		}
		now := service.now()
		err = service.repository.CreateDeviceAuthorization(ctx, DeviceAuthorization{
			DeviceCodeHash: deviceCodeHash,
			UserCode:       userCode,
			CreatedAt:      now,
			ExpiresAt:      now.Add(service.deviceCodeTTL),
		})
		if err == nil {
			break
		}
		if !errors.Is(err, domain.ErrConflict) || attempt == deviceAuthorizationCreateAttempts-1 {
			return DeviceAuthorizationResponse{}, fmt.Errorf("persist device authorization: %w", err)
		}
	}

	verificationURI := service.resolvePublicPath("/auth/dingtalk/start")
	completeURI := cloneURL(verificationURI)
	query := completeURI.Query()
	query.Set("user_code", userCode)
	completeURI.RawQuery = query.Encode()

	return DeviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI.String(),
		VerificationURIComplete: completeURI.String(),
		ExpiresIn:               int64(service.deviceCodeTTL.Seconds()),
		Interval:                int64(service.pollInterval.Seconds()),
	}, nil
}

func (service *Service) StartAuthorization(ctx context.Context, userCode, confirmation string) (string, error) {
	userCode = strings.TrimSpace(userCode)
	if userCode == "" {
		return "", fmt.Errorf("%w: user code is required", domain.ErrInvalidInput)
	}
	confirmation = strings.TrimSpace(confirmation)
	if decoded, err := hex.DecodeString(confirmation); err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("%w: authorization confirmation is invalid", domain.ErrInvalidInput)
	}
	stateSeed, err := service.hasher.Hash("oauth-state\x00" + userCode + "\x00" + confirmation)
	if err != nil {
		return "", fmt.Errorf("derive OAuth state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateSeed)
	stateHash, err := service.hasher.Hash(state)
	if err != nil {
		return "", fmt.Errorf("hash OAuth state: %w", err)
	}
	if err := service.repository.BindOAuthState(ctx, userCode, stateHash, service.now()); err != nil {
		return "", fmt.Errorf("bind OAuth state: %w", err)
	}

	redirectURL := service.resolvePublicPath("/auth/dingtalk/callback")
	authorizeURL := cloneURL(service.authorizeURL)
	query := authorizeURL.Query()
	query.Set("client_id", service.clientID)
	query.Set("redirect_uri", redirectURL.String())
	query.Set("response_type", "code")
	query.Set("scope", "openid corpid")
	query.Set("state", state)
	query.Set("prompt", "consent")
	authorizeURL.RawQuery = query.Encode()
	return authorizeURL.String(), nil
}

func (service *Service) RejectAuthorization(ctx context.Context, state string) error {
	if strings.TrimSpace(state) == "" {
		return fmt.Errorf("%w: state is required", domain.ErrInvalidInput)
	}
	stateHash, err := service.hasher.Hash(state)
	if err != nil {
		return fmt.Errorf("hash OAuth state: %w", err)
	}
	rejectionContext, cancel := context.WithTimeout(
		context.WithoutCancel(ctx),
		authorizationRejectionTimeout,
	)
	defer cancel()
	if err := service.repository.RejectOAuthState(
		rejectionContext,
		stateHash,
		service.now(),
	); err != nil {
		return fmt.Errorf("reject OAuth state: %w", err)
	}
	return nil
}

func (service *Service) CompleteAuthorization(
	ctx context.Context,
	state string,
	code string,
) (resultErr error) {
	if strings.TrimSpace(state) == "" || strings.TrimSpace(code) == "" {
		return fmt.Errorf("%w: state and code are required", domain.ErrInvalidInput)
	}
	stateHash, err := service.hasher.Hash(state)
	if err != nil {
		return fmt.Errorf("hash OAuth state: %w", err)
	}
	deviceCodeHash, err := service.repository.ClaimOAuthState(ctx, stateHash, service.now())
	if err != nil {
		return fmt.Errorf("claim OAuth state: %w", err)
	}
	defer func() {
		if resultErr == nil {
			return
		}
		if rejectErr := service.rejectClaimedAuthorization(ctx, deviceCodeHash); rejectErr != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf("reject failed device authorization: %w", rejectErr),
			)
		}
	}()
	identityToken, err := service.identityProvider.ExchangeAuthorizationCode(ctx, code)
	if err != nil {
		return fmt.Errorf("exchange DingTalk authorization code: %w", err)
	}
	if identityToken.CorpID != service.corpID {
		return fmt.Errorf("%w: DingTalk corporation does not match", domain.ErrForbidden)
	}
	if identityToken.AccessToken == "" {
		return fmt.Errorf("%w: DingTalk user token is empty", domain.ErrUpstream)
	}
	profile, err := service.identityProvider.CurrentUser(ctx, identityToken.AccessToken)
	if err != nil {
		return fmt.Errorf("get DingTalk current user: %w", err)
	}
	if profile.UnionID == "" {
		return fmt.Errorf("%w: DingTalk union ID is empty", domain.ErrUpstream)
	}
	userID, err := service.identityProvider.UserIDByUnionID(ctx, profile.UnionID)
	if err != nil {
		return fmt.Errorf("map DingTalk union ID to user ID: %w", err)
	}
	if userID == "" {
		return fmt.Errorf("%w: DingTalk user ID is empty", domain.ErrUpstream)
	}
	if err := service.repository.CompleteDeviceAuthorization(ctx, deviceCodeHash, domain.User{
		CorpID:      identityToken.CorpID,
		UserID:      userID,
		UnionID:     profile.UnionID,
		DisplayName: profile.DisplayName,
	}, service.now()); err != nil {
		return fmt.Errorf("complete device authorization: %w", err)
	}
	return nil
}

func (service *Service) rejectClaimedAuthorization(
	ctx context.Context,
	deviceCodeHash []byte,
) error {
	rejectionContext, cancel := context.WithTimeout(
		context.WithoutCancel(ctx),
		authorizationRejectionTimeout,
	)
	defer cancel()
	for {
		err := service.repository.RejectDeviceAuthorization(
			rejectionContext,
			deviceCodeHash,
			service.now(),
		)
		if err == nil {
			return nil
		}
		if !errors.Is(err, domain.ErrUnavailable) {
			return err
		}
		timer := time.NewTimer(authorizationRejectionRetryDelay)
		select {
		case <-rejectionContext.Done():
			timer.Stop()
			return errors.Join(err, rejectionContext.Err())
		case <-timer.C:
		}
	}
}

func (service *Service) ExchangeDeviceAuthorization(
	ctx context.Context,
	deviceCode string,
) (SessionResponse, error) {
	deviceCodeHash, err := service.hasher.Hash(deviceCode)
	if err != nil {
		return SessionResponse{}, fmt.Errorf("%w: device code is required", domain.ErrInvalidInput)
	}
	session, response, err := service.newSession()
	if err != nil {
		return SessionResponse{}, err
	}
	if _, err := service.repository.ExchangeDeviceAuthorization(
		ctx,
		deviceCodeHash,
		session,
		service.now(),
	); err != nil {
		return SessionResponse{}, fmt.Errorf("exchange device authorization: %w", err)
	}
	return response, nil
}

func (service *Service) Authenticate(ctx context.Context, accessToken string) (domain.User, error) {
	accessTokenHash, err := service.hasher.Hash(accessToken)
	if err != nil {
		return domain.User{}, fmt.Errorf("%w: access token is required", domain.ErrUnauthorized)
	}
	user, err := service.repository.GetSessionByAccessToken(ctx, accessTokenHash, service.now())
	if err != nil {
		return domain.User{}, fmt.Errorf("authenticate session: %w", err)
	}
	return user, nil
}

func (service *Service) Refresh(ctx context.Context, refreshToken string) (SessionResponse, error) {
	refreshTokenHash, err := service.hasher.Hash(refreshToken)
	if err != nil {
		return SessionResponse{}, fmt.Errorf("%w: refresh token is required", domain.ErrUnauthorized)
	}
	session, response, err := service.newSession()
	if err != nil {
		return SessionResponse{}, err
	}
	if _, err := service.repository.RotateSession(
		ctx,
		refreshTokenHash,
		session,
		service.now(),
	); err != nil {
		return SessionResponse{}, fmt.Errorf("rotate session: %w", err)
	}
	return response, nil
}

func (service *Service) Revoke(ctx context.Context, accessToken string) error {
	accessTokenHash, err := service.hasher.Hash(accessToken)
	if err != nil {
		return fmt.Errorf("%w: access token is required", domain.ErrUnauthorized)
	}
	if err := service.repository.RevokeSession(ctx, accessTokenHash, service.now()); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (service *Service) newSession() (SessionSeed, SessionResponse, error) {
	accessToken, err := service.generator.Token()
	if err != nil {
		return SessionSeed{}, SessionResponse{}, fmt.Errorf("generate access token: %w", err)
	}
	refreshToken, err := service.generator.Token()
	if err != nil {
		return SessionSeed{}, SessionResponse{}, fmt.Errorf("generate refresh token: %w", err)
	}
	accessTokenHash, err := service.hasher.Hash(accessToken)
	if err != nil {
		return SessionSeed{}, SessionResponse{}, fmt.Errorf("hash access token: %w", err)
	}
	refreshTokenHash, err := service.hasher.Hash(refreshToken)
	if err != nil {
		return SessionSeed{}, SessionResponse{}, fmt.Errorf("hash refresh token: %w", err)
	}
	now := service.now()
	return SessionSeed{
			AccessTokenHash:  accessTokenHash,
			RefreshTokenHash: refreshTokenHash,
			AccessExpiresAt:  now.Add(service.accessTokenTTL),
			RefreshExpiresAt: now.Add(service.refreshTokenTTL),
		}, SessionResponse{
			AccessToken:      accessToken,
			TokenType:        "Bearer",
			ExpiresIn:        int64(service.accessTokenTTL.Seconds()),
			RefreshToken:     refreshToken,
			RefreshExpiresIn: int64(service.refreshTokenTTL.Seconds()),
		}, nil
}

func (service *Service) resolvePublicPath(path string) *url.URL {
	reference := &url.URL{Path: path}
	return service.publicBaseURL.ResolveReference(reference)
}

type Hasher struct {
	pepper []byte
}

func NewHasher(pepper string) *Hasher {
	return &Hasher{pepper: []byte(pepper)}
}

func (hasher *Hasher) Hash(credential string) ([]byte, error) {
	if credential == "" {
		return nil, fmt.Errorf("credential is required")
	}
	mac := hmac.New(sha256.New, hasher.pepper)
	if _, err := mac.Write([]byte(credential)); err != nil {
		return nil, fmt.Errorf("hash credential: %w", err)
	}
	return mac.Sum(nil), nil
}

type cryptoGenerator struct {
	reader io.Reader
}

func newCryptoGenerator(reader io.Reader) *cryptoGenerator {
	return &cryptoGenerator{reader: reader}
}

func (generator *cryptoGenerator) Token() (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(generator.reader, raw); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (generator *cryptoGenerator) UserCode() (string, error) {
	raw := make([]byte, 8)
	for index := range raw {
		value, err := rand.Int(generator.reader, big.NewInt(int64(len(userCodeAlphabet))))
		if err != nil {
			return "", fmt.Errorf("read random user code: %w", err)
		}
		raw[index] = userCodeAlphabet[value.Int64()]
	}
	return string(raw[:4]) + "-" + string(raw[4:]), nil
}

func cloneURL(value *url.URL) *url.URL {
	if value == nil {
		return &url.URL{}
	}
	cloned := *value
	return &cloned
}
