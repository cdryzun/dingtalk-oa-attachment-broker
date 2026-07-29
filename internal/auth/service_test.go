package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

func TestServiceCreatesDeviceAuthorizationWithoutPersistingRawCode(t *testing.T) {
	repository := &recordingRepository{}
	service := newTestService(repository, &identityProviderStub{})
	service.generator = &tokenGeneratorStub{
		tokens:    []string{"raw-device-code"},
		userCodes: []string{"ABCD-EFGH"},
	}

	got, err := service.CreateDeviceAuthorization(context.Background())
	if err != nil {
		t.Fatalf("CreateDeviceAuthorization() error = %v", err)
	}

	if got.DeviceCode != "raw-device-code" {
		t.Errorf("DeviceCode = %q; want raw-device-code", got.DeviceCode)
	}
	if got.UserCode != "ABCD-EFGH" {
		t.Errorf("UserCode = %q; want ABCD-EFGH", got.UserCode)
	}
	if got.VerificationURI != "https://broker.example.com/auth/dingtalk/start" {
		t.Errorf("VerificationURI = %q", got.VerificationURI)
	}
	if !strings.HasSuffix(got.VerificationURIComplete, "?user_code=ABCD-EFGH") {
		t.Errorf("VerificationURIComplete = %q", got.VerificationURIComplete)
	}
	if repository.createdDevice.UserCode != "ABCD-EFGH" {
		t.Errorf("stored user code = %q; want ABCD-EFGH", repository.createdDevice.UserCode)
	}
	if string(repository.createdDevice.DeviceCodeHash) == "raw-device-code" {
		t.Error("repository received the raw device code")
	}
	if repository.createdDevice.ExpiresAt.Sub(repository.createdDevice.CreatedAt) != 10*time.Minute {
		t.Errorf("device lifetime = %s; want 10m", repository.createdDevice.ExpiresAt.Sub(repository.createdDevice.CreatedAt))
	}
}

func TestServiceStartsDingTalkAuthorizationWithSingleUseState(t *testing.T) {
	repository := &recordingRepository{}
	service := newTestService(repository, &identityProviderStub{})
	service.generator = &tokenGeneratorStub{tokens: []string{"raw-oauth-state"}}

	got, err := service.StartAuthorization(context.Background(), "ABCD-EFGH")
	if err != nil {
		t.Fatalf("StartAuthorization() error = %v", err)
	}

	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Host != "login.dingtalk.com" {
		t.Errorf("authorization host = %q; want login.dingtalk.com", parsed.Host)
	}
	query := parsed.Query()
	assertString(t, query.Get("client_id"), "client-id")
	assertString(t, query.Get("redirect_uri"), "https://broker.example.com/auth/dingtalk/callback")
	assertString(t, query.Get("response_type"), "code")
	assertString(t, query.Get("scope"), "openid corpid")
	assertString(t, query.Get("prompt"), "consent")
	assertString(t, query.Get("state"), "raw-oauth-state")

	if repository.boundUserCode != "ABCD-EFGH" {
		t.Errorf("bound user code = %q; want ABCD-EFGH", repository.boundUserCode)
	}
	if string(repository.boundStateHash) == "raw-oauth-state" {
		t.Error("repository received the raw OAuth state")
	}
}

func TestServiceCompletesAuthorizationWithVerifiedEnterpriseUser(t *testing.T) {
	repository := &recordingRepository{}
	identity := &identityProviderStub{
		token: IdentityToken{AccessToken: "user-token", CorpID: "corp-id"},
		profile: IdentityProfile{
			UnionID:     "union-id",
			DisplayName: "Verified User",
		},
		userID: "user-id",
	}
	service := newTestService(repository, identity)

	err := service.CompleteAuthorization(context.Background(), "raw-state", "authorization-code")
	if err != nil {
		t.Fatalf("CompleteAuthorization() error = %v", err)
	}

	if identity.receivedCode != "authorization-code" {
		t.Errorf("identity provider code = %q", identity.receivedCode)
	}
	if identity.receivedUserToken != "user-token" {
		t.Errorf("identity provider user token = %q", identity.receivedUserToken)
	}
	if identity.receivedUnionID != "union-id" {
		t.Errorf("identity provider union ID = %q", identity.receivedUnionID)
	}
	wantUser := domain.User{
		CorpID:      "corp-id",
		UserID:      "user-id",
		UnionID:     "union-id",
		DisplayName: "Verified User",
	}
	if repository.completedUser != wantUser {
		t.Errorf("completed user = %#v; want %#v", repository.completedUser, wantUser)
	}
	if repository.claimCalls != 1 {
		t.Errorf("OAuth state claim calls = %d; want 1", repository.claimCalls)
	}
	if string(repository.claimStateHash) == "raw-state" {
		t.Error("repository received the raw OAuth state")
	}
	if string(repository.completedDeviceHash) != "claimed-device-hash" {
		t.Errorf("completed device hash = %q; want claimed hash", repository.completedDeviceHash)
	}
}

func TestServiceClaimsOAuthStateBeforeCallingDingTalk(t *testing.T) {
	repository := &recordingRepository{claimErr: domain.ErrUnauthorized}
	identity := &identityProviderStub{
		token: IdentityToken{AccessToken: "user-token", CorpID: "corp-id"},
		profile: IdentityProfile{
			UnionID:     "union-id",
			DisplayName: "Verified User",
		},
		userID: "user-id",
	}
	service := newTestService(repository, identity)

	err := service.CompleteAuthorization(context.Background(), "unknown-state", "authorization-code")
	if !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("CompleteAuthorization() error = %v; want ErrUnauthorized", err)
	}
	if identity.receivedCode != "" {
		t.Errorf("DingTalk received code %q before state validation", identity.receivedCode)
	}
	if repository.completeCalls != 0 {
		t.Error("repository completed an unclaimed authorization")
	}
}

func TestServiceRejectsAuthorizationFromAnotherCorporation(t *testing.T) {
	repository := &recordingRepository{}
	identity := &identityProviderStub{
		token: IdentityToken{AccessToken: "user-token", CorpID: "other-corp"},
	}
	service := newTestService(repository, identity)

	err := service.CompleteAuthorization(context.Background(), "state", "code")
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("CompleteAuthorization() error = %v; want ErrForbidden", err)
	}
	if repository.completeCalls != 0 {
		t.Error("repository was updated for a user from another corporation")
	}
}

func TestServiceExchangesApprovedDeviceCodeForOpaqueSession(t *testing.T) {
	repository := &recordingRepository{
		exchangeUser: domain.User{
			CorpID:      "corp-id",
			UserID:      "user-id",
			UnionID:     "union-id",
			DisplayName: "Verified User",
		},
	}
	service := newTestService(repository, &identityProviderStub{})
	service.generator = &tokenGeneratorStub{
		tokens: []string{"raw-access-token", "raw-refresh-token"},
	}

	got, err := service.ExchangeDeviceAuthorization(context.Background(), "raw-device-code")
	if err != nil {
		t.Fatalf("ExchangeDeviceAuthorization() error = %v", err)
	}

	assertString(t, got.AccessToken, "raw-access-token")
	assertString(t, got.RefreshToken, "raw-refresh-token")
	assertString(t, got.TokenType, "Bearer")
	if got.ExpiresIn != int64((8 * time.Hour).Seconds()) {
		t.Errorf("ExpiresIn = %d; want %d", got.ExpiresIn, int64((8 * time.Hour).Seconds()))
	}
	if string(repository.exchangeDeviceHash) == "raw-device-code" ||
		string(repository.exchangeSession.AccessTokenHash) == "raw-access-token" ||
		string(repository.exchangeSession.RefreshTokenHash) == "raw-refresh-token" {
		t.Error("repository received a raw credential")
	}
}

func TestServicePropagatesAuthorizationPending(t *testing.T) {
	repository := &recordingRepository{exchangeErr: domain.ErrAuthorizationPending}
	service := newTestService(repository, &identityProviderStub{})
	service.generator = &tokenGeneratorStub{
		tokens: []string{"unused-access", "unused-refresh"},
	}

	_, err := service.ExchangeDeviceAuthorization(context.Background(), "device-code")
	if !errors.Is(err, domain.ErrAuthorizationPending) {
		t.Fatalf("ExchangeDeviceAuthorization() error = %v; want ErrAuthorizationPending", err)
	}
}

func TestServiceAuthenticatesRefreshesAndRevokesHashedSessions(t *testing.T) {
	user := domain.User{CorpID: "corp-id", UserID: "user-id", UnionID: "union-id"}
	repository := &recordingRepository{
		sessionUser: user,
		rotateUser:  user,
	}
	service := newTestService(repository, &identityProviderStub{})

	gotUser, err := service.Authenticate(context.Background(), "access-token")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if gotUser != user {
		t.Errorf("Authenticate() user = %#v; want %#v", gotUser, user)
	}
	if string(repository.sessionAccessHash) == "access-token" {
		t.Error("Authenticate() sent a raw access token to the repository")
	}

	service.generator = &tokenGeneratorStub{
		tokens: []string{"new-access-token", "new-refresh-token"},
	}
	session, err := service.Refresh(context.Background(), "refresh-token")
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	assertString(t, session.AccessToken, "new-access-token")
	if string(repository.rotateRefreshHash) == "refresh-token" {
		t.Error("Refresh() sent a raw refresh token to the repository")
	}

	if err := service.Revoke(context.Background(), "access-token"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if string(repository.revokedAccessHash) == "access-token" {
		t.Error("Revoke() sent a raw access token to the repository")
	}
}

func TestHasherRejectsEmptyCredentials(t *testing.T) {
	hasher := NewHasher("01234567890123456789012345678901")
	if _, err := hasher.Hash(""); err == nil {
		t.Fatal("Hash() returned nil error for empty credential")
	}

	first, err := hasher.Hash("credential")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	second, err := hasher.Hash("credential")
	if err != nil {
		t.Fatalf("Hash() second error = %v", err)
	}
	if string(first) != string(second) {
		t.Error("Hash() is not deterministic")
	}
	if string(first) == "credential" {
		t.Error("Hash() returned the raw credential")
	}
}

func TestCreateAndStartAuthorizationErrorPaths(t *testing.T) {
	t.Run("device token generation", func(t *testing.T) {
		service := newTestService(&recordingRepository{}, &identityProviderStub{})
		service.generator = &tokenGeneratorStub{}
		if _, err := service.CreateDeviceAuthorization(context.Background()); err == nil {
			t.Fatal("CreateDeviceAuthorization() error = nil")
		}
	})
	t.Run("user code generation", func(t *testing.T) {
		service := newTestService(&recordingRepository{}, &identityProviderStub{})
		service.generator = &tokenGeneratorStub{tokens: []string{"device"}}
		if _, err := service.CreateDeviceAuthorization(context.Background()); err == nil {
			t.Fatal("CreateDeviceAuthorization() error = nil")
		}
	})
	t.Run("empty generated device token", func(t *testing.T) {
		service := newTestService(&recordingRepository{}, &identityProviderStub{})
		service.generator = &tokenGeneratorStub{
			tokens:    []string{""},
			userCodes: []string{"ABCD-EFGH"},
		}
		if _, err := service.CreateDeviceAuthorization(context.Background()); err == nil {
			t.Fatal("CreateDeviceAuthorization() error = nil")
		}
	})
	t.Run("repository create", func(t *testing.T) {
		service := newTestService(
			&recordingRepository{createErr: errors.New("write failed")},
			&identityProviderStub{},
		)
		service.generator = &tokenGeneratorStub{
			tokens:    []string{"device"},
			userCodes: []string{"ABCD-EFGH"},
		}
		if _, err := service.CreateDeviceAuthorization(context.Background()); err == nil {
			t.Fatal("CreateDeviceAuthorization() error = nil")
		}
	})
	t.Run("missing user code", func(t *testing.T) {
		service := newTestService(&recordingRepository{}, &identityProviderStub{})
		if _, err := service.StartAuthorization(context.Background(), " "); !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatalf("StartAuthorization() error = %v", err)
		}
	})
	t.Run("state generation", func(t *testing.T) {
		service := newTestService(&recordingRepository{}, &identityProviderStub{})
		service.generator = &tokenGeneratorStub{}
		if _, err := service.StartAuthorization(context.Background(), "ABCD-EFGH"); err == nil {
			t.Fatal("StartAuthorization() error = nil")
		}
	})
	t.Run("empty generated state", func(t *testing.T) {
		service := newTestService(&recordingRepository{}, &identityProviderStub{})
		service.generator = &tokenGeneratorStub{tokens: []string{""}}
		if _, err := service.StartAuthorization(context.Background(), "ABCD-EFGH"); err == nil {
			t.Fatal("StartAuthorization() error = nil")
		}
	})
	t.Run("repository bind", func(t *testing.T) {
		service := newTestService(
			&recordingRepository{bindErr: errors.New("write failed")},
			&identityProviderStub{},
		)
		service.generator = &tokenGeneratorStub{tokens: []string{"state"}}
		if _, err := service.StartAuthorization(context.Background(), "ABCD-EFGH"); err == nil {
			t.Fatal("StartAuthorization() error = nil")
		}
	})
}

func TestCompleteAuthorizationFailsClosedForIncompleteIdentity(t *testing.T) {
	upstreamFailure := errors.New("upstream failed")
	testCases := []struct {
		name     string
		state    string
		code     string
		identity identityProviderStub
		repoErr  error
		want     error
	}{
		{name: "missing state", code: "code", want: domain.ErrInvalidInput},
		{name: "missing code", state: "state", want: domain.ErrInvalidInput},
		{
			name:     "token exchange",
			state:    "state",
			code:     "code",
			identity: identityProviderStub{tokenErr: upstreamFailure},
			want:     upstreamFailure,
		},
		{
			name:     "empty access token",
			state:    "state",
			code:     "code",
			identity: identityProviderStub{token: IdentityToken{CorpID: "corp-id"}},
			want:     domain.ErrUpstream,
		},
		{
			name:  "current user",
			state: "state",
			code:  "code",
			identity: identityProviderStub{
				token:      IdentityToken{CorpID: "corp-id", AccessToken: "token"},
				profileErr: upstreamFailure,
			},
			want: upstreamFailure,
		},
		{
			name:  "empty union ID",
			state: "state",
			code:  "code",
			identity: identityProviderStub{
				token: IdentityToken{CorpID: "corp-id", AccessToken: "token"},
			},
			want: domain.ErrUpstream,
		},
		{
			name:  "user mapping",
			state: "state",
			code:  "code",
			identity: identityProviderStub{
				token:     IdentityToken{CorpID: "corp-id", AccessToken: "token"},
				profile:   IdentityProfile{UnionID: "union"},
				userIDErr: upstreamFailure,
			},
			want: upstreamFailure,
		},
		{
			name:  "empty user ID",
			state: "state",
			code:  "code",
			identity: identityProviderStub{
				token:   IdentityToken{CorpID: "corp-id", AccessToken: "token"},
				profile: IdentityProfile{UnionID: "union"},
			},
			want: domain.ErrUpstream,
		},
		{
			name:  "repository completion",
			state: "state",
			code:  "code",
			identity: identityProviderStub{
				token:   IdentityToken{CorpID: "corp-id", AccessToken: "token"},
				profile: IdentityProfile{UnionID: "union"},
				userID:  "user",
			},
			repoErr: upstreamFailure,
			want:    upstreamFailure,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			repository := &recordingRepository{completeErr: testCase.repoErr}
			identity := testCase.identity
			service := newTestService(repository, &identity)
			err := service.CompleteAuthorization(
				context.Background(),
				testCase.state,
				testCase.code,
			)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("CompleteAuthorization() error = %v; want %v", err, testCase.want)
			}
		})
	}
}

func TestSessionOperationsRejectInvalidCredentialsAndRepositoryFailures(t *testing.T) {
	repositoryFailure := errors.New("repository failed")

	service := newTestService(&recordingRepository{}, &identityProviderStub{})
	if _, err := service.ExchangeDeviceAuthorization(context.Background(), ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("empty device exchange error = %v", err)
	}

	service = newTestService(&recordingRepository{}, &identityProviderStub{})
	service.generator = &tokenGeneratorStub{}
	if _, err := service.ExchangeDeviceAuthorization(context.Background(), "device"); err == nil {
		t.Error("access token generation error = nil")
	}

	service = newTestService(&recordingRepository{}, &identityProviderStub{})
	service.generator = &tokenGeneratorStub{tokens: []string{"access"}}
	if _, err := service.ExchangeDeviceAuthorization(context.Background(), "device"); err == nil {
		t.Error("refresh token generation error = nil")
	}

	service = newTestService(&recordingRepository{}, &identityProviderStub{})
	service.generator = &tokenGeneratorStub{tokens: []string{"", "refresh"}}
	if _, err := service.ExchangeDeviceAuthorization(context.Background(), "device"); err == nil {
		t.Error("access token hashing error = nil")
	}

	service = newTestService(&recordingRepository{}, &identityProviderStub{})
	service.generator = &tokenGeneratorStub{tokens: []string{"access", ""}}
	if _, err := service.ExchangeDeviceAuthorization(context.Background(), "device"); err == nil {
		t.Error("refresh token hashing error = nil")
	}

	service = newTestService(
		&recordingRepository{exchangeErr: repositoryFailure},
		&identityProviderStub{},
	)
	service.generator = &tokenGeneratorStub{tokens: []string{"access", "refresh"}}
	if _, err := service.ExchangeDeviceAuthorization(context.Background(), "device"); !errors.Is(err, repositoryFailure) {
		t.Errorf("exchange repository error = %v", err)
	}

	service = newTestService(
		&recordingRepository{sessionErr: repositoryFailure},
		&identityProviderStub{},
	)
	if _, err := service.Authenticate(context.Background(), "access"); !errors.Is(err, repositoryFailure) {
		t.Errorf("authenticate repository error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), ""); !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("empty access token error = %v", err)
	}

	service = newTestService(&recordingRepository{}, &identityProviderStub{})
	if _, err := service.Refresh(context.Background(), ""); !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("empty refresh token error = %v", err)
	}
	service = newTestService(
		&recordingRepository{rotateErr: repositoryFailure},
		&identityProviderStub{},
	)
	service.generator = &tokenGeneratorStub{tokens: []string{"access", "refresh"}}
	if _, err := service.Refresh(context.Background(), "old-refresh"); !errors.Is(err, repositoryFailure) {
		t.Errorf("refresh repository error = %v", err)
	}

	service = newTestService(&recordingRepository{}, &identityProviderStub{})
	if err := service.Revoke(context.Background(), ""); !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("empty revoke token error = %v", err)
	}
	service = newTestService(
		&recordingRepository{revokeErr: repositoryFailure},
		&identityProviderStub{},
	)
	if err := service.Revoke(context.Background(), "access"); !errors.Is(err, repositoryFailure) {
		t.Errorf("revoke repository error = %v", err)
	}
}

func TestCryptoGeneratorProducesOpaqueTokensAndHandlesEntropyFailures(t *testing.T) {
	generator := newCryptoGenerator(bytes.NewReader(bytes.Repeat([]byte{1}, 128)))
	token, err := generator.Token()
	if err != nil || token == "" {
		t.Fatalf("Token() = %q, %v", token, err)
	}
	userCode, err := generator.UserCode()
	if err != nil {
		t.Fatalf("UserCode() error = %v", err)
	}
	if len(userCode) != 9 || userCode[4] != '-' {
		t.Errorf("UserCode() = %q", userCode)
	}

	failing := newCryptoGenerator(errorReader{})
	if _, err := failing.Token(); err == nil {
		t.Error("Token() entropy error = nil")
	}
	if _, err := failing.UserCode(); err == nil {
		t.Error("UserCode() entropy error = nil")
	}
}

func TestNewServiceValidatesDependenciesAndAppliesDefaultClock(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{name: "repository", mutate: func(options *Options) { options.Repository = nil }},
		{name: "identity provider", mutate: func(options *Options) { options.IdentityProvider = nil }},
		{name: "hasher", mutate: func(options *Options) { options.Hasher = nil }},
		{name: "public URL", mutate: func(options *Options) { options.PublicBaseURL = nil }},
		{name: "authorize URL", mutate: func(options *Options) { options.AuthorizeURL = nil }},
		{name: "client ID", mutate: func(options *Options) { options.ClientID = "" }},
		{name: "corp ID", mutate: func(options *Options) { options.CorpID = "" }},
		{name: "durations", mutate: func(options *Options) { options.PollInterval = 0 }},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			options := validServiceOptions(t)
			testCase.mutate(&options)
			if _, err := NewService(options); err == nil {
				t.Fatal("NewService() error = nil; want invalid options")
			}
		})
	}
	service := newTestService(&recordingRepository{}, &identityProviderStub{})
	if service.now == nil {
		t.Error("NewService() did not apply a default clock")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func newTestService(repository Repository, identity IdentityProvider) *Service {
	options := validServiceOptions(nil)
	options.Repository = repository
	options.IdentityProvider = identity
	service, err := NewService(options)
	if err != nil {
		panic(err)
	}
	return service
}

func validServiceOptions(t *testing.T) Options {
	if t != nil {
		t.Helper()
	}
	publicBaseURL, err := url.Parse("https://broker.example.com")
	if err != nil {
		panic(err)
	}
	authorizeURL, err := url.Parse("https://login.dingtalk.com/oauth2/auth")
	if err != nil {
		panic(err)
	}
	return Options{
		Repository:       &recordingRepository{},
		IdentityProvider: &identityProviderStub{},
		Hasher:           NewHasher("01234567890123456789012345678901"),
		PublicBaseURL:    publicBaseURL,
		AuthorizeURL:     authorizeURL,
		ClientID:         "client-id",
		CorpID:           "corp-id",
		DeviceCodeTTL:    10 * time.Minute,
		AccessTokenTTL:   8 * time.Hour,
		RefreshTokenTTL:  30 * 24 * time.Hour,
		PollInterval:     5 * time.Second,
		Now:              func() time.Time { return time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC) },
	}
}

type recordingRepository struct {
	createdDevice       DeviceAuthorization
	createErr           error
	boundUserCode       string
	boundStateHash      []byte
	bindErr             error
	claimStateHash      []byte
	claimedDeviceHash   []byte
	claimCalls          int
	claimErr            error
	completedDeviceHash []byte
	completedUser       domain.User
	completeCalls       int
	completeErr         error
	exchangeDeviceHash  []byte
	exchangeSession     SessionSeed
	exchangeUser        domain.User
	exchangeErr         error
	sessionAccessHash   []byte
	sessionUser         domain.User
	sessionErr          error
	rotateRefreshHash   []byte
	rotateSession       SessionSeed
	rotateUser          domain.User
	rotateErr           error
	revokedAccessHash   []byte
	revokeErr           error
}

func (repository *recordingRepository) CreateDeviceAuthorization(
	_ context.Context,
	authorization DeviceAuthorization,
) error {
	repository.createdDevice = authorization
	return repository.createErr
}

func (repository *recordingRepository) BindOAuthState(
	_ context.Context,
	userCode string,
	stateHash []byte,
	_ time.Time,
) error {
	repository.boundUserCode = userCode
	repository.boundStateHash = append([]byte(nil), stateHash...)
	return repository.bindErr
}

func (repository *recordingRepository) ClaimOAuthState(
	_ context.Context,
	stateHash []byte,
	_ time.Time,
) ([]byte, error) {
	repository.claimCalls++
	repository.claimStateHash = append([]byte(nil), stateHash...)
	if repository.claimErr != nil {
		return nil, repository.claimErr
	}
	if len(repository.claimedDeviceHash) == 0 {
		return []byte("claimed-device-hash"), nil
	}
	return append([]byte(nil), repository.claimedDeviceHash...), nil
}

func (repository *recordingRepository) CompleteDeviceAuthorization(
	_ context.Context,
	deviceCodeHash []byte,
	user domain.User,
	_ time.Time,
) error {
	repository.completeCalls++
	repository.completedDeviceHash = append([]byte(nil), deviceCodeHash...)
	repository.completedUser = user
	return repository.completeErr
}

func (repository *recordingRepository) ExchangeDeviceAuthorization(
	_ context.Context,
	deviceCodeHash []byte,
	session SessionSeed,
	_ time.Time,
) (domain.User, error) {
	repository.exchangeDeviceHash = append([]byte(nil), deviceCodeHash...)
	repository.exchangeSession = session
	return repository.exchangeUser, repository.exchangeErr
}

func (repository *recordingRepository) GetSessionByAccessToken(
	_ context.Context,
	accessTokenHash []byte,
	_ time.Time,
) (domain.User, error) {
	repository.sessionAccessHash = append([]byte(nil), accessTokenHash...)
	return repository.sessionUser, repository.sessionErr
}

func (repository *recordingRepository) RotateSession(
	_ context.Context,
	refreshTokenHash []byte,
	session SessionSeed,
	_ time.Time,
) (domain.User, error) {
	repository.rotateRefreshHash = append([]byte(nil), refreshTokenHash...)
	repository.rotateSession = session
	return repository.rotateUser, repository.rotateErr
}

func (repository *recordingRepository) RevokeSession(
	_ context.Context,
	accessTokenHash []byte,
	_ time.Time,
) error {
	repository.revokedAccessHash = append([]byte(nil), accessTokenHash...)
	return repository.revokeErr
}

type identityProviderStub struct {
	token             IdentityToken
	tokenErr          error
	profile           IdentityProfile
	profileErr        error
	userID            string
	userIDErr         error
	receivedCode      string
	receivedUserToken string
	receivedUnionID   string
}

func (provider *identityProviderStub) ExchangeAuthorizationCode(
	_ context.Context,
	code string,
) (IdentityToken, error) {
	provider.receivedCode = code
	return provider.token, provider.tokenErr
}

func (provider *identityProviderStub) CurrentUser(
	_ context.Context,
	userAccessToken string,
) (IdentityProfile, error) {
	provider.receivedUserToken = userAccessToken
	return provider.profile, provider.profileErr
}

func (provider *identityProviderStub) UserIDByUnionID(
	_ context.Context,
	unionID string,
) (string, error) {
	provider.receivedUnionID = unionID
	return provider.userID, provider.userIDErr
}

type tokenGeneratorStub struct {
	tokens    []string
	userCodes []string
}

func (generator *tokenGeneratorStub) Token() (string, error) {
	if len(generator.tokens) == 0 {
		return "", errors.New("no token configured")
	}
	result := generator.tokens[0]
	generator.tokens = generator.tokens[1:]
	return result, nil
}

func (generator *tokenGeneratorStub) UserCode() (string, error) {
	if len(generator.userCodes) == 0 {
		return "", errors.New("no user code configured")
	}
	result := generator.userCodes[0]
	generator.userCodes = generator.userCodes[1:]
	return result, nil
}

func assertString(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}
