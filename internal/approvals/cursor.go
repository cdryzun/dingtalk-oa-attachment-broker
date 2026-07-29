package approvals

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

const (
	cursorVersion            = 3
	categoryCursorVersion    = 2
	maxCursorBytes           = 8 * 1024
	defaultCursorTTL         = time.Hour
	cursorClockSkew          = time.Minute
	cursorSeparator          = "."
	cursorSignatureBytes     = sha256.Size
	searchCursorErrorLabel   = "approval search cursor"
	categoryCursorErrorLabel = "approval category cursor"
)

type cursorSource struct {
	NextToken int64 `json:"nextToken"`
	Done      bool  `json:"done"`
}

type cursorState struct {
	Version          int            `json:"version"`
	SubjectHash      string         `json:"subjectHash"`
	CategoryID       string         `json:"categoryId"`
	CategoryRevision string         `json:"categoryRevision"`
	Keyword          string         `json:"keyword,omitempty"`
	StartMS          int64          `json:"startMs"`
	EndMS            int64          `json:"endMs"`
	IssuedAt         int64          `json:"issuedAt"`
	Sources          []cursorSource `json:"sources"`
}

type categoryCursorState struct {
	Version         int    `json:"version"`
	SubjectHash     string `json:"subjectHash"`
	Keyword         string `json:"keyword,omitempty"`
	CatalogRevision string `json:"catalogRevision"`
	Offset          int    `json:"offset"`
	IssuedAt        int64  `json:"issuedAt"`
}

type cursorCodec struct {
	key []byte
	now func() time.Time
	ttl time.Duration
}

func newCursorCodec(key []byte, now func() time.Time) (*cursorCodec, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("%w: cursor signing key must contain at least 32 bytes", domain.ErrInvalidInput)
	}
	if now == nil {
		now = time.Now
	}
	return &cursorCodec{
		key: append([]byte(nil), key...),
		now: now,
		ttl: defaultCursorTTL,
	}, nil
}

func (codec *cursorCodec) Encode(state cursorState) (string, error) {
	now := codec.now().UTC()
	state.Version = cursorVersion
	state.IssuedAt = now.Unix()
	return codec.encodePayload(state, searchCursorErrorLabel)
}

func (codec *cursorCodec) Decode(raw string) (cursorState, error) {
	payload, err := codec.decodePayload(raw, searchCursorErrorLabel)
	if err != nil {
		return cursorState{}, err
	}
	var state cursorState
	if err := decodeCursorPayload(payload, &state, searchCursorErrorLabel); err != nil {
		return cursorState{}, err
	}
	now := codec.now().UTC()
	issuedAt := time.Unix(state.IssuedAt, 0)
	if state.Version != cursorVersion ||
		state.SubjectHash == "" ||
		state.CategoryID == "" ||
		state.CategoryRevision == "" ||
		state.StartMS <= 0 ||
		state.EndMS <= state.StartMS ||
		len(state.Sources) == 0 ||
		issuedAt.After(now.Add(cursorClockSkew)) ||
		issuedAt.Before(now.Add(-codec.ttl)) {
		return cursorState{}, fmt.Errorf(
			"%w: %s has expired or invalid state",
			domain.ErrInvalidInput,
			searchCursorErrorLabel,
		)
	}
	return state, nil
}

func (codec *cursorCodec) EncodeCategory(state categoryCursorState) (string, error) {
	state.Version = categoryCursorVersion
	state.IssuedAt = codec.now().UTC().Unix()
	return codec.encodePayload(state, categoryCursorErrorLabel)
}

func (codec *cursorCodec) DecodeCategory(raw string) (categoryCursorState, error) {
	payload, err := codec.decodePayload(raw, categoryCursorErrorLabel)
	if err != nil {
		return categoryCursorState{}, err
	}
	var state categoryCursorState
	if err := decodeCursorPayload(payload, &state, categoryCursorErrorLabel); err != nil {
		return categoryCursorState{}, err
	}
	now := codec.now().UTC()
	issuedAt := time.Unix(state.IssuedAt, 0)
	if state.Version != categoryCursorVersion ||
		state.SubjectHash == "" ||
		state.CatalogRevision == "" ||
		state.Offset < 0 ||
		issuedAt.After(now.Add(cursorClockSkew)) ||
		issuedAt.Before(now.Add(-codec.ttl)) {
		return categoryCursorState{}, fmt.Errorf(
			"%w: %s has expired or invalid state",
			domain.ErrInvalidInput,
			categoryCursorErrorLabel,
		)
	}
	return state, nil
}

func (codec *cursorCodec) encodePayload(value any, label string) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode %s: %w", label, err)
	}
	if len(payload) > maxCursorBytes {
		return "", fmt.Errorf("%w: %s payload is too large", domain.ErrInvalidInput, label)
	}
	signature := codec.sign(payload)
	return base64.RawURLEncoding.EncodeToString(payload) +
		cursorSeparator +
		base64.RawURLEncoding.EncodeToString(signature), nil
}

func (codec *cursorCodec) decodePayload(raw, label string) ([]byte, error) {
	if len(raw) == 0 || len(raw) > maxCursorBytes*2 {
		return nil, fmt.Errorf("%w: %s is invalid", domain.ErrInvalidInput, label)
	}
	parts := strings.Split(raw, cursorSeparator)
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w: %s is invalid", domain.ErrInvalidInput, label)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) == 0 || len(payload) > maxCursorBytes {
		return nil, fmt.Errorf("%w: %s is invalid", domain.ErrInvalidInput, label)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != cursorSignatureBytes ||
		!hmac.Equal(signature, codec.sign(payload)) {
		return nil, fmt.Errorf("%w: %s signature is invalid", domain.ErrInvalidInput, label)
	}
	return payload, nil
}

func decodeCursorPayload(payload []byte, destination any, label string) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("%w: decode %s", domain.ErrInvalidInput, label)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("%w: %s has trailing data", domain.ErrInvalidInput, label)
	}
	return nil
}

func (codec *cursorCodec) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, codec.key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}
