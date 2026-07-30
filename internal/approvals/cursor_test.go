package approvals

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

func TestCursorCodecRejectsLegacySearchCursor(t *testing.T) {
	now := time.Date(2026, time.July, 20, 10, 0, 0, 0, time.UTC)
	codec, err := newCursorCodec([]byte(strings.Repeat("k", 32)), func() time.Time {
		return now
	})
	if err != nil {
		t.Fatalf("newCursorCodec() error = %v", err)
	}
	legacyState := struct {
		Version          int            `json:"version"`
		CategoryID       string         `json:"categoryId"`
		CategoryRevision string         `json:"categoryRevision"`
		StartMS          int64          `json:"startMs"`
		EndMS            int64          `json:"endMs"`
		IssuedAt         int64          `json:"issuedAt"`
		Sources          []cursorSource `json:"sources"`
	}{
		Version:          1,
		CategoryID:       "firmware-flow",
		CategoryRevision: strings.Repeat("a", 64),
		StartMS:          now.Add(-24 * time.Hour).UnixMilli(),
		EndMS:            now.UnixMilli(),
		IssuedAt:         now.Unix(),
		Sources:          []cursorSource{{NextToken: 10}},
	}
	payload, err := json.Marshal(legacyState)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(payload) +
		cursorSeparator +
		base64.RawURLEncoding.EncodeToString(codec.sign(payload))

	if _, err := codec.Decode(raw); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Decode() legacy cursor error = %v; want invalid input", err)
	}
}

func TestCursorCodecEncodesCurrentSearchCursorWithSubjectBinding(t *testing.T) {
	now := time.Date(2026, time.July, 20, 10, 0, 0, 0, time.UTC)
	codec, err := newCursorCodec([]byte(strings.Repeat("k", 32)), func() time.Time {
		return now
	})
	if err != nil {
		t.Fatalf("newCursorCodec() error = %v", err)
	}
	state := cursorState{
		SubjectHash:      strings.Repeat("b", 64),
		CategoryID:       "firmware-flow",
		CategoryRevision: strings.Repeat("a", 64),
		StartMS:          now.Add(-24 * time.Hour).UnixMilli(),
		EndMS:            now.UnixMilli(),
		Sources:          []cursorSource{{NextToken: 10}},
	}

	raw, err := codec.Encode(state)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	payload := decodeCursorPayloadForTest(t, raw)
	var decoded cursorState
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() payload error = %v", err)
	}
	if decoded.Version != cursorVersion ||
		decoded.SubjectHash != state.SubjectHash {
		t.Errorf("Encode() payload = %#v", decoded)
	}
}

func TestCursorCodecPreservesCategoryCursorIssuance(t *testing.T) {
	now := time.Date(2026, time.July, 20, 10, 0, 0, 0, time.UTC)
	codec, err := newCursorCodec([]byte(strings.Repeat("k", 32)), func() time.Time {
		return now
	})
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := now.Add(-30 * time.Minute).Unix()
	raw, err := codec.EncodeCategory(categoryCursorState{
		SubjectHash:     strings.Repeat("b", 64),
		CatalogRevision: strings.Repeat("a", 64),
		Offset:          10,
		IssuedAt:        issuedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := codec.DecodeCategory(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.IssuedAt != issuedAt {
		t.Errorf("category cursor issuedAt = %d; want %d", decoded.IssuedAt, issuedAt)
	}
}

func decodeCursorPayloadForTest(t *testing.T, raw string) []byte {
	t.Helper()
	parts := strings.Split(raw, cursorSeparator)
	if len(parts) != 2 {
		t.Fatalf("cursor parts = %d; want 2", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode cursor payload: %v", err)
	}
	return payload
}
