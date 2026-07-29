package approvals

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

type auditContextKey struct{}

var searchNow = time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)

func TestSearchFiltersByAuthorizationAndAttachmentPresence(t *testing.T) {
	provider := &fakeProvider{
		pages: map[string]domain.ApprovalInstanceIDPage{
			"PROC-DIRECT": {
				ProcessInstanceIDs: []string{
					"direct-authorized",
					"direct-outsider",
					"firmware",
					"no-attachment",
				},
				NextToken: int64Pointer(20),
			},
		},
		approvals: map[string]domain.Approval{
			"direct-authorized": approvalFixture(
				"direct-authorized",
				"Version release",
				"authorized",
				true,
			),
			"direct-outsider": approvalFixture(
				"direct-outsider",
				"Version release",
				"outsider",
				true,
			),
			"firmware": approvalFixture(
				"firmware",
				"Order review",
				"authorized",
				true,
				domain.FormValue{Value: "Android 固件版本发布"},
			),
			"no-attachment": approvalFixture(
				"no-attachment",
				"MCU版本发布",
				"authorized",
				false,
			),
		},
	}
	audit := &recordingAudit{}
	service := newTestService(t, provider, audit)
	user := domain.User{CorpID: "corp", UserID: "authorized"}

	result, err := service.Search(
		context.Background(),
		user,
		SearchQuery{CategoryID: service.categoryID(user, "PROC-DIRECT"), Limit: 10},
		"request-id",
	)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(result.Items) != 2 {
		t.Fatalf("items = %#v; want two", result.Items)
	}
	if result.Items[0].ProcessInstanceID != "firmware" &&
		result.Items[1].ProcessInstanceID != "firmware" {
		t.Errorf("items = %#v; firmware item missing", result.Items)
	}
	if result.NextCursor == "" {
		t.Error("next cursor is empty; filtered source has another page")
	}
	if provider.totalRequested() != 10 {
		t.Errorf("total DingTalk page size = %d; want 10", provider.totalRequested())
	}

	decisions := audit.decisions()
	if decisions["direct-authorized"] != domain.AuditDecisionAllowed ||
		decisions["firmware"] != domain.AuditDecisionAllowed ||
		decisions["direct-outsider"] != domain.AuditDecisionDenied {
		t.Errorf("audit decisions = %#v", decisions)
	}
}

func TestDeniedSearchAuditSurvivesRequestCancellation(t *testing.T) {
	provider := &fakeProvider{
		pages: map[string]domain.ApprovalInstanceIDPage{
			"PROC-DIRECT": {ProcessInstanceIDs: []string{"failed"}},
		},
		errors: map[string]error{"failed": domain.ErrUpstream},
	}
	audit := &recordingAudit{}
	service := newTestService(t, provider, audit)
	user := domain.User{CorpID: "corp", UserID: "authorized"}
	requestContext := context.WithValue(context.Background(), auditContextKey{}, "trace-value")
	requestContext, cancel := context.WithCancel(requestContext)
	cancel()

	_, err := service.Search(
		requestContext,
		user,
		SearchQuery{CategoryID: service.categoryID(user, "PROC-DIRECT"), Limit: 10},
		"request-id",
	)
	if !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("Search() error = %v; want upstream error", err)
	}
	if audit.decisions()["failed"] != domain.AuditDecisionDenied {
		t.Fatalf("audit events = %#v; want denied event", audit.events)
	}
	if audit.contextErr != nil {
		t.Errorf("audit context error at write = %v", audit.contextErr)
	}
	if audit.contextValue != "trace-value" {
		t.Errorf("audit context value = %#v", audit.contextValue)
	}
	if remaining := time.Until(audit.deadline); remaining <= 0 || remaining > 5*time.Second {
		t.Errorf("audit deadline remaining = %v; want within 5s", remaining)
	}
}

func TestSearchCursorContinuesProcessCodeAndRejectsTampering(t *testing.T) {
	provider := &fakeProvider{
		pages: map[string]domain.ApprovalInstanceIDPage{
			"PROC-DIRECT": {NextToken: int64Pointer(5)},
		},
		approvals: map[string]domain.Approval{},
	}
	service := newTestService(t, provider, &recordingAudit{})
	user := domain.User{CorpID: "corp", UserID: "authorized"}
	categoryID := service.categoryID(user, "PROC-DIRECT")
	first, err := service.Search(
		context.Background(),
		user,
		SearchQuery{CategoryID: categoryID, Limit: 10},
		"request-one",
	)
	if err != nil {
		t.Fatalf("first Search() error = %v", err)
	}
	if first.NextCursor == "" {
		t.Fatal("first cursor is empty")
	}
	payloadPart := strings.Split(first.NextCursor, ".")[0]
	payload, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		t.Fatalf("decode cursor payload: %v", err)
	}
	if strings.Contains(string(payload), "PROC-") ||
		strings.Contains(string(payload), "固件") ||
		strings.Contains(string(payload), "authorized") ||
		strings.Contains(string(payload), `"corp"`) {
		t.Errorf("cursor payload exposed category rules or identity: %s", payload)
	}

	provider.mu.Lock()
	provider.pages["PROC-DIRECT"] = domain.ApprovalInstanceIDPage{}
	provider.queries = nil
	provider.mu.Unlock()
	if _, err := service.Search(
		context.Background(),
		user,
		SearchQuery{
			CategoryID: categoryID,
			Cursor:     first.NextCursor,
			Limit:      10,
		},
		"request-two",
	); err != nil {
		t.Fatalf("cursor Search() error = %v", err)
	}
	queries := provider.snapshotQueries()
	if len(queries) != 1 || queries[0].NextToken != 5 {
		t.Errorf("continued queries = %#v", queries)
	}

	tampered := first.NextCursor[:len(first.NextCursor)-1] + "A"
	if _, err := service.Search(
		context.Background(),
		user,
		SearchQuery{CategoryID: categoryID, Cursor: tampered, Limit: 10},
		"request-three",
	); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("tampered cursor error = %v; want invalid input", err)
	}
}

func TestSearchCurrentCursorRejectsDifferentUser(t *testing.T) {
	provider := &fakeProvider{
		pages: map[string]domain.ApprovalInstanceIDPage{
			"PROC-DIRECT": {NextToken: int64Pointer(5)},
		},
		approvals: map[string]domain.Approval{},
	}
	service := newTestService(t, provider, &recordingAudit{})
	user := domain.User{CorpID: "corp", UserID: "authorized"}
	categoryID := service.categoryID(user, "PROC-DIRECT")

	first, err := service.Search(
		context.Background(),
		user,
		SearchQuery{CategoryID: categoryID, Limit: 10},
		"request-current-cursor",
	)
	if err != nil {
		t.Fatalf("first Search() error = %v", err)
	}
	if first.NextCursor == "" {
		t.Fatal("first cursor is empty")
	}
	if _, err := service.Search(
		context.Background(),
		domain.User{CorpID: "corp", UserID: "different-user"},
		SearchQuery{
			CategoryID: categoryID,
			Cursor:     first.NextCursor,
			Limit:      10,
		},
		"request-different-user",
	); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("different user cursor error = %v; want not found", err)
	}
}

func TestSearchLegacyCursorRestartsWithoutReusingPaginationPosition(t *testing.T) {
	provider := &fakeProvider{
		pages: map[string]domain.ApprovalInstanceIDPage{
			"PROC-DIRECT": {NextToken: int64Pointer(9)},
		},
		approvals: map[string]domain.Approval{},
	}
	service := newTestService(t, provider, &recordingAudit{})
	user := domain.User{CorpID: "corp", UserID: "different-user"}
	category := domain.ApprovalCategory{
		ID:      service.categoryID(user, "PROC-DIRECT"),
		Sources: []domain.ApprovalCategorySource{{ProcessCode: "PROC-DIRECT"}},
	}
	legacyRaw, err := service.cursor.encodePayload(struct {
		Version          int            `json:"version"`
		CategoryID       string         `json:"categoryId"`
		CategoryRevision string         `json:"categoryRevision"`
		StartMS          int64          `json:"startMs"`
		EndMS            int64          `json:"endMs"`
		IssuedAt         int64          `json:"issuedAt"`
		Sources          []cursorSource `json:"sources"`
	}{
		Version:          cursorVersion - 1,
		CategoryID:       category.ID,
		CategoryRevision: categoryRevision(category),
		StartMS:          searchNow.Add(-24 * time.Hour).UnixMilli(),
		EndMS:            searchNow.UnixMilli(),
		IssuedAt:         searchNow.Unix(),
		Sources:          []cursorSource{{NextToken: 5}},
	}, searchCursorErrorLabel)
	if err != nil {
		t.Fatalf("encode legacy cursor: %v", err)
	}

	_, err = service.Search(
		context.Background(),
		user,
		SearchQuery{
			CategoryID: category.ID,
			Cursor:     legacyRaw,
			Limit:      10,
		},
		"request-legacy-cursor",
	)
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("legacy cursor Search() error = %v; want invalid input", err)
	}
	if len(provider.snapshotQueries()) != 0 {
		t.Errorf("legacy cursor must be rejected before querying DingTalk")
	}
}

func TestSearchValidatesTimeRangeAndFailsClosedOnUpstreamErrors(t *testing.T) {
	provider := &fakeProvider{
		pages: map[string]domain.ApprovalInstanceIDPage{
			"PROC-DIRECT": {ProcessInstanceIDs: []string{"failed"}},
		},
		approvals: map[string]domain.Approval{},
		errors:    map[string]error{"failed": domain.ErrUpstream},
	}
	audit := &recordingAudit{}
	service := newTestService(t, provider, audit)
	user := domain.User{CorpID: "corp", UserID: "authorized"}
	categoryID := service.categoryID(user, "PROC-DIRECT")
	tooOld := searchNow.Add(-366 * 24 * time.Hour)
	if _, err := service.Search(
		context.Background(),
		user,
		SearchQuery{
			CategoryID:   categoryID,
			CreatedAfter: &tooOld,
			Limit:        10,
		},
		"request-old",
	); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("old range error = %v; want invalid input", err)
	}

	if _, err := service.Search(
		context.Background(),
		user,
		SearchQuery{CategoryID: categoryID, Limit: 10},
		"request-upstream",
	); !errors.Is(err, domain.ErrUpstream) {
		t.Errorf("upstream error = %v; want upstream", err)
	}
	decisions := audit.decisions()
	if decisions["failed"] != domain.AuditDecisionDenied {
		t.Errorf("audit decisions = %#v", decisions)
	}
}

func TestSearchClassifiesInvalidUpstreamInstanceIDsAsUpstreamFailure(t *testing.T) {
	provider := &fakeProvider{
		pages: map[string]domain.ApprovalInstanceIDPage{
			"PROC-DIRECT": {ProcessInstanceIDs: []string{"PROC-TEMPLATE"}},
		},
	}
	service := newTestService(t, provider, &recordingAudit{})
	user := domain.User{CorpID: "corp", UserID: "authorized"}

	if _, err := service.Search(
		context.Background(),
		user,
		SearchQuery{
			CategoryID: service.categoryID(user, "PROC-DIRECT"),
			Limit:      10,
		},
		"request-invalid-upstream-id",
	); !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("Search() error = %v; want upstream", err)
	}
}

func TestSearchSortsByParsedCreationTime(t *testing.T) {
	earlier := approvalFixture("earlier", "Earlier", "authorized", true)
	earlier.CreateTime = "2026-07-18T08:30:00+08:00"
	later := approvalFixture("later", "Later", "authorized", true)
	later.CreateTime = "2026-07-18T01:00:00Z"
	provider := &fakeProvider{
		pages: map[string]domain.ApprovalInstanceIDPage{
			"PROC-DIRECT": {
				ProcessInstanceIDs: []string{"earlier", "later"},
			},
		},
		approvals: map[string]domain.Approval{
			"earlier": earlier,
			"later":   later,
		},
	}
	service := newTestService(t, provider, &recordingAudit{})
	user := domain.User{CorpID: "corp", UserID: "authorized"}

	result, err := service.Search(
		context.Background(),
		user,
		SearchQuery{CategoryID: service.categoryID(user, "PROC-DIRECT"), Limit: 10},
		"request-sort",
	)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(result.Items) != 2 ||
		result.Items[0].ProcessInstanceID != "later" ||
		result.Items[1].ProcessInstanceID != "earlier" {
		t.Errorf("sorted items = %#v", result.Items)
	}
}

func TestSearchRateLimitIsScopedByCorporationAndUser(t *testing.T) {
	service := newTestServiceWithRate(
		t,
		&fakeProvider{},
		&recordingAudit{},
		1,
	)
	firstUser := domain.User{CorpID: "corp-one", UserID: "same-user"}
	secondUser := domain.User{CorpID: "corp-two", UserID: "same-user"}

	if _, err := service.Search(
		context.Background(),
		firstUser,
		SearchQuery{CategoryID: service.categoryID(firstUser, "PROC-DIRECT"), Limit: 10},
		"request-corp-one",
	); err != nil {
		t.Fatalf("first corporation Search() error = %v", err)
	}
	if _, err := service.Search(
		context.Background(),
		secondUser,
		SearchQuery{CategoryID: service.categoryID(secondUser, "PROC-DIRECT"), Limit: 10},
		"request-corp-two",
	); err != nil {
		t.Fatalf("second corporation Search() error = %v", err)
	}
	if _, err := service.Search(
		context.Background(),
		firstUser,
		SearchQuery{CategoryID: service.categoryID(firstUser, "PROC-DIRECT"), Limit: 10},
		"request-corp-one-limited",
	); !errors.Is(err, domain.ErrRateLimited) {
		t.Errorf("repeated Search() error = %v; want rate limited", err)
	}
}

func TestCategoriesDoNotExposeProcessCodesOrMatchingSignals(t *testing.T) {
	service := newTestService(t, &fakeProvider{}, &recordingAudit{})
	result, err := service.VisibleCategories(
		context.Background(),
		domain.User{CorpID: "corp", UserID: "user"},
		CategoryDiscoveryQuery{},
		"request-categories",
	)
	if err != nil {
		t.Fatalf("VisibleCategories() error = %v", err)
	}
	if len(result.Categories) != 1 {
		t.Fatalf("categories = %#v", result.Categories)
	}
	if strings.Contains(result.Categories[0].ID, "PROC-") ||
		strings.Contains(result.Categories[0].Description, "PROC-") {
		t.Errorf("category leaked process code: %#v", result.Categories[0])
	}
}

func TestVisibleCategoriesFiltersCatalogByKeyword(t *testing.T) {
	provider := &fakeProvider{}
	service := newCategoryDiscoveryService(t, provider)
	user := domain.User{CorpID: "corp", UserID: "user"}

	result, err := service.VisibleCategories(
		context.Background(),
		user,
		CategoryDiscoveryQuery{Keyword: "firmware"},
		"request-keyword",
	)
	if err != nil {
		t.Fatalf("VisibleCategories() error = %v", err)
	}
	if len(result.Categories) != 1 ||
		result.Categories[0].ID != service.categoryID(user, "PROC-FIRMWARE") ||
		!result.Complete {
		t.Errorf("discovery result = %#v", result)
	}
	if len(provider.snapshotQueries()) != 0 {
		t.Errorf("category filtering must not scan approval instances")
	}
}

func TestSearchKeywordMatchesOnlyAuthorizedApprovalContent(t *testing.T) {
	provider := &fakeProvider{
		pages: map[string]domain.ApprovalInstanceIDPage{
			"PROC-DIRECT": {
				ProcessInstanceIDs: []string{"authorized-match", "authorized-miss", "outsider-match"},
				NextToken:          int64Pointer(20),
			},
		},
		approvals: map[string]domain.Approval{
			"authorized-match": approvalFixture(
				"authorized-match",
				"Tablet T120 firmware release",
				"user",
				true,
			),
			"authorized-miss": approvalFixture(
				"authorized-miss",
				"Tablet T100 firmware release",
				"user",
				true,
			),
			"outsider-match": approvalFixture(
				"outsider-match",
				"Tablet T120 secret release",
				"outsider",
				true,
			),
		},
	}
	audit := &recordingAudit{}
	service := newTestService(t, provider, audit)
	user := domain.User{CorpID: "corp", UserID: "user"}
	categoryID := service.categoryID(user, "PROC-DIRECT")

	result, err := service.Search(
		context.Background(),
		user,
		SearchQuery{
			CategoryID: categoryID,
			Keyword:    "T120",
			Limit:      10,
		},
		"request-keyword",
	)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(result.Items) != 1 ||
		result.Items[0].ProcessInstanceID != "authorized-match" ||
		result.NextCursor == "" {
		t.Errorf("search result = %#v", result)
	}
	if audit.decisions()["outsider-match"] != domain.AuditDecisionDenied {
		t.Errorf("audit decisions = %#v", audit.decisions())
	}

	if _, err := service.Search(
		context.Background(),
		domain.User{CorpID: "corp", UserID: "other-user"},
		SearchQuery{
			CategoryID: categoryID,
			Cursor:     result.NextCursor,
			Limit:      10,
		},
		"request-cross-user",
	); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("cross-user search cursor error = %v; want not found", err)
	}
}

func TestSearchAndCategoryDiscoveryValidateKeywordAndTimeBounds(t *testing.T) {
	service := newCategoryDiscoveryService(t, &fakeProvider{})
	user := domain.User{CorpID: "corp", UserID: "user"}
	categoryID := service.categoryID(user, "PROC-FIRMWARE")
	invalidKeyword := strings.Repeat("界", 101)
	if _, err := service.VisibleCategories(
		context.Background(),
		user,
		CategoryDiscoveryQuery{Keyword: invalidKeyword},
		"request-category-keyword",
	); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("category keyword error = %v; want invalid input", err)
	}
	if _, err := service.Search(
		context.Background(),
		user,
		SearchQuery{
			CategoryID: categoryID,
			Keyword:    invalidKeyword,
			Limit:      10,
		},
		"request-search-keyword",
	); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("search keyword error = %v; want invalid input", err)
	}
}

func newTestService(
	t *testing.T,
	provider Provider,
	audit AuditRepository,
) *Service {
	t.Helper()
	return newTestServiceWithRate(t, provider, audit, 10)
}

func newTestServiceWithRate(
	t *testing.T,
	provider Provider,
	audit AuditRepository,
	requestsPerMinute int,
) *Service {
	t.Helper()
	if fake, ok := provider.(*fakeProvider); ok && fake.templatePages == nil {
		fake.templatePages = map[int64]domain.VisibleApprovalTemplatePage{
			0: {
				Templates: []domain.VisibleApprovalTemplate{
					{ProcessCode: "PROC-DIRECT", Name: "Firmware flow"},
				},
			},
		}
	}
	service, err := NewService(Options{
		Provider:          provider,
		Audit:             audit,
		CursorSigningKey:  []byte(strings.Repeat("k", 32)),
		DetailConcurrency: 2,
		RequestsPerMinute: requestsPerMinute,
		Now:               func() time.Time { return searchNow },
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func newCategoryDiscoveryService(t *testing.T, provider Provider) *Service {
	t.Helper()
	if fake, ok := provider.(*fakeProvider); ok && fake.templatePages == nil {
		fake.templatePages = map[int64]domain.VisibleApprovalTemplatePage{
			0: {
				Templates: []domain.VisibleApprovalTemplate{
					{ProcessCode: "PROC-FIRMWARE", Name: "Firmware flow"},
					{ProcessCode: "PROC-DEPARTURE", Name: "Personnel departure"},
				},
			},
		}
	}
	service, err := NewService(Options{
		Provider:          provider,
		Audit:             &recordingAudit{},
		CursorSigningKey:  []byte(strings.Repeat("k", 32)),
		DetailConcurrency: 2,
		RequestsPerMinute: 10,
		Now:               func() time.Time { return searchNow },
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func approvalFixture(
	processInstanceID string,
	title string,
	participant string,
	hasAttachment bool,
	formValues ...domain.FormValue,
) domain.Approval {
	approval := domain.Approval{
		ProcessInstanceID: processInstanceID,
		BusinessID:        "business-" + processInstanceID,
		Title:             title,
		CreateTime:        "2026-07-18T08:00Z",
		ApproverUserIDs:   []string{participant},
		FormValues:        formValues,
	}
	if hasAttachment {
		approval.Attachments = []domain.Attachment{
			{FileID: "file-" + processInstanceID, FileName: "attachment.bin"},
		}
	}
	return approval
}

type fakeProvider struct {
	mu              sync.Mutex
	templatePages   map[int64]domain.VisibleApprovalTemplatePage
	templateError   error
	templateQueries []domain.VisibleApprovalTemplateQuery
	pages           map[string]domain.ApprovalInstanceIDPage
	pageSequences   map[string]map[int64]domain.ApprovalInstanceIDPage
	approvals       map[string]domain.Approval
	errors          map[string]error
	queries         []domain.ApprovalInstanceIDQuery
}

func (fake *fakeProvider) ListVisibleApprovalTemplates(
	_ context.Context,
	query domain.VisibleApprovalTemplateQuery,
) (domain.VisibleApprovalTemplatePage, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.templateQueries = append(fake.templateQueries, query)
	if fake.templateError != nil {
		return domain.VisibleApprovalTemplatePage{}, fake.templateError
	}
	return fake.templatePages[query.NextToken], nil
}

func (fake *fakeProvider) ListApprovalInstanceIDs(
	_ context.Context,
	query domain.ApprovalInstanceIDQuery,
) (domain.ApprovalInstanceIDPage, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.queries = append(fake.queries, query)
	if pages := fake.pageSequences[query.ProcessCode]; pages != nil {
		return pages[query.NextToken], nil
	}
	return fake.pages[query.ProcessCode], nil
}

func (fake *fakeProvider) Approval(
	_ context.Context,
	processInstanceID string,
) (domain.Approval, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if err := fake.errors[processInstanceID]; err != nil {
		return domain.Approval{}, err
	}
	return fake.approvals[processInstanceID], nil
}

func (fake *fakeProvider) totalRequested() int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	total := 0
	for _, query := range fake.queries {
		total += query.MaxResults
	}
	return total
}

func (fake *fakeProvider) snapshotQueries() []domain.ApprovalInstanceIDQuery {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]domain.ApprovalInstanceIDQuery(nil), fake.queries...)
}

type recordingAudit struct {
	mu           sync.Mutex
	events       []domain.AuditEvent
	err          error
	contextErr   error
	contextValue any
	deadline     time.Time
}

func (audit *recordingAudit) RecordAudit(
	ctx context.Context,
	event domain.AuditEvent,
) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	audit.contextErr = ctx.Err()
	audit.contextValue = ctx.Value(auditContextKey{})
	audit.deadline, _ = ctx.Deadline()
	if audit.contextErr != nil {
		return audit.contextErr
	}
	if audit.err != nil {
		return audit.err
	}
	audit.events = append(audit.events, event)
	return nil
}

func (audit *recordingAudit) decisions() map[string]domain.AuditDecision {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	result := make(map[string]domain.AuditDecision, len(audit.events))
	for _, event := range audit.events {
		result[event.ProcessInstanceID] = event.Decision
	}
	return result
}

func int64Pointer(value int64) *int64 {
	return &value
}
