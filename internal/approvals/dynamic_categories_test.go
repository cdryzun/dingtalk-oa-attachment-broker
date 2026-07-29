package approvals

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

func TestVisibleCatalogOwnerCancellationDoesNotFailOtherCallers(t *testing.T) {
	provider := &blockingCatalogProvider{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	service := newTestService(t, provider, &recordingAudit{})
	user := domain.User{CorpID: "corp", UserID: "user"}
	ownerContext, cancelOwner := context.WithCancel(context.Background())
	ownerResult := make(chan error, 1)
	go func() {
		_, err := service.VisibleCategories(ownerContext, user, CategoryDiscoveryQuery{}, "owner")
		ownerResult <- err
	}()
	<-provider.started
	cancelOwner()
	if err := <-ownerResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("owner VisibleCategories() error = %v; want canceled", err)
	}

	liveResult := make(chan error, 1)
	go func() {
		_, err := service.VisibleCategories(
			context.Background(),
			user,
			CategoryDiscoveryQuery{},
			"live",
		)
		liveResult <- err
	}()
	close(provider.release)
	if err := <-liveResult; err != nil {
		t.Fatalf("live VisibleCategories() error = %v", err)
	}
	if provider.calls.Load() != 1 {
		t.Errorf("catalog loads = %d; want 1", provider.calls.Load())
	}
}

func TestVisibleCategoriesComeFromCurrentUsersTemplateCatalog(t *testing.T) {
	provider := &fakeProvider{
		templatePages: map[int64]domain.VisibleApprovalTemplatePage{
			0: {
				Templates: []domain.VisibleApprovalTemplate{
					{
						ProcessCode:   "PROC-EXPENSE",
						Name:          "Expense reimbursement",
						DirectoryName: "Finance",
					},
					{
						ProcessCode:   "PROC-DEPARTURE",
						Name:          "Employee departure",
						DirectoryName: "Human resources",
					},
				},
				NextToken: int64Pointer(2),
			},
			2: {
				Templates: []domain.VisibleApprovalTemplate{
					{
						ProcessCode:   "PROC-CONTRACT",
						Name:          "Contract approval",
						DirectoryName: "Legal",
					},
				},
			},
		},
	}
	service := newDynamicTestService(t, provider, 10)
	user := domain.User{CorpID: "corp", UserID: "user-one"}

	result, err := service.VisibleCategories(
		context.Background(),
		user,
		CategoryDiscoveryQuery{},
		"request-categories",
	)
	if err != nil {
		t.Fatalf("VisibleCategories() error = %v", err)
	}
	if len(result.Categories) != 3 || !result.Complete || result.NextCursor != "" {
		t.Fatalf("visible categories = %#v", result)
	}
	for _, category := range result.Categories {
		if !strings.HasPrefix(category.ID, "category-") ||
			strings.Contains(category.ID, "PROC-") ||
			category.DisplayName == "" {
			t.Errorf("unsafe category = %#v", category)
		}
	}
	if result.Categories[0].DisplayName != "Expense reimbursement" ||
		result.Categories[0].DirectoryName != "Finance" {
		t.Errorf("sorted category metadata = %#v", result.Categories)
	}

	secondUserResult, err := service.VisibleCategories(
		context.Background(),
		domain.User{CorpID: "corp", UserID: "user-two"},
		CategoryDiscoveryQuery{},
		"request-second-user",
	)
	if err != nil {
		t.Fatalf("second user VisibleCategories() error = %v", err)
	}
	if secondUserResult.Categories[0].ID == result.Categories[0].ID {
		t.Error("category IDs must be bound to the authenticated user")
	}
}

func TestSearchResolvesOnlyCurrentUsersOpaqueCategory(t *testing.T) {
	provider := &fakeProvider{
		templatePages: map[int64]domain.VisibleApprovalTemplatePage{
			0: {
				Templates: []domain.VisibleApprovalTemplate{
					{ProcessCode: "PROC-FIRMWARE", Name: "Firmware release"},
				},
			},
		},
		pages: map[string]domain.ApprovalInstanceIDPage{
			"PROC-FIRMWARE": {ProcessInstanceIDs: []string{"instance-one"}},
		},
		approvals: map[string]domain.Approval{
			"instance-one": approvalFixture(
				"instance-one",
				"Firmware release",
				"user-one",
				true,
			),
		},
	}
	service := newDynamicTestService(t, provider, 10)
	user := domain.User{CorpID: "corp", UserID: "user-one"}
	categories, err := service.VisibleCategories(
		context.Background(),
		user,
		CategoryDiscoveryQuery{},
		"request-categories",
	)
	if err != nil || len(categories.Categories) != 1 {
		t.Fatalf("VisibleCategories() = %#v, %v", categories, err)
	}

	result, err := service.Search(
		context.Background(),
		user,
		SearchQuery{CategoryID: categories.Categories[0].ID, Limit: 10},
		"request-search",
	)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(result.Items) != 1 || result.Items[0].ProcessInstanceID != "instance-one" {
		t.Errorf("search result = %#v", result)
	}
	queries := provider.snapshotQueries()
	if len(queries) != 1 || queries[0].ProcessCode != "PROC-FIRMWARE" {
		t.Errorf("approval instance queries = %#v", queries)
	}

	otherUserCategories, err := service.VisibleCategories(
		context.Background(),
		domain.User{CorpID: "corp", UserID: "user-two"},
		CategoryDiscoveryQuery{},
		"request-other-categories",
	)
	if err != nil {
		t.Fatalf("other user VisibleCategories() error = %v", err)
	}
	if _, err := service.Search(
		context.Background(),
		user,
		SearchQuery{CategoryID: otherUserCategories.Categories[0].ID, Limit: 10},
		"request-cross-user-category",
	); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("cross-user category error = %v; want not found", err)
	}
}

func TestVisibleCategoryCursorIsOpaqueAndUserBound(t *testing.T) {
	templates := make([]domain.VisibleApprovalTemplate, 0, 101)
	for index := 0; index < 101; index++ {
		templates = append(templates, domain.VisibleApprovalTemplate{
			ProcessCode: fmt.Sprintf("PROC-%03d", index),
			Name:        fmt.Sprintf("Approval %03d", index),
		})
	}
	provider := &fakeProvider{
		templatePages: map[int64]domain.VisibleApprovalTemplatePage{
			0: {
				Templates: templates[:100],
				NextToken: int64Pointer(100),
			},
			100: {Templates: templates[100:]},
		},
	}
	service := newDynamicTestService(t, provider, 10)
	user := domain.User{CorpID: "corp", UserID: "user-one"}

	first, err := service.VisibleCategories(
		context.Background(),
		user,
		CategoryDiscoveryQuery{},
		"request-first-page",
	)
	if err != nil {
		t.Fatalf("first VisibleCategories() error = %v", err)
	}
	if len(first.Categories) != 100 || first.Complete || first.NextCursor == "" {
		t.Fatalf("first category page = %#v", first)
	}
	payloadPart := strings.Split(first.NextCursor, ".")[0]
	payload, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		t.Fatalf("decode category cursor payload: %v", err)
	}
	if strings.Contains(string(payload), "PROC-") ||
		strings.Contains(string(payload), "user-one") ||
		strings.Contains(string(payload), `"corp"`) {
		t.Errorf("category cursor exposed sensitive catalog data: %s", payload)
	}

	if _, err := service.VisibleCategories(
		context.Background(),
		domain.User{CorpID: "corp", UserID: "user-two"},
		CategoryDiscoveryQuery{Cursor: first.NextCursor},
		"request-cross-user-cursor",
	); !errors.Is(err, domain.ErrInvalidInput) {
		t.Errorf("cross-user category cursor error = %v; want invalid input", err)
	}

	second, err := service.VisibleCategories(
		context.Background(),
		user,
		CategoryDiscoveryQuery{Cursor: first.NextCursor},
		"request-second-page",
	)
	if err != nil {
		t.Fatalf("second VisibleCategories() error = %v", err)
	}
	if len(second.Categories) != 1 || !second.Complete || second.NextCursor != "" {
		t.Errorf("second category page = %#v", second)
	}
}

func TestVisibleCatalogIsCachedPerEnterpriseUser(t *testing.T) {
	provider := &fakeProvider{
		templatePages: map[int64]domain.VisibleApprovalTemplatePage{
			0: {
				Templates: []domain.VisibleApprovalTemplate{
					{ProcessCode: "PROC-ONE", Name: "Approval one"},
				},
			},
		},
	}
	service := newDynamicTestService(t, provider, 10)
	firstUser := domain.User{CorpID: "corp", UserID: "user-one"}

	for request := 0; request < 2; request++ {
		if _, err := service.VisibleCategories(
			context.Background(),
			firstUser,
			CategoryDiscoveryQuery{},
			fmt.Sprintf("request-cache-%d", request),
		); err != nil {
			t.Fatalf("VisibleCategories() error = %v", err)
		}
	}
	if _, err := service.VisibleCategories(
		context.Background(),
		domain.User{CorpID: "corp", UserID: "user-two"},
		CategoryDiscoveryQuery{},
		"request-second-user",
	); err != nil {
		t.Fatalf("second user VisibleCategories() error = %v", err)
	}

	provider.mu.Lock()
	queries := append(
		[]domain.VisibleApprovalTemplateQuery(nil),
		provider.templateQueries...,
	)
	provider.mu.Unlock()
	if len(queries) != 2 || queries[0].UserID != "user-one" ||
		queries[1].UserID != "user-two" {
		t.Errorf("visible template queries = %#v", queries)
	}
}

func TestVisibleCategoryPaginationDoesNotConsumeSearchRateLimit(t *testing.T) {
	provider := &fakeProvider{
		templatePages: map[int64]domain.VisibleApprovalTemplatePage{
			0: {
				Templates: []domain.VisibleApprovalTemplate{
					{ProcessCode: "PROC-ONE", Name: "Approval one"},
				},
			},
		},
		pages: map[string]domain.ApprovalInstanceIDPage{
			"PROC-ONE": {ProcessInstanceIDs: []string{"instance-one"}},
		},
		approvals: map[string]domain.Approval{
			"instance-one": approvalFixture(
				"instance-one",
				"Approval one",
				"user-one",
				true,
			),
		},
	}
	service := newDynamicTestService(t, provider, 1)
	user := domain.User{CorpID: "corp", UserID: "user-one"}

	var categoryID string
	for request := 0; request < 3; request++ {
		result, err := service.VisibleCategories(
			context.Background(),
			user,
			CategoryDiscoveryQuery{},
			fmt.Sprintf("request-category-%d", request),
		)
		if err != nil {
			t.Fatalf("VisibleCategories() request %d error = %v", request, err)
		}
		categoryID = result.Categories[0].ID
	}

	if _, err := service.Search(
		context.Background(),
		user,
		SearchQuery{CategoryID: categoryID, Limit: 10},
		"request-first-search",
	); err != nil {
		t.Fatalf("first Search() error = %v", err)
	}
	if _, err := service.Search(
		context.Background(),
		user,
		SearchQuery{CategoryID: categoryID, Limit: 10},
		"request-second-search",
	); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("second Search() error = %v; want rate limited", err)
	}
}

func TestVisibleCatalogFailsClosedOnInvalidMetadata(t *testing.T) {
	provider := &fakeProvider{
		templatePages: map[int64]domain.VisibleApprovalTemplatePage{
			0: {
				Templates: []domain.VisibleApprovalTemplate{
					{
						ProcessCode:   "PROC-ONE",
						Name:          "Approval one",
						DirectoryName: strings.Repeat("x", 513),
					},
				},
			},
		},
	}
	service := newDynamicTestService(t, provider, 10)

	if _, err := service.VisibleCategories(
		context.Background(),
		domain.User{CorpID: "corp", UserID: "user"},
		CategoryDiscoveryQuery{},
		"request-invalid-metadata",
	); !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("VisibleCategories() error = %v; want upstream", err)
	}
}

func newDynamicTestService(
	t *testing.T,
	provider Provider,
	requestsPerMinute int,
) *Service {
	t.Helper()
	service, err := NewService(Options{
		Provider:          provider,
		Audit:             &recordingAudit{},
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

type blockingCatalogProvider struct {
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
}

func (provider *blockingCatalogProvider) ListVisibleApprovalTemplates(
	ctx context.Context,
	_ domain.VisibleApprovalTemplateQuery,
) (domain.VisibleApprovalTemplatePage, error) {
	if provider.calls.Add(1) == 1 {
		close(provider.started)
	}
	select {
	case <-ctx.Done():
		return domain.VisibleApprovalTemplatePage{}, ctx.Err()
	case <-provider.release:
		return domain.VisibleApprovalTemplatePage{
			Templates: []domain.VisibleApprovalTemplate{{
				ProcessCode: "PROC-DIRECT",
				Name:        "Approval",
			}},
		}, nil
	}
}

func (*blockingCatalogProvider) ListApprovalInstanceIDs(
	context.Context,
	domain.ApprovalInstanceIDQuery,
) (domain.ApprovalInstanceIDPage, error) {
	return domain.ApprovalInstanceIDPage{}, nil
}

func (*blockingCatalogProvider) Approval(context.Context, string) (domain.Approval, error) {
	return domain.Approval{}, nil
}
