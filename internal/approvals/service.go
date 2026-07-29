package approvals

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

const (
	DefaultSearchPageSize    = 20
	MinSearchPageSize        = 10
	categoryPageSize         = 100
	visibleTemplatePageSize  = 100
	maxVisibleTemplatePages  = 100
	maxVisibleTemplates      = 5000
	visibleCatalogCacheTTL   = time.Minute
	maxVisibleCatalogEntries = 1024
	maxKeywordRunes          = 100
	maxSearchRange           = 120 * 24 * time.Hour
	maxSearchHistory         = 365 * 24 * time.Hour
	searchClockSkew          = time.Minute
	auditWriteTimeout        = 5 * time.Second
)

type Provider interface {
	ListVisibleApprovalTemplates(
		context.Context,
		domain.VisibleApprovalTemplateQuery,
	) (domain.VisibleApprovalTemplatePage, error)
	ListApprovalInstanceIDs(
		context.Context,
		domain.ApprovalInstanceIDQuery,
	) (domain.ApprovalInstanceIDPage, error)
	Approval(context.Context, string) (domain.Approval, error)
}

type AuditRepository interface {
	RecordAudit(context.Context, domain.AuditEvent) error
}

type Options struct {
	Provider             Provider
	Audit                AuditRepository
	AdministratorUserIDs map[string]struct{}
	CursorSigningKey     []byte
	DetailConcurrency    int
	RequestsPerMinute    int
	Now                  func() time.Time
}

type Service struct {
	provider          Provider
	audit             AuditRepository
	administrators    map[string]struct{}
	cursor            *cursorCodec
	categoryKey       []byte
	catalogMu         sync.RWMutex
	catalogCache      map[string]visibleCatalogCacheEntry
	catalogLoads      singleflight.Group
	detailConcurrency int
	rateLimiter       *searchRateLimiter
	now               func() time.Time
}

type Category struct {
	ID            string `json:"id"`
	DisplayName   string `json:"displayName"`
	DirectoryName string `json:"directoryName,omitempty"`
	Description   string `json:"description,omitempty"`
}

type SearchQuery struct {
	CategoryID    string
	Keyword       string
	CreatedAfter  *time.Time
	CreatedBefore *time.Time
	Cursor        string
	Limit         int
}

type CategoryDiscoveryQuery struct {
	Keyword string
	Cursor  string
}

type CategoryDiscoveryResult struct {
	Categories        []Category `json:"categories"`
	NextCursor        string     `json:"nextCursor,omitempty"`
	Complete          bool       `json:"complete"`
	ScannedPages      int        `json:"scannedPages"`
	ScannedCandidates int        `json:"scannedCandidates"`
	TotalCategories   int        `json:"totalCategories"`
}

type Item struct {
	ProcessInstanceID string              `json:"processInstanceId"`
	BusinessID        string              `json:"businessId,omitempty"`
	Title             string              `json:"title"`
	Status            string              `json:"status,omitempty"`
	Result            string              `json:"result,omitempty"`
	CreateTime        string              `json:"createTime,omitempty"`
	FinishTime        string              `json:"finishTime,omitempty"`
	Attachments       []domain.Attachment `json:"attachments"`
}

type SearchResult struct {
	CategoryID string `json:"categoryId"`
	Items      []Item `json:"items"`
	NextCursor string `json:"nextCursor,omitempty"`
}

type candidate struct {
	processInstanceID string
	source            domain.ApprovalCategorySource
}

func NewService(options Options) (*Service, error) {
	if options.Provider == nil {
		return nil, fmt.Errorf("%w: approval provider is required", domain.ErrInvalidInput)
	}
	if options.Audit == nil {
		return nil, fmt.Errorf("%w: audit repository is required", domain.ErrInvalidInput)
	}
	cursor, err := newCursorCodec(options.CursorSigningKey, options.Now)
	if err != nil {
		return nil, err
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	detailConcurrency := options.DetailConcurrency
	if detailConcurrency < 1 || detailConcurrency > domain.MaxApprovalSearchPageSize {
		return nil, fmt.Errorf(
			"%w: approval detail concurrency must be between 1 and %d",
			domain.ErrInvalidInput,
			domain.MaxApprovalSearchPageSize,
		)
	}
	if options.RequestsPerMinute < 1 {
		return nil, fmt.Errorf(
			"%w: approval search request rate must be positive",
			domain.ErrInvalidInput,
		)
	}
	return &Service{
		provider:          options.Provider,
		audit:             options.Audit,
		administrators:    cloneSet(options.AdministratorUserIDs),
		cursor:            cursor,
		categoryKey:       append([]byte(nil), options.CursorSigningKey...),
		catalogCache:      make(map[string]visibleCatalogCacheEntry),
		detailConcurrency: detailConcurrency,
		rateLimiter:       newSearchRateLimiter(options.RequestsPerMinute, now),
		now:               now,
	}, nil
}

func (service *Service) Search(
	ctx context.Context,
	user domain.User,
	query SearchQuery,
	requestID string,
) (SearchResult, error) {
	if err := validateAuthenticatedUser(user); err != nil {
		return SearchResult{}, err
	}
	if strings.TrimSpace(requestID) == "" {
		return SearchResult{}, fmt.Errorf("%w: request ID is required", domain.ErrInvalidInput)
	}
	limit := query.Limit
	if limit == 0 {
		limit = DefaultSearchPageSize
	}
	if limit < MinSearchPageSize || limit > domain.MaxApprovalSearchPageSize {
		return SearchResult{}, fmt.Errorf(
			"%w: approval search limit must be between %d and %d",
			domain.ErrInvalidInput,
			MinSearchPageSize,
			domain.MaxApprovalSearchPageSize,
		)
	}
	rateLimitKey := user.CorpID + "\x00" + user.UserID
	if !service.rateLimiter.Allow(rateLimitKey) {
		return SearchResult{}, domain.ErrRateLimited
	}
	categories, err := service.visibleCatalog(ctx, user)
	if err != nil {
		return SearchResult{}, err
	}
	category, exists := resolveVisibleCategory(
		categories,
		strings.TrimSpace(query.CategoryID),
	)
	if !exists {
		return SearchResult{}, domain.ErrNotFound
	}
	state, err := service.searchState(category, user, query)
	if err != nil {
		return SearchResult{}, err
	}
	candidates, err := service.listCandidates(ctx, category, &state, limit)
	if err != nil {
		return SearchResult{}, err
	}
	items, err := service.authorizeCandidates(
		ctx,
		user,
		candidates,
		state.Keyword,
		requestID,
		"approvals.search",
	)
	if err != nil {
		return SearchResult{}, err
	}
	sort.SliceStable(items, func(left, right int) bool {
		leftTime, leftErr := time.Parse(time.RFC3339, items[left].CreateTime)
		rightTime, rightErr := time.Parse(time.RFC3339, items[right].CreateTime)
		if leftErr == nil && rightErr == nil && !leftTime.Equal(rightTime) {
			return leftTime.After(rightTime)
		}
		if (leftErr == nil) != (rightErr == nil) {
			return leftErr == nil
		}
		if items[left].CreateTime != items[right].CreateTime {
			return items[left].CreateTime > items[right].CreateTime
		}
		return items[left].ProcessInstanceID > items[right].ProcessInstanceID
	})

	nextCursor := ""
	if hasRemainingSources(state.Sources) {
		nextCursor, err = service.cursor.Encode(state)
		if err != nil {
			return SearchResult{}, err
		}
	}
	return SearchResult{
		CategoryID: category.ID,
		Items:      items,
		NextCursor: nextCursor,
	}, nil
}

func (service *Service) VisibleCategories(
	ctx context.Context,
	user domain.User,
	query CategoryDiscoveryQuery,
	requestID string,
) (CategoryDiscoveryResult, error) {
	if err := validateAuthenticatedUser(user); err != nil {
		return CategoryDiscoveryResult{}, err
	}
	if strings.TrimSpace(requestID) == "" {
		return CategoryDiscoveryResult{}, fmt.Errorf(
			"%w: request ID is required",
			domain.ErrInvalidInput,
		)
	}
	catalog, err := service.visibleCatalog(ctx, user)
	if err != nil {
		return CategoryDiscoveryResult{}, err
	}
	keyword := ""
	offset := 0
	if strings.TrimSpace(query.Cursor) != "" {
		if strings.TrimSpace(query.Keyword) != "" {
			return CategoryDiscoveryResult{}, fmt.Errorf(
				"%w: keyword must not be combined with a cursor",
				domain.ErrInvalidInput,
			)
		}
		state, decodeError := service.cursor.DecodeCategory(strings.TrimSpace(query.Cursor))
		if decodeError != nil {
			return CategoryDiscoveryResult{}, decodeError
		}
		if state.SubjectHash != approvalSubjectHash(user) {
			return CategoryDiscoveryResult{}, fmt.Errorf(
				"%w: approval category cursor does not match the user",
				domain.ErrInvalidInput,
			)
		}
		keyword = state.Keyword
		categories := visibleCategoriesMatchingKeyword(catalog, keyword)
		if state.CatalogRevision != categoryCatalogRevision(categories) ||
			state.Offset > len(categories) {
			return CategoryDiscoveryResult{}, fmt.Errorf(
				"%w: approval category cursor does not match the current catalog",
				domain.ErrInvalidInput,
			)
		}
		offset = state.Offset
	} else {
		keyword, err = normalizeKeyword(query.Keyword)
		if err != nil {
			return CategoryDiscoveryResult{}, err
		}
	}
	categories := visibleCategoriesMatchingKeyword(catalog, keyword)
	end := offset + categoryPageSize
	if end > len(categories) {
		end = len(categories)
	}
	publicCategories := make([]Category, 0, end-offset)
	for _, category := range categories[offset:end] {
		publicCategories = append(publicCategories, publicCategory(category))
	}
	result := CategoryDiscoveryResult{
		Categories:        publicCategories,
		Complete:          end == len(categories),
		ScannedPages:      1,
		ScannedCandidates: end - offset,
		TotalCategories:   len(categories),
	}
	if !result.Complete {
		result.NextCursor, err = service.cursor.EncodeCategory(categoryCursorState{
			SubjectHash:     approvalSubjectHash(user),
			Keyword:         keyword,
			CatalogRevision: categoryCatalogRevision(categories),
			Offset:          end,
		})
		if err != nil {
			return CategoryDiscoveryResult{}, err
		}
	}
	return result, nil
}

func (service *Service) searchState(
	category domain.ApprovalCategory,
	user domain.User,
	query SearchQuery,
) (cursorState, error) {
	now := service.now().UTC()
	if strings.TrimSpace(query.Cursor) != "" {
		if query.CreatedAfter != nil ||
			query.CreatedBefore != nil ||
			strings.TrimSpace(query.Keyword) != "" {
			return cursorState{}, fmt.Errorf(
				"%w: keyword and time bounds must not be combined with a cursor",
				domain.ErrInvalidInput,
			)
		}
		state, err := service.cursor.Decode(strings.TrimSpace(query.Cursor))
		if err != nil {
			return cursorState{}, err
		}
		if state.CategoryID != category.ID ||
			!cursorMatchesCategory(state, category) {
			return cursorState{}, fmt.Errorf(
				"%w: approval search cursor does not match the user or category",
				domain.ErrInvalidInput,
			)
		}
		if state.SubjectHash != approvalSubjectHash(user) {
			return cursorState{}, fmt.Errorf(
				"%w: approval search cursor does not match the user or category",
				domain.ErrInvalidInput,
			)
		}
		if err := validateTimeRange(
			time.UnixMilli(state.StartMS),
			time.UnixMilli(state.EndMS),
			now,
		); err != nil {
			return cursorState{}, err
		}
		return state, nil
	}

	keyword, err := normalizeKeyword(query.Keyword)
	if err != nil {
		return cursorState{}, err
	}
	end := now
	if query.CreatedBefore != nil {
		end = query.CreatedBefore.UTC()
	}
	start := end.Add(-maxSearchRange)
	if query.CreatedAfter != nil {
		start = query.CreatedAfter.UTC()
	}
	if err := validateTimeRange(start, end, now); err != nil {
		return cursorState{}, err
	}
	sources := make([]cursorSource, 0, len(category.Sources))
	for range category.Sources {
		sources = append(sources, cursorSource{})
	}
	return cursorState{
		SubjectHash:      approvalSubjectHash(user),
		CategoryID:       category.ID,
		CategoryRevision: categoryRevision(category),
		Keyword:          keyword,
		StartMS:          start.UnixMilli(),
		EndMS:            end.UnixMilli(),
		Sources:          sources,
	}, nil
}

func (service *Service) listCandidates(
	ctx context.Context,
	category domain.ApprovalCategory,
	state *cursorState,
	limit int,
) ([]candidate, error) {
	active := 0
	for _, source := range state.Sources {
		if !source.Done {
			active++
		}
	}
	if active == 0 {
		return []candidate{}, nil
	}
	remainingLimit := limit
	remainingSources := active
	candidates := make([]candidate, 0, limit)
	seen := make(map[string]struct{}, limit)
	for sourceIndex := range state.Sources {
		sourceState := &state.Sources[sourceIndex]
		if sourceState.Done {
			continue
		}
		quota := remainingLimit / remainingSources
		remainingLimit -= quota
		remainingSources--
		page, err := service.provider.ListApprovalInstanceIDs(
			ctx,
			domain.ApprovalInstanceIDQuery{
				ProcessCode: category.Sources[sourceIndex].ProcessCode,
				StartTime:   time.UnixMilli(state.StartMS),
				EndTime:     time.UnixMilli(state.EndMS),
				NextToken:   sourceState.NextToken,
				MaxResults:  quota,
			},
		)
		if err != nil {
			return nil, err
		}
		if len(page.ProcessInstanceIDs) > quota {
			return nil, fmt.Errorf(
				"%w: DingTalk returned more approval instances than requested",
				domain.ErrUpstream,
			)
		}
		if page.NextToken == nil {
			sourceState.Done = true
		} else {
			sourceState.NextToken = *page.NextToken
		}
		for _, processInstanceID := range page.ProcessInstanceIDs {
			normalizedProcessInstanceID, normalizeError := domain.NormalizeProcessInstanceID(
				processInstanceID,
			)
			if normalizeError != nil {
				return nil, fmt.Errorf(
					"%w: DingTalk returned an invalid process instance ID",
					domain.ErrUpstream,
				)
			}
			processInstanceID = normalizedProcessInstanceID
			if _, exists := seen[processInstanceID]; exists {
				continue
			}
			seen[processInstanceID] = struct{}{}
			candidates = append(candidates, candidate{
				processInstanceID: processInstanceID,
				source:            category.Sources[sourceIndex],
			})
		}
	}
	return candidates, nil
}

func (service *Service) authorizeCandidates(
	ctx context.Context,
	user domain.User,
	candidates []candidate,
	keyword string,
	requestID string,
	auditAction string,
) ([]Item, error) {
	results := make([]*Item, len(candidates))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(service.detailConcurrency)
	for index := range candidates {
		index := index
		group.Go(func() error {
			current := candidates[index]
			approval, err := service.provider.Approval(
				groupContext,
				current.processInstanceID,
			)
			if err != nil {
				return service.recordDenied(
					groupContext,
					user,
					current.processInstanceID,
					requestID,
					auditAction,
					err,
				)
			}
			if !approval.CanAccess(user.UserID, service.administrators) {
				if err := service.recordAudit(
					groupContext,
					user,
					current.processInstanceID,
					requestID,
					auditAction,
					domain.AuditDecisionDenied,
					domain.ErrorClass(domain.ErrForbidden),
				); err != nil {
					return err
				}
				return nil
			}
			if len(approval.Attachments) == 0 {
				return nil
			}
			if keyword != "" && !approvalMatchesKeyword(approval, keyword) {
				return nil
			}
			if err := service.recordAudit(
				groupContext,
				user,
				current.processInstanceID,
				requestID,
				auditAction,
				domain.AuditDecisionAllowed,
				"",
			); err != nil {
				return err
			}
			results[index] = &Item{
				ProcessInstanceID: approval.ProcessInstanceID,
				BusinessID:        approval.BusinessID,
				Title:             approval.Title,
				Status:            approval.Status,
				Result:            approval.Result,
				CreateTime:        approval.CreateTime,
				FinishTime:        approval.FinishTime,
				Attachments:       append([]domain.Attachment(nil), approval.Attachments...),
			}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	items := make([]Item, 0, len(results))
	for _, result := range results {
		if result != nil {
			items = append(items, *result)
		}
	}
	return items, nil
}

func (service *Service) recordDenied(
	ctx context.Context,
	user domain.User,
	processInstanceID string,
	requestID string,
	auditAction string,
	cause error,
) error {
	if err := service.recordAudit(
		ctx,
		user,
		processInstanceID,
		requestID,
		auditAction,
		domain.AuditDecisionDenied,
		domain.ErrorClass(cause),
	); err != nil {
		return err
	}
	return cause
}

func (service *Service) recordAudit(
	ctx context.Context,
	user domain.User,
	processInstanceID string,
	requestID string,
	action string,
	decision domain.AuditDecision,
	errorClass string,
) error {
	auditContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()
	if err := service.audit.RecordAudit(auditContext, domain.AuditEvent{
		RequestID:          requestID,
		CorpID:             user.CorpID,
		ActorUserID:        user.UserID,
		Action:             action,
		ProcessInstanceID:  processInstanceID,
		Decision:           decision,
		UpstreamErrorClass: errorClass,
		CreatedAt:          service.now().UTC(),
	}); err != nil {
		return fmt.Errorf("%w: record approval search audit event: %v", domain.ErrUnavailable, err)
	}
	return nil
}

func approvalContains(approval domain.Approval, signal string) bool {
	needle := strings.ToLower(signal)
	if strings.Contains(strings.ToLower(approval.Title), needle) {
		return true
	}
	for _, formValue := range approval.FormValues {
		for _, value := range []string{formValue.Name, formValue.Value, formValue.ExtValue} {
			if strings.Contains(strings.ToLower(value), needle) {
				return true
			}
		}
	}
	return false
}

func approvalMatchesKeyword(approval domain.Approval, keyword string) bool {
	needle := strings.ToLower(keyword)
	if strings.Contains(strings.ToLower(approval.BusinessID), needle) {
		return true
	}
	return approvalContains(approval, needle)
}

func validateAuthenticatedUser(user domain.User) error {
	if strings.TrimSpace(user.CorpID) == "" || strings.TrimSpace(user.UserID) == "" {
		return fmt.Errorf("%w: authenticated user is incomplete", domain.ErrUnauthorized)
	}
	return nil
}

func normalizeKeyword(value string) (string, error) {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return "", nil
	}
	if !utf8.ValidString(normalized) || utf8.RuneCountInString(normalized) > maxKeywordRunes {
		return "", fmt.Errorf(
			"%w: keyword must contain at most %d Unicode characters",
			domain.ErrInvalidInput,
			maxKeywordRunes,
		)
	}
	return normalized, nil
}

func approvalSubjectHash(user domain.User) string {
	digest := sha256.Sum256([]byte(user.CorpID + "\x00" + user.UserID))
	return hex.EncodeToString(digest[:])
}

func categoryCatalogRevision(categories []domain.ApprovalCategory) string {
	encoded, err := json.Marshal(categories)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func publicCategory(category domain.ApprovalCategory) Category {
	return Category{
		ID:            category.ID,
		DisplayName:   category.DisplayName,
		DirectoryName: category.DirectoryName,
		Description:   category.Description,
	}
}

func validateTimeRange(start, end, now time.Time) error {
	if start.IsZero() || end.IsZero() || !end.After(start) {
		return fmt.Errorf("%w: approval search time range is invalid", domain.ErrInvalidInput)
	}
	if end.Sub(start) > maxSearchRange {
		return fmt.Errorf(
			"%w: approval search time range must not exceed 120 days",
			domain.ErrInvalidInput,
		)
	}
	if start.Before(now.Add(-maxSearchHistory)) {
		return fmt.Errorf(
			"%w: approval search cannot start more than 365 days ago",
			domain.ErrInvalidInput,
		)
	}
	if end.After(now.Add(searchClockSkew)) {
		return fmt.Errorf(
			"%w: approval search end time must not be in the future",
			domain.ErrInvalidInput,
		)
	}
	return nil
}

func cursorMatchesCategory(state cursorState, category domain.ApprovalCategory) bool {
	if state.CategoryRevision != categoryRevision(category) ||
		len(state.Sources) != len(category.Sources) {
		return false
	}
	for _, stateSource := range state.Sources {
		if stateSource.NextToken < 0 {
			return false
		}
	}
	return true
}

func categoryRevision(category domain.ApprovalCategory) string {
	encoded, err := json.Marshal(category)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func hasRemainingSources(sources []cursorSource) bool {
	for _, source := range sources {
		if !source.Done {
			return true
		}
	}
	return false
}

func cloneCategories(source []domain.ApprovalCategory) []domain.ApprovalCategory {
	result := make([]domain.ApprovalCategory, 0, len(source))
	for _, category := range source {
		cloned := category
		cloned.Sources = append([]domain.ApprovalCategorySource(nil), category.Sources...)
		result = append(result, cloned)
	}
	return result
}

func cloneSet(source map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{}, len(source))
	for value := range source {
		result[value] = struct{}{}
	}
	return result
}
