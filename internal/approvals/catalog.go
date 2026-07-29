package approvals

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

type visibleCatalogCacheEntry struct {
	categories []domain.ApprovalCategory
	loadedAt   time.Time
	expiresAt  time.Time
}

func (service *Service) visibleCatalog(
	ctx context.Context,
	user domain.User,
) ([]domain.ApprovalCategory, error) {
	cacheKey := approvalSubjectHash(user)
	now := service.now().UTC()
	if categories, ok := service.cachedVisibleCatalog(cacheKey, now); ok {
		return categories, nil
	}

	resultChannel := service.catalogLoads.DoChan(cacheKey, func() (any, error) {
		loadContext, cancel := context.WithTimeout(
			context.Background(),
			visibleCatalogLoadTimeout,
		)
		defer cancel()
		refreshTime := service.now().UTC()
		if categories, ok := service.cachedVisibleCatalog(cacheKey, refreshTime); ok {
			return categories, nil
		}
		categories, err := service.fetchVisibleCatalog(loadContext, user)
		if err != nil {
			return nil, err
		}
		service.storeVisibleCatalog(cacheKey, categories, refreshTime)
		return categories, nil
	})
	var result singleflight.Result
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result = <-resultChannel:
	}
	if result.Err != nil {
		return nil, result.Err
	}
	categories, ok := result.Val.([]domain.ApprovalCategory)
	if !ok {
		return nil, fmt.Errorf("%w: visible approval catalog cache is invalid", domain.ErrUnavailable)
	}
	return cloneCategories(categories), nil
}

func (service *Service) cachedVisibleCatalog(
	cacheKey string,
	now time.Time,
) ([]domain.ApprovalCategory, bool) {
	service.catalogMu.RLock()
	entry, exists := service.catalogCache[cacheKey]
	service.catalogMu.RUnlock()
	if !exists || !now.Before(entry.expiresAt) {
		return nil, false
	}
	return cloneCategories(entry.categories), true
}

func (service *Service) storeVisibleCatalog(
	cacheKey string,
	categories []domain.ApprovalCategory,
	now time.Time,
) {
	service.catalogMu.Lock()
	defer service.catalogMu.Unlock()
	for key, entry := range service.catalogCache {
		if !now.Before(entry.expiresAt) {
			delete(service.catalogCache, key)
		}
	}
	if _, exists := service.catalogCache[cacheKey]; !exists &&
		len(service.catalogCache) >= maxVisibleCatalogEntries {
		oldestKey := ""
		var oldestTime time.Time
		for key, entry := range service.catalogCache {
			if oldestKey == "" || entry.loadedAt.Before(oldestTime) {
				oldestKey = key
				oldestTime = entry.loadedAt
			}
		}
		if oldestKey != "" {
			delete(service.catalogCache, oldestKey)
		}
	}
	service.catalogCache[cacheKey] = visibleCatalogCacheEntry{
		categories: cloneCategories(categories),
		loadedAt:   now,
		expiresAt:  now.Add(visibleCatalogCacheTTL),
	}
}

func (service *Service) fetchVisibleCatalog(
	ctx context.Context,
	user domain.User,
) ([]domain.ApprovalCategory, error) {
	nextToken := int64(0)
	seenProcessCodes := make(map[string]struct{})
	categories := make([]domain.ApprovalCategory, 0, visibleTemplatePageSize)
	for pageIndex := 0; pageIndex < maxVisibleTemplatePages; pageIndex++ {
		page, err := service.provider.ListVisibleApprovalTemplates(
			ctx,
			domain.VisibleApprovalTemplateQuery{
				UserID:     user.UserID,
				NextToken:  nextToken,
				MaxResults: visibleTemplatePageSize,
			},
		)
		if err != nil {
			return nil, err
		}
		if len(page.Templates) > visibleTemplatePageSize ||
			len(categories)+len(page.Templates) > maxVisibleTemplates {
			return nil, fmt.Errorf(
				"%w: DingTalk visible approval template catalog is too large",
				domain.ErrUpstream,
			)
		}
		for _, template := range page.Templates {
			processCode := strings.TrimSpace(template.ProcessCode)
			name := strings.TrimSpace(template.Name)
			directoryName := strings.TrimSpace(template.DirectoryName)
			if processCode == "" || len(processCode) > 256 ||
				name == "" || len(name) > 512 || len(directoryName) > 512 {
				return nil, fmt.Errorf(
					"%w: DingTalk visible approval template catalog is invalid",
					domain.ErrUpstream,
				)
			}
			if _, duplicate := seenProcessCodes[processCode]; duplicate {
				continue
			}
			seenProcessCodes[processCode] = struct{}{}
			categories = append(categories, domain.ApprovalCategory{
				ID:            service.categoryID(user, processCode),
				DisplayName:   name,
				DirectoryName: directoryName,
				Sources: []domain.ApprovalCategorySource{
					{ProcessCode: processCode},
				},
			})
		}
		if page.NextToken == nil {
			sortVisibleCategories(categories)
			return categories, nil
		}
		if *page.NextToken <= nextToken {
			return nil, fmt.Errorf(
				"%w: DingTalk visible approval template cursor did not advance",
				domain.ErrUpstream,
			)
		}
		nextToken = *page.NextToken
	}
	return nil, fmt.Errorf(
		"%w: DingTalk visible approval template pagination exceeded the safety limit",
		domain.ErrUpstream,
	)
}

func (service *Service) categoryID(user domain.User, processCode string) string {
	mac := hmac.New(sha256.New, service.categoryKey)
	_, _ = mac.Write([]byte(
		"approval-category-v1\x00" +
			user.CorpID + "\x00" +
			user.UserID + "\x00" +
			processCode,
	))
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mac.Sum(nil))
	return "category-" + strings.ToLower(encoded)
}

func resolveVisibleCategory(
	categories []domain.ApprovalCategory,
	categoryID string,
) (domain.ApprovalCategory, bool) {
	for _, category := range categories {
		if len(category.ID) == len(categoryID) &&
			hmac.Equal([]byte(category.ID), []byte(categoryID)) {
			return cloneCategories([]domain.ApprovalCategory{category})[0], true
		}
	}
	return domain.ApprovalCategory{}, false
}

func visibleCategoriesMatchingKeyword(
	categories []domain.ApprovalCategory,
	keyword string,
) []domain.ApprovalCategory {
	if keyword == "" {
		return cloneCategories(categories)
	}
	needle := strings.ToLower(keyword)
	result := make([]domain.ApprovalCategory, 0, len(categories))
	for _, category := range categories {
		if strings.Contains(strings.ToLower(category.ID), needle) ||
			strings.Contains(strings.ToLower(category.DisplayName), needle) ||
			strings.Contains(strings.ToLower(category.DirectoryName), needle) ||
			strings.Contains(strings.ToLower(category.Description), needle) {
			result = append(result, category)
		}
	}
	return cloneCategories(result)
}

func sortVisibleCategories(categories []domain.ApprovalCategory) {
	sort.Slice(categories, func(left, right int) bool {
		if categories[left].DirectoryName != categories[right].DirectoryName {
			return categories[left].DirectoryName < categories[right].DirectoryName
		}
		if categories[left].DisplayName != categories[right].DisplayName {
			return categories[left].DisplayName < categories[right].DisplayName
		}
		return categories[left].ID < categories[right].ID
	})
}
