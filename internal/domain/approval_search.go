package domain

import (
	"time"
)

const MaxApprovalSearchPageSize = 20

type ApprovalCategory struct {
	ID            string                   `json:"id"`
	DisplayName   string                   `json:"displayName"`
	DirectoryName string                   `json:"directoryName,omitempty"`
	Description   string                   `json:"description,omitempty"`
	Sources       []ApprovalCategorySource `json:"sources"`
}

type ApprovalCategorySource struct {
	ProcessCode string `json:"processCode"`
}

type VisibleApprovalTemplate struct {
	ProcessCode   string
	Name          string
	DirectoryName string
}

type VisibleApprovalTemplateQuery struct {
	UserID     string
	NextToken  int64
	MaxResults int
}

type VisibleApprovalTemplatePage struct {
	Templates []VisibleApprovalTemplate
	NextToken *int64
}

type ApprovalInstanceIDQuery struct {
	ProcessCode string
	StartTime   time.Time
	EndTime     time.Time
	NextToken   int64
	MaxResults  int
}

type ApprovalInstanceIDPage struct {
	ProcessInstanceIDs []string
	NextToken          *int64
}
