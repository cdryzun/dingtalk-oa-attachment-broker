package domain

import (
	"reflect"
	"testing"
)

func TestApprovalAllowsOnlyParticipantsAndConfiguredAdministrators(t *testing.T) {
	approval := Approval{
		OriginatorUserID: "originator",
		ApproverUserIDs:  []string{"approver"},
		CCUserIDs:        []string{"cc"},
		TaskUserIDs:      []string{"task-user"},
	}
	admins := map[string]struct{}{"auditor": {}}

	tests := []struct {
		name   string
		userID string
		want   bool
	}{
		{name: "originator", userID: "originator", want: true},
		{name: "approver", userID: "approver", want: true},
		{name: "copy recipient", userID: "cc", want: true},
		{name: "task handler", userID: "task-user", want: true},
		{name: "configured auditor", userID: "auditor", want: true},
		{name: "unrelated enterprise user", userID: "other", want: false},
		{name: "empty identity", userID: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := approval.CanAccess(tt.userID, admins); got != tt.want {
				t.Errorf("CanAccess(%q) = %t; want %t", tt.userID, got, tt.want)
			}
		})
	}
}

func TestApprovalFindAttachmentRequiresExactMembership(t *testing.T) {
	approval := Approval{
		Attachments: []Attachment{
			{FileID: "form-file", FileName: "form.pdf", Source: AttachmentSourceForm},
			{FileID: "comment-file", FileName: "comment.txt", Source: AttachmentSourceComment},
		},
	}

	got, ok := approval.FindAttachment("comment-file")
	if !ok {
		t.Fatal("FindAttachment() returned ok=false; want true")
	}
	if got.Source != AttachmentSourceComment {
		t.Errorf("attachment source = %q; want %q", got.Source, AttachmentSourceComment)
	}

	if _, ok := approval.FindAttachment("other-file"); ok {
		t.Error("FindAttachment() returned ok=true for a file outside the approval")
	}
}

func TestParseAttachmentsReadsFormAndCommentAttachments(t *testing.T) {
	formValues := []FormValue{
		{
			Name: "Requirement attachments",
			Value: `[
				{"fileId":"form-1","fileName":"requirement.eml","fileSize":"100096","fileType":"eml","spaceId":"10"},
				{"fileId":"form-2","name":"nested.zip","size":2048,"extension":"zip"}
			]`,
		},
		{
			Name:     "Nested value",
			ExtValue: `{"files":[{"fileId":"form-3","fileName":"nested.pdf","fileSize":4096}]}`,
		},
		{
			Name:  "Ordinary text",
			Value: "No attachment here",
		},
	}
	operationRecords := []OperationRecord{
		{
			UserID: "commenter",
			Attachments: []Attachment{
				{
					FileID:   "comment-1",
					FileName: "review.txt",
					FileSize: 512,
					FileType: "txt",
					SpaceID:  "20",
				},
				{
					FileID:   "form-1",
					FileName: "duplicate.eml",
					Source:   AttachmentSourceComment,
				},
			},
		},
	}

	got := ParseAttachments(formValues, operationRecords)
	want := []Attachment{
		{
			FileID:   "form-1",
			FileName: "requirement.eml",
			FileSize: 100096,
			FileType: "eml",
			SpaceID:  "10",
			Source:   AttachmentSourceForm,
		},
		{
			FileID:   "form-2",
			FileName: "nested.zip",
			FileSize: 2048,
			FileType: "zip",
			Source:   AttachmentSourceForm,
		},
		{
			FileID:   "form-3",
			FileName: "nested.pdf",
			FileSize: 4096,
			Source:   AttachmentSourceForm,
		},
		{
			FileID:   "comment-1",
			FileName: "review.txt",
			FileSize: 512,
			FileType: "txt",
			SpaceID:  "20",
			Source:   AttachmentSourceComment,
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseAttachments() = %#v; want %#v", got, want)
	}
}

func TestParseAttachmentsRejectsMalformedAndIncompleteValues(t *testing.T) {
	formValues := []FormValue{
		{Value: `{not-json}`},
		{Value: `{"fileName":"missing-id.pdf"}`},
		{Value: `{"fileId":42,"fileName":"wrong-type.pdf"}`},
		{Value: `{"fileId":"valid","fileName":"valid.pdf","fileSize":"invalid"}`},
		{Value: `{"fileId":"business-record","status":"active"}`},
	}

	got := ParseAttachments(formValues, nil)
	want := []Attachment{{
		FileID:   "valid",
		FileName: "valid.pdf",
		Source:   AttachmentSourceForm,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseAttachments() = %#v; want %#v", got, want)
	}
}
