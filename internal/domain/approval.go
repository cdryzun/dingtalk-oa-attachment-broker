package domain

import (
	"encoding/json"
	"strconv"
	"strings"
)

type AttachmentSource string

const (
	AttachmentSourceForm    AttachmentSource = "form"
	AttachmentSourceComment AttachmentSource = "comment"
)

type User struct {
	CorpID      string
	UserID      string
	UnionID     string
	DisplayName string
}

type Attachment struct {
	FileID   string           `json:"fileId"`
	FileName string           `json:"fileName"`
	FileSize int64            `json:"fileSize,omitempty"`
	FileType string           `json:"fileType,omitempty"`
	SpaceID  string           `json:"-"`
	Source   AttachmentSource `json:"source"`
}

type FormValue struct {
	Name     string
	Value    string
	ExtValue string
}

type OperationRecord struct {
	UserID      string
	CCUserIDs   []string
	Attachments []Attachment
}

type Approval struct {
	ProcessInstanceID string
	ProcessCode       string
	BusinessID        string
	Title             string
	Status            string
	Result            string
	CreateTime        string
	FinishTime        string
	OriginatorUserID  string
	ApproverUserIDs   []string
	CCUserIDs         []string
	TaskUserIDs       []string
	FormValues        []FormValue
	OperationRecords  []OperationRecord
	Attachments       []Attachment
}

func (approval Approval) CanAccess(userID string, administrators map[string]struct{}) bool {
	if userID == "" {
		return false
	}
	if _, ok := administrators[userID]; ok {
		return true
	}
	if approval.OriginatorUserID == userID {
		return true
	}
	return contains(approval.ApproverUserIDs, userID) ||
		contains(approval.CCUserIDs, userID) ||
		contains(approval.TaskUserIDs, userID)
}

func (approval Approval) FindAttachment(fileID string) (Attachment, bool) {
	if fileID == "" {
		return Attachment{}, false
	}
	for _, attachment := range approval.Attachments {
		if attachment.FileID == fileID {
			return attachment, true
		}
	}
	return Attachment{}, false
}

func ParseAttachments(formValues []FormValue, operationRecords []OperationRecord) []Attachment {
	attachments := make([]Attachment, 0)
	seen := make(map[string]struct{})

	appendAttachment := func(attachment Attachment, source AttachmentSource) {
		attachment.FileID = strings.TrimSpace(attachment.FileID)
		if attachment.FileID == "" {
			return
		}
		if _, exists := seen[attachment.FileID]; exists {
			return
		}
		attachment.FileName = strings.TrimSpace(attachment.FileName)
		attachment.FileType = strings.TrimSpace(attachment.FileType)
		attachment.SpaceID = strings.TrimSpace(attachment.SpaceID)
		attachment.Source = source
		seen[attachment.FileID] = struct{}{}
		attachments = append(attachments, attachment)
	}

	for _, formValue := range formValues {
		for _, raw := range []string{formValue.Value, formValue.ExtValue} {
			for _, attachment := range parseJSONAttachments(raw) {
				appendAttachment(attachment, AttachmentSourceForm)
			}
		}
	}
	for _, operationRecord := range operationRecords {
		for _, attachment := range operationRecord.Attachments {
			appendAttachment(attachment, AttachmentSourceComment)
		}
	}
	return attachments
}

func parseJSONAttachments(raw string) []Attachment {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var value any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return nil
	}
	result := make([]Attachment, 0)
	walkAttachmentJSON(value, &result)
	return result
}

func walkAttachmentJSON(value any, result *[]Attachment) {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			walkAttachmentJSON(item, result)
		}
	case map[string]any:
		if attachment, ok := attachmentFromMap(typed); ok {
			*result = append(*result, attachment)
		}
		for _, nested := range typed {
			walkAttachmentJSON(nested, result)
		}
	}
}

func attachmentFromMap(value map[string]any) (Attachment, bool) {
	fileID, ok := stringValue(value["fileId"])
	if !ok || strings.TrimSpace(fileID) == "" {
		return Attachment{}, false
	}
	fileName, ok := firstString(value, "fileName", "name")
	if !ok || strings.TrimSpace(fileName) == "" {
		return Attachment{}, false
	}
	fileType, _ := firstString(value, "fileType", "extension")
	spaceID, _ := stringValue(value["spaceId"])
	fileSize := firstInt64(value, "fileSize", "size")
	return Attachment{
		FileID:   fileID,
		FileName: fileName,
		FileSize: fileSize,
		FileType: fileType,
		SpaceID:  spaceID,
	}, true
}

func firstString(value map[string]any, keys ...string) (string, bool) {
	for _, key := range keys {
		if result, ok := stringValue(value[key]); ok {
			return result, true
		}
	}
	return "", false
}

func stringValue(value any) (string, bool) {
	result, ok := value.(string)
	return result, ok
}

func firstInt64(value map[string]any, keys ...string) int64 {
	for _, key := range keys {
		switch typed := value[key].(type) {
		case string:
			parsed, err := strconv.ParseInt(typed, 10, 64)
			if err == nil && parsed >= 0 {
				return parsed
			}
		case float64:
			if typed >= 0 && typed == float64(int64(typed)) {
				return int64(typed)
			}
		}
	}
	return 0
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
