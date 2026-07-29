package domain

import (
	"fmt"
	"strings"
	"time"
)

type AuditDecision string

const (
	AuditDecisionAllowed AuditDecision = "allowed"
	AuditDecisionDenied  AuditDecision = "denied"
)

type AuditEvent struct {
	RequestID          string
	CorpID             string
	ActorUserID        string
	Action             string
	ProcessInstanceID  string
	FileID             string
	Decision           AuditDecision
	UpstreamErrorClass string
	CreatedAt          time.Time
}

func (event AuditEvent) Validate() error {
	requiredValues := map[string]string{
		"request ID":          event.RequestID,
		"corporation ID":      event.CorpID,
		"actor user ID":       event.ActorUserID,
		"action":              event.Action,
		"process instance ID": event.ProcessInstanceID,
	}
	for field, value := range requiredValues {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: audit %s is required", ErrInvalidInput, field)
		}
	}
	if event.Decision != AuditDecisionAllowed && event.Decision != AuditDecisionDenied {
		return fmt.Errorf("%w: unsupported audit decision", ErrInvalidInput)
	}
	if event.CreatedAt.IsZero() {
		return fmt.Errorf("%w: audit creation time is required", ErrInvalidInput)
	}
	return nil
}
