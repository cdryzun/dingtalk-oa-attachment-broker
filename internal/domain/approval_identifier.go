package domain

import (
	"fmt"
	"strings"
	"unicode"
)

const maxProcessInstanceIDBytes = 512

func NormalizeProcessInstanceID(value string) (string, error) {
	normalized := strings.TrimSpace(value)
	if normalized == "" || len(normalized) > maxProcessInstanceIDBytes ||
		strings.HasPrefix(strings.ToUpper(normalized), "PROC-") {
		return "", fmt.Errorf("%w: process instance ID is invalid", ErrInvalidInput)
	}
	for _, character := range normalized {
		if unicode.IsSpace(character) || unicode.IsControl(character) ||
			character == '/' || character == '\\' {
			return "", fmt.Errorf("%w: process instance ID is invalid", ErrInvalidInput)
		}
	}
	return normalized, nil
}
