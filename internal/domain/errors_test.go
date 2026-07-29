package domain

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorClassPreservesPublicErrorCategories(t *testing.T) {
	testCases := map[error]string{
		ErrInvalidInput:         "invalid_input",
		ErrUnauthorized:         "unauthorized",
		ErrForbidden:            "forbidden",
		ErrNotFound:             "not_found",
		ErrConflict:             "conflict",
		ErrExpired:              "expired",
		ErrAlreadyUsed:          "already_used",
		ErrAuthorizationPending: "authorization_pending",
		ErrRateLimited:          "rate_limited",
		ErrTooLarge:             "too_large",
		ErrUnavailable:          "unavailable",
		errors.New("unknown"):   "upstream",
	}
	for input, expected := range testCases {
		if actual := ErrorClass(fmt.Errorf("wrapped: %w", input)); actual != expected {
			t.Errorf("ErrorClass(%v) = %q; want %q", input, actual, expected)
		}
	}
}
