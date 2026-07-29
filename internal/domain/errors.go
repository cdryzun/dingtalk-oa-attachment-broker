package domain

import "errors"

var (
	ErrInvalidInput         = errors.New("invalid input")
	ErrUnauthorized         = errors.New("unauthorized")
	ErrForbidden            = errors.New("forbidden")
	ErrNotFound             = errors.New("not found")
	ErrConflict             = errors.New("conflict")
	ErrExpired              = errors.New("expired")
	ErrAlreadyUsed          = errors.New("already used")
	ErrAuthorizationPending = errors.New("authorization pending")
	ErrRateLimited          = errors.New("rate limited")
	ErrTooLarge             = errors.New("resource too large")
	ErrUpstream             = errors.New("upstream failure")
	ErrUnavailable          = errors.New("service unavailable")
)

func ErrorClass(err error) string {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return "invalid_input"
	case errors.Is(err, ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, ErrForbidden):
		return "forbidden"
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrConflict):
		return "conflict"
	case errors.Is(err, ErrExpired):
		return "expired"
	case errors.Is(err, ErrAlreadyUsed):
		return "already_used"
	case errors.Is(err, ErrAuthorizationPending):
		return "authorization_pending"
	case errors.Is(err, ErrRateLimited):
		return "rate_limited"
	case errors.Is(err, ErrTooLarge):
		return "too_large"
	case errors.Is(err, ErrUnavailable):
		return "unavailable"
	default:
		return "upstream"
	}
}
