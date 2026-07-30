package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeProcessInstanceIDRejectsTemplateCodes(t *testing.T) {
	testCases := []struct {
		name      string
		value     string
		want      string
		wantError bool
	}{
		{name: "valid", value: " Jm3NHxEeT0-E2XoX2i9wRw04411784253697 ", want: "Jm3NHxEeT0-E2XoX2i9wRw04411784253697"},
		{name: "empty", value: " ", wantError: true},
		{name: "template code", value: "PROC-DF836022-D293-44C2-976F-F80EC6340BC8", wantError: true},
		{name: "case insensitive template code", value: "proc-0421CFCB-58BA-4937-AF5E-3472773274C2", wantError: true},
		{name: "control character", value: "instance\nidentifier", wantError: true},
		{name: "path separator", value: "instance/identifier", wantError: true},
		{name: "too long", value: strings.Repeat("a", 513), wantError: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := NormalizeProcessInstanceID(testCase.value)
			if testCase.wantError {
				if !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("NormalizeProcessInstanceID() error = %v; want invalid input", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeProcessInstanceID() error = %v", err)
			}
			if got != testCase.want {
				t.Errorf("NormalizeProcessInstanceID() = %q; want %q", got, testCase.want)
			}
		})
	}
}
