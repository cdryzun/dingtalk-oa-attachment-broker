package domain

import "testing"

func TestApprovalSearchPageSizeRemainsBounded(t *testing.T) {
	if MaxApprovalSearchPageSize != 20 {
		t.Fatalf("MaxApprovalSearchPageSize = %d; want 20", MaxApprovalSearchPageSize)
	}
}
