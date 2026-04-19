package memory

import (
	"testing"
	"time"
)

func TestRevoker_RevokeAndCheck(t *testing.T) {
	r := NewTokenRevoker()
	if err := r.Revoke("jti-1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	revoked, err := r.IsRevoked("jti-1")
	if err != nil {
		t.Fatalf("isrevoked: %v", err)
	}
	if !revoked {
		t.Fatal("expected jti-1 to be revoked")
	}
	if r.Len() != 1 {
		t.Fatalf("len = %d", r.Len())
	}
}

func TestRevoker_RevokeUntilExpires(t *testing.T) {
	r := NewTokenRevoker()
	if err := r.RevokeUntil("jti-2", time.Now().Add(-1*time.Second)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	revoked, err := r.IsRevoked("jti-2")
	if err != nil {
		t.Fatalf("isrevoked: %v", err)
	}
	if revoked {
		t.Fatal("expected expired entry to be considered not revoked (lazy cleanup)")
	}
	if r.Len() != 0 {
		t.Fatalf("expected lazy cleanup to drop entry, len=%d", r.Len())
	}
}

func TestRevoker_CleanupRemovesExpired(t *testing.T) {
	r := NewTokenRevoker()
	_ = r.RevokeUntil("a", time.Now().Add(-1*time.Hour))
	_ = r.RevokeUntil("b", time.Now().Add(1*time.Hour))
	if err := r.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if r.Len() != 1 {
		t.Fatalf("expected only the live entry to remain, len=%d", r.Len())
	}
	revoked, _ := r.IsRevoked("a")
	if revoked {
		t.Fatal("expected 'a' to be cleaned up")
	}
	revoked, _ = r.IsRevoked("b")
	if !revoked {
		t.Fatal("expected 'b' to remain revoked")
	}
}

func TestRevoker_RevokeUntilKeepsLaterExpiry(t *testing.T) {
	r := NewTokenRevoker()
	later := time.Now().Add(2 * time.Hour)
	earlier := time.Now().Add(1 * time.Hour)
	_ = r.RevokeUntil("c", later)
	_ = r.RevokeUntil("c", earlier)
	r.mu.RLock()
	exp := r.revoked["c"]
	r.mu.RUnlock()
	if !exp.Equal(later) {
		t.Fatalf("expected later expiry to be kept, got %v", exp)
	}
}

// TestRevoker_NoLeakUnderChurn is the regression for the unbounded
// revoker map: under a 10k-entry churn the map should shrink back to
// roughly the live set after a Cleanup() call.
func TestRevoker_NoLeakUnderChurn(t *testing.T) {
	r := NewTokenRevoker()
	for i := 0; i < 10_000; i++ {
		_ = r.RevokeUntil(string(rune(i)), time.Now().Add(-time.Second))
	}
	if r.Len() == 0 {
		t.Fatal("expected entries before cleanup")
	}
	if err := r.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if r.Len() != 0 {
		t.Fatalf("expected map to drain after cleanup, got %d", r.Len())
	}
}
