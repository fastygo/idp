package memory

import (
	"testing"
	"time"

	"idp-cyberos/pkg/core"
)

func TestSessionStore_CleanupExpired(t *testing.T) {
	s := NewSessionStore()
	_ = s.Register(&core.SessionRecord{
		SID:       "alive",
		Sub:       "u1",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	_ = s.Register(&core.SessionRecord{
		SID:       "dead",
		Sub:       "u2",
		IssuedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	if s.Len() != 2 {
		t.Fatalf("len = %d", s.Len())
	}
	if err := s.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if s.Len() != 1 {
		t.Fatalf("expected only live session, len=%d", s.Len())
	}
	rec, _ := s.Lookup("dead")
	if rec != nil {
		t.Fatal("expected dead session to be removed")
	}
}

func TestCodeStore_Len(t *testing.T) {
	s := NewCodeStore()
	_ = s.Save(&core.AuthCode{Code: "a", ExpiresAt: time.Now().Add(time.Minute)})
	_ = s.Save(&core.AuthCode{Code: "b", ExpiresAt: time.Now().Add(-time.Minute)})
	if s.Len() != 2 {
		t.Fatalf("len = %d", s.Len())
	}
	if err := s.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if s.Len() != 1 {
		t.Fatalf("expected one entry after cleanup, got %d", s.Len())
	}
}
