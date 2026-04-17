package auth

import (
	"net/http/httptest"
	"testing"
)

func TestSessionRoundtrip(t *testing.T) {
	key := "test-session-key-1234567890abcde"

	rr := httptest.NewRecorder()
	CreateSession(rr, "user@test.local", "user@test.local", "sid-123", key)

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookies set")
	}

	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	sess := GetSession(req, key)
	if sess == nil {
		t.Fatal("session not found")
	}
	if sess.Email != "user@test.local" {
		t.Fatalf("email = %q", sess.Email)
	}
	if sess.Sub != "user@test.local" {
		t.Fatalf("sub = %q", sess.Sub)
	}
	if sess.SID != "sid-123" {
		t.Fatalf("sid = %q", sess.SID)
	}

	sess2 := GetSession(req, "wrong-key")
	if sess2 != nil {
		t.Fatal("session should be nil with wrong key")
	}
}
