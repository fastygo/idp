package auth

import (
	"net/http/httptest"
	"strings"
	"testing"
)

const testSessionKey = "test-session-key-please-rotate"

func TestSavePendingRequestClearsOIDCPending(t *testing.T) {
	rec := httptest.NewRecorder()
	SavePendingRequest(rec, "saml-request-id", "https://siteA.example.com/sp",
		"https://siteA.example.com/acs", "rs-1", testSessionKey)

	cookies := rec.Result().Cookies()
	var samlSet, oidcCleared bool
	for _, c := range cookies {
		if c.Name == IdpPendingCookie && c.Value != "" {
			samlSet = true
		}
		if c.Name == IdpOIDCPendingCookie && c.MaxAge < 0 {
			oidcCleared = true
		}
	}

	if !samlSet {
		t.Fatalf("expected SAML pending cookie to be set, got cookies: %+v", cookies)
	}
	if !oidcCleared {
		t.Fatalf("expected OIDC pending cookie to be cleared, got cookies: %+v", cookies)
	}
}

func TestSaveOIDCPendingRequestClearsSAMLPending(t *testing.T) {
	rec := httptest.NewRecorder()
	SaveOIDCPendingRequest(rec, &PendingOIDCRequest{
		ClientID:    "fastygo",
		RedirectURI: "https://fastygo.ru/auth/callback",
		State:       "state-2",
		Scope:       "openid",
	}, testSessionKey)

	cookies := rec.Result().Cookies()
	var oidcSet, samlCleared bool
	for _, c := range cookies {
		if c.Name == IdpOIDCPendingCookie && c.Value != "" {
			oidcSet = true
		}
		if c.Name == IdpPendingCookie && c.MaxAge < 0 {
			samlCleared = true
		}
	}

	if !oidcSet {
		t.Fatalf("expected OIDC pending cookie to be set, got cookies: %+v", cookies)
	}
	if !samlCleared {
		t.Fatalf("expected SAML pending cookie to be cleared, got cookies: %+v", cookies)
	}
}

func TestClearAllPendingRemovesBoth(t *testing.T) {
	rec := httptest.NewRecorder()
	ClearAllPending(rec)

	cookies := rec.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected exactly 2 cleared cookies, got %d (%+v)", len(cookies), cookies)
	}
	for _, c := range cookies {
		if c.MaxAge >= 0 || c.Value != "" {
			t.Fatalf("expected cookie %q to be cleared (MaxAge<0, empty value); got MaxAge=%d value=%q",
				c.Name, c.MaxAge, c.Value)
		}
		if c.Name != IdpPendingCookie && c.Name != IdpOIDCPendingCookie {
			t.Fatalf("unexpected cookie name: %s", c.Name)
		}
	}
}

func TestSessionRoundTripPopulatesSubFromEmail(t *testing.T) {
	rec := httptest.NewRecorder()
	CreateSession(rec, "alice@example.com", "", "sid-123", testSessionKey)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one session cookie, got %d", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != IdpSessionCookie {
		t.Fatalf("unexpected cookie name: %s", cookie.Name)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Cookie", cookie.Name+"="+cookie.Value)

	sess := GetSession(req, testSessionKey)
	if sess == nil {
		t.Fatal("expected session to decode")
	}
	if sess.Email != "alice@example.com" {
		t.Fatalf("unexpected email: %q", sess.Email)
	}
	if sess.Sub != "alice@example.com" {
		t.Fatalf("expected sub to fall back to email, got %q", sess.Sub)
	}
	if sess.SID != "sid-123" {
		t.Fatalf("unexpected sid: %q", sess.SID)
	}
}

func TestGenerateSessionIDIsUniqueAndHex(t *testing.T) {
	a := GenerateSessionID()
	b := GenerateSessionID()
	if a == b {
		t.Fatal("expected unique session IDs")
	}
	if len(a) != 32 {
		t.Fatalf("expected hex-encoded 16-byte ID (32 chars), got %d", len(a))
	}
	if strings.ContainsAny(a, "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ") {
		t.Fatalf("expected lowercase hex only, got %q", a)
	}
}
