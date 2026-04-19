package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"idp-cyberos/internal/auth"
	"idp-cyberos/pkg/core"
)

func TestAuthorize_RejectsMissingOpenIDScope(t *testing.T) {
	h, cfg, _, _ := newTestOIDCHandlers(t)

	loginRR := httptest.NewRecorder()
	auth.CreateSession(loginRR, "user@test.local", "user@test.local", "sid-x", cfg.SessionKey)

	req := httptest.NewRequest("GET", "/authorize?client_id=testclient&redirect_uri="+url.QueryEscape("https://app.test.local/callback")+"&response_type=code&scope=email", nil)
	for _, c := range loginRR.Result().Cookies() {
		req.AddCookie(c)
	}

	rr := httptest.NewRecorder()
	h.HandleAuthorize(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("showLogin should not be called: scope rejection happens before")
	})(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "openid") {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}

func TestVerifyAccessToken_RejectsBadIssuer(t *testing.T) {
	h, _, _, _ := newTestOIDCHandlers(t)

	// Mint a token with a foreign iss (simulating an IdP rename) and
	// confirm verifyAccessToken rejects it.
	tok, err := GenerateAccessToken(h.kp, "https://other.example.com", "testclient", "sub", "u@x", "openid", "sid-x", time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if _, err := h.verifyAccessToken(tok); err == nil {
		t.Fatal("expected issuer mismatch rejection")
	} else if !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyAccessToken_AcceptsMatchingIssuer(t *testing.T) {
	h, _, _, sessionStore := newTestOIDCHandlers(t)

	if err := sessionStore.Register(&core.SessionRecord{
		SID:       "sid-x",
		Sub:       "sub",
		Email:     "u@x",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	tok, err := GenerateAccessToken(h.kp, "https://idp.test.local", "testclient", "sub", "u@x", "openid", "sid-x", time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if _, err := h.verifyAccessToken(tok); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
}
