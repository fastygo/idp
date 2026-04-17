package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"idp-cyberos/internal/config"
	"idp-cyberos/pkg/core"
)

func TestIntrospectActiveToken(t *testing.T) {
	h, cfg, _, sessionStore := newTestOIDCHandlers(t)
	registerSessionForTest(t, sessionStore, "sid-1", "user@test.local")

	token := issueAccessTokenForTest(t, h, cfg, "testclient", "sid-1", time.Hour)
	form := url.Values{
		"token":         {token},
		"client_id":     {"testclient"},
		"client_secret": {"testsecret"},
	}

	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleIntrospect(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp["active"] != true {
		t.Fatalf("active = %#v", resp["active"])
	}
	if resp["username"] != "user@test.local" {
		t.Fatalf("username = %#v", resp["username"])
	}
}

func TestIntrospectExpiredToken(t *testing.T) {
	h, cfg, _, sessionStore := newTestOIDCHandlers(t)
	registerSessionForTest(t, sessionStore, "sid-1", "user@test.local")

	token := issueAccessTokenForTest(t, h, cfg, "testclient", "sid-1", -time.Minute)
	form := url.Values{
		"token":         {token},
		"client_id":     {"testclient"},
		"client_secret": {"testsecret"},
	}

	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleIntrospect(rr, req)

	assertInactiveIntrospection(t, rr)
}

func TestIntrospectRevokedToken(t *testing.T) {
	h, cfg, _, sessionStore := newTestOIDCHandlers(t)
	registerSessionForTest(t, sessionStore, "sid-1", "user@test.local")

	token := issueAccessTokenForTest(t, h, cfg, "testclient", "sid-1", time.Hour)
	var claims AccessTokenClaims
	if err := VerifySignedClaims(token, &h.kp.PrivateKey.PublicKey, &claims); err != nil {
		t.Fatalf("parse token claims: %v", err)
	}
	if err := h.revoker.Revoke(claims.Jti); err != nil {
		t.Fatalf("revoke jti: %v", err)
	}

	form := url.Values{
		"token":         {token},
		"client_id":     {"testclient"},
		"client_secret": {"testsecret"},
	}

	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleIntrospect(rr, req)

	assertInactiveIntrospection(t, rr)
}

func TestIntrospectWrongClientHidesUsername(t *testing.T) {
	h, cfg, _, sessionStore := newTestOIDCHandlers(t)
	cfg.OIDCClients = append(cfg.OIDCClients, config.OIDCClient{
		ClientID:     "otherclient",
		ClientSecret: "othersecret",
		RedirectURIs: []string{"https://other.test.local/callback"},
		Name:         "Other App",
	})
	cfg.BuildIndexes()
	registerSessionForTest(t, sessionStore, "sid-1", "user@test.local")

	token := issueAccessTokenForTest(t, h, cfg, "testclient", "sid-1", time.Hour)
	form := url.Values{
		"token":         {token},
		"client_id":     {"otherclient"},
		"client_secret": {"othersecret"},
	}

	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleIntrospect(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp["active"] != true {
		t.Fatalf("active = %#v", resp["active"])
	}
	if _, ok := resp["username"]; ok {
		t.Fatalf("username should be hidden, got %#v", resp["username"])
	}
	if _, ok := resp["exp"]; !ok {
		t.Fatalf("expected exp in response, got %#v", resp)
	}
	if resp["iss"] != cfg.BaseURL {
		t.Fatalf("iss = %#v", resp["iss"])
	}
}

func TestRevokeAlwaysReturns200(t *testing.T) {
	h, _, _, _ := newTestOIDCHandlers(t)

	form := url.Values{
		"token":         {"invalid-token"},
		"client_id":     {"testclient"},
		"client_secret": {"testsecret"},
	}

	req := httptest.NewRequest("POST", "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleRevoke(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestRevokeMakesUserinfoFail(t *testing.T) {
	h, cfg, _, sessionStore := newTestOIDCHandlers(t)
	registerSessionForTest(t, sessionStore, "sid-1", "user@test.local")

	token := issueAccessTokenForTest(t, h, cfg, "testclient", "sid-1", time.Hour)
	revokeForm := url.Values{
		"token":         {token},
		"client_id":     {"testclient"},
		"client_secret": {"testsecret"},
	}

	revokeReq := httptest.NewRequest("POST", "/revoke", strings.NewReader(revokeForm.Encode()))
	revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revokeRR := httptest.NewRecorder()
	h.HandleRevoke(revokeRR, revokeReq)
	if revokeRR.Code != http.StatusOK {
		t.Fatalf("expected revoke 200, got %d", revokeRR.Code)
	}

	userinfoReq := httptest.NewRequest("GET", "/userinfo", nil)
	userinfoReq.Header.Set("Authorization", "Bearer "+token)
	userinfoRR := httptest.NewRecorder()
	h.HandleUserinfo(userinfoRR, userinfoReq)
	if userinfoRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", userinfoRR.Code)
	}
}

func issueAccessTokenForTest(t *testing.T, h *Handlers, cfg *config.Config, clientID, sid string, ttl time.Duration) string {
	t.Helper()
	token, err := GenerateAccessToken(h.kp, cfg.BaseURL, clientID, "user@test.local", "user@test.local", "openid email", sid, ttl)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}
	return token
}

func registerSessionForTest(t *testing.T, store core.SessionStore, sid, sub string) {
	t.Helper()
	if err := store.Register(&core.SessionRecord{
		SID:       sid,
		Sub:       sub,
		Email:     sub,
		Clients:   []string{"testclient"},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("register session: %v", err)
	}
}

func assertInactiveIntrospection(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp["active"] != false {
		t.Fatalf("active = %#v", resp["active"])
	}
}
