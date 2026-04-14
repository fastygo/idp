package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestIdPServer(t *testing.T) *IdPServer {
	t.Helper()
	kp := generateTestKeyPair(t)
	cfg := &Config{
		EntityID:   "https://idp.test.local",
		BaseURL:    "https://idp.test.local",
		ListenAddr: ":5800",
		SessionKey: "test-session-key-1234567890abcde",
		OIDCClients: []OIDCClient{
			{
				ClientID:     "testclient",
				ClientSecret: "testsecret",
				RedirectURIs: []string{"https://app.test.local/callback"},
				Name:         "Test App",
			},
		},
	}
	cfg.spIndex = make(map[string]*ServiceProvider)
	cfg.oidcIndex = map[string]*OIDCClient{
		"testclient": &cfg.OIDCClients[0],
	}

	srv := &IdPServer{
		cfg:       cfg,
		kp:        kp,
		codeStore: NewCodeStore(),
	}
	return srv
}

func TestOIDCDiscovery(t *testing.T) {
	srv := newTestIdPServer(t)
	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	srv.handleOIDCDiscovery(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}

	var doc map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}

	if doc["issuer"] != "https://idp.test.local" {
		t.Fatalf("issuer = %v", doc["issuer"])
	}
	if doc["authorization_endpoint"] != "https://idp.test.local/authorize" {
		t.Fatalf("authorization_endpoint = %v", doc["authorization_endpoint"])
	}
	if doc["token_endpoint"] != "https://idp.test.local/token" {
		t.Fatalf("token_endpoint = %v", doc["token_endpoint"])
	}
	if doc["jwks_uri"] != "https://idp.test.local/jwks" {
		t.Fatalf("jwks_uri = %v", doc["jwks_uri"])
	}
}

func TestOIDCJWKS(t *testing.T) {
	srv := newTestIdPServer(t)
	req := httptest.NewRequest("GET", "/jwks", nil)
	rr := httptest.NewRecorder()
	srv.handleOIDCJWKS(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}

	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("parse JWKS: %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}

	key := jwks.Keys[0]
	if key["kty"] != "RSA" {
		t.Fatalf("kty = %q", key["kty"])
	}
	if key["alg"] != "RS256" {
		t.Fatalf("alg = %q", key["alg"])
	}
	if key["kid"] == "" {
		t.Fatal("kid is empty")
	}
	if key["n"] == "" {
		t.Fatal("n is empty")
	}
	if key["e"] == "" {
		t.Fatal("e is empty")
	}
}

func TestOIDCAuthorizeRedirect(t *testing.T) {
	srv := newTestIdPServer(t)

	// Create a session first so authorize issues code immediately
	sessionRR := httptest.NewRecorder()
	createSession(sessionRR, "user@test.local", srv.cfg.SessionKey)
	sessionCookies := sessionRR.Result().Cookies()

	reqURL := "/authorize?client_id=testclient&redirect_uri=https://app.test.local/callback&response_type=code&scope=openid+email&state=xyz&nonce=abc"
	req := httptest.NewRequest("GET", reqURL, nil)
	for _, c := range sessionCookies {
		req.AddCookie(c)
	}

	rr := httptest.NewRecorder()
	srv.handleOIDCAuthorize(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rr.Code, rr.Body.String())
	}

	loc := rr.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}

	if u.Host != "app.test.local" {
		t.Fatalf("redirect host = %q", u.Host)
	}
	if u.Query().Get("code") == "" {
		t.Fatal("no code in redirect")
	}
	if u.Query().Get("state") != "xyz" {
		t.Fatalf("state = %q", u.Query().Get("state"))
	}
}

func TestOIDCAuthorizeInvalidClient(t *testing.T) {
	srv := newTestIdPServer(t)
	req := httptest.NewRequest("GET", "/authorize?client_id=unknown&redirect_uri=https://evil.com/cb&response_type=code", nil)
	rr := httptest.NewRecorder()
	srv.handleOIDCAuthorize(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestOIDCTokenExchange(t *testing.T) {
	srv := newTestIdPServer(t)

	// Simulate a saved auth code
	code := generateCode()
	srv.codeStore.Save(&AuthCode{
		Code:        code,
		ClientID:    "testclient",
		RedirectURI: "https://app.test.local/callback",
		Email:       "user@test.local",
		Sub:         "user@test.local",
		Nonce:       "abc",
		ExpiresAt:   timeNowPlus5Min(),
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.test.local/callback"},
		"client_id":     {"testclient"},
		"client_secret": {"testsecret"},
	}

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.handleOIDCToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}

	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Fatal("missing access_token")
	}
	if resp["id_token"] == nil || resp["id_token"] == "" {
		t.Fatal("missing id_token")
	}
	if resp["token_type"] != "Bearer" {
		t.Fatalf("token_type = %v", resp["token_type"])
	}
}

func TestOIDCTokenReplay(t *testing.T) {
	srv := newTestIdPServer(t)

	code := generateCode()
	srv.codeStore.Save(&AuthCode{
		Code:        code,
		ClientID:    "testclient",
		RedirectURI: "https://app.test.local/callback",
		Email:       "user@test.local",
		Sub:         "user@test.local",
		ExpiresAt:   timeNowPlus5Min(),
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.test.local/callback"},
		"client_id":     {"testclient"},
		"client_secret": {"testsecret"},
	}

	// First exchange succeeds
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.handleOIDCToken(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first exchange: expected 200, got %d", rr.Code)
	}

	// Second exchange with same code must fail
	req2 := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()
	srv.handleOIDCToken(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("replay: expected 400, got %d", rr2.Code)
	}
}

func TestOIDCTokenWrongSecret(t *testing.T) {
	srv := newTestIdPServer(t)

	code := generateCode()
	srv.codeStore.Save(&AuthCode{
		Code:        code,
		ClientID:    "testclient",
		RedirectURI: "https://app.test.local/callback",
		Email:       "user@test.local",
		Sub:         "user@test.local",
		ExpiresAt:   timeNowPlus5Min(),
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.test.local/callback"},
		"client_id":     {"testclient"},
		"client_secret": {"wrongsecret"},
	}

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.handleOIDCToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func timeNowPlus5Min() time.Time {
	return time.Now().Add(5 * time.Minute)
}
