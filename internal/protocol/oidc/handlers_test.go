package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"idp-cyberos/internal/auth"
	"idp-cyberos/internal/config"
	"idp-cyberos/pkg/core"
	"idp-cyberos/pkg/store/memory"
)

func generateTestKeyPair(t *testing.T) *auth.IdPKeyPair {
	t.Helper()
	dir := t.TempDir()
	kp, err := auth.LoadOrGenerateKeyPair(dir+"/test.key", dir+"/test.crt")
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	return kp
}

func newTestOIDCHandlers(t *testing.T) (*Handlers, *config.Config, *memory.CodeStore, *memory.SessionStore) {
	t.Helper()
	kp := generateTestKeyPair(t)
	cfg := &config.Config{
		EntityID:   "https://idp.test.local",
		BaseURL:    "https://idp.test.local",
		ListenAddr: ":5800",
		SessionKey: "test-session-key-1234567890abcde",
		OIDCClients: []config.OIDCClient{
			{
				ClientID:     "testclient",
				ClientSecret: "testsecret",
				RedirectURIs: []string{"https://app.test.local/callback"},
				Name:         "Test App",
			},
		},
	}

	cfg.BuildIndexes()
	codeStore := memory.NewCodeStore()
	sessionStore := memory.NewSessionStore()
	revoker := memory.NewTokenRevoker()
	h := NewHandlers(cfg, kp, codeStore, sessionStore, revoker)
	return h, cfg, codeStore, sessionStore
}

func TestOIDCDiscovery(t *testing.T) {
	h, _, _, _ := newTestOIDCHandlers(t)
	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	h.HandleDiscovery(rr, req)

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
	methods, ok := doc["code_challenge_methods_supported"].([]any)
	if !ok || len(methods) != 2 {
		t.Fatalf("code_challenge_methods_supported = %#v", doc["code_challenge_methods_supported"])
	}
	gotMethods := []string{methods[0].(string), methods[1].(string)}
	if !slices.Equal(gotMethods, []string{"S256", "plain"}) {
		t.Fatalf("code_challenge_methods_supported = %#v", gotMethods)
	}
}

func TestOIDCJWKS(t *testing.T) {
	h, _, _, _ := newTestOIDCHandlers(t)
	req := httptest.NewRequest("GET", "/jwks", nil)
	rr := httptest.NewRecorder()
	h.HandleJWKS(rr, req)

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
}

func TestOIDCTokenExchange(t *testing.T) {
	h, cfg, _, _ := newTestOIDCHandlers(t)

	code := memory.GenerateCode()
	_ = h.codeStore.Save(&core.AuthCode{
		Code:        code,
		ClientID:    "testclient",
		RedirectURI: "https://app.test.local/callback",
		Email:       "user@test.local",
		Sub:         "user@test.local",
		Nonce:       "abc",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	})
	_ = cfg

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
	h.HandleToken(rr, req)

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
	h, _, _, _ := newTestOIDCHandlers(t)

	code := memory.GenerateCode()
	_ = h.codeStore.Save(&core.AuthCode{
		Code:        code,
		ClientID:    "testclient",
		RedirectURI: "https://app.test.local/callback",
		Email:       "user@test.local",
		Sub:         "user@test.local",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
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
	h.HandleToken(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first exchange: expected 200, got %d", rr.Code)
	}

	req2 := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()
	h.HandleToken(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("replay: expected 400, got %d", rr2.Code)
	}
}

func TestOIDCTokenWrongSecret(t *testing.T) {
	h, _, _, _ := newTestOIDCHandlers(t)

	code := memory.GenerateCode()
	_ = h.codeStore.Save(&core.AuthCode{
		Code:        code,
		ClientID:    "testclient",
		RedirectURI: "https://app.test.local/callback",
		Email:       "user@test.local",
		Sub:         "user@test.local",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
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
	h.HandleToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestOIDCAuthorizeWithPKCE(t *testing.T) {
	h, cfg, codeStore, _ := newTestOIDCHandlers(t)

	loginRR := httptest.NewRecorder()
	auth.CreateSession(loginRR, "user@test.local", "user@test.local", "sid-existing", cfg.SessionKey)

	req := httptest.NewRequest("GET", "/authorize?client_id=testclient&redirect_uri=https%3A%2F%2Fapp.test.local%2Fcallback&response_type=code&scope=openid+email&state=state-1&nonce=nonce-1&code_challenge=pkce-s256-value&code_challenge_method=S256", nil)
	for _, cookie := range loginRR.Result().Cookies() {
		req.AddCookie(cookie)
	}

	rr := httptest.NewRecorder()
	h.HandleAuthorize(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("showLogin should not be called when session exists")
	})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location == "" {
		t.Fatal("missing redirect location")
	}

	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatal("missing code in redirect")
	}

	ac, err := codeStore.Consume(code)
	if err != nil {
		t.Fatalf("consume code: %v", err)
	}
	if ac == nil {
		t.Fatal("expected stored auth code")
	}
	if ac.CodeChallenge != "pkce-s256-value" {
		t.Fatalf("code challenge = %q", ac.CodeChallenge)
	}
	if ac.CodeChallengeMethod != "S256" {
		t.Fatalf("code challenge method = %q", ac.CodeChallengeMethod)
	}
	if ac.SID != "sid-existing" {
		t.Fatalf("sid = %q", ac.SID)
	}
}

func TestOIDCTokenWithS256Verifier(t *testing.T) {
	h, _, _, _ := newTestOIDCHandlers(t)

	verifier := "correct-verifier-value"
	code := memory.GenerateCode()
	_ = h.codeStore.Save(&core.AuthCode{
		Code:                code,
		ClientID:            "testclient",
		RedirectURI:         "https://app.test.local/callback",
		Email:               "user@test.local",
		Sub:                 "user@test.local",
		Nonce:               "abc",
		CodeChallenge:       verifyPKCEChallengeForTest(verifier),
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.test.local/callback"},
		"client_id":     {"testclient"},
		"client_secret": {"testsecret"},
		"code_verifier": {verifier},
	}

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestOIDCTokenWithBadVerifier(t *testing.T) {
	h, _, _, _ := newTestOIDCHandlers(t)

	code := memory.GenerateCode()
	_ = h.codeStore.Save(&core.AuthCode{
		Code:                code,
		ClientID:            "testclient",
		RedirectURI:         "https://app.test.local/callback",
		Email:               "user@test.local",
		Sub:                 "user@test.local",
		CodeChallenge:       verifyPKCEChallengeForTest("good-verifier"),
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.test.local/callback"},
		"client_id":     {"testclient"},
		"client_secret": {"testsecret"},
		"code_verifier": {"wrong-verifier"},
	}

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "code_verifier mismatch") {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}

func TestOIDCTokenMissingVerifier(t *testing.T) {
	h, _, _, _ := newTestOIDCHandlers(t)

	code := memory.GenerateCode()
	_ = h.codeStore.Save(&core.AuthCode{
		Code:                code,
		ClientID:            "testclient",
		RedirectURI:         "https://app.test.local/callback",
		Email:               "user@test.local",
		Sub:                 "user@test.local",
		CodeChallenge:       verifyPKCEChallengeForTest("good-verifier"),
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(5 * time.Minute),
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
	h.HandleToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "code_verifier required") {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}

func verifyPKCEChallengeForTest(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
