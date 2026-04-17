package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"idp-cyberos/pkg/core"
	"idp-cyberos/pkg/store/memory"
)

func TestEndSessionRedirectsToWhitelistedURI(t *testing.T) {
	h, cfg, _, sessionStore := newTestOIDCHandlers(t)
	cfg.OIDCClients[0].PostLogoutRedirectURIs = []string{"https://app.test.local/logout/callback"}
	cfg.BuildIndexes()

	if err := sessionStore.Register(&core.SessionRecord{
		SID:       "sid-1",
		Sub:       "user@test.local",
		Email:     "user@test.local",
		Clients:   []string{"testclient"},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("register session: %v", err)
	}

	idToken, err := GenerateIDToken(h.kp, cfg.BaseURL, "testclient", "user@test.local", "user@test.local", "", "sid-1", time.Hour)
	if err != nil {
		t.Fatalf("generate id token: %v", err)
	}

	req := httptest.NewRequest("GET", "/end_session?id_token_hint="+url.QueryEscape(idToken)+"&post_logout_redirect_uri="+url.QueryEscape("https://app.test.local/logout/callback"), nil)
	rr := httptest.NewRecorder()
	h.HandleEndSession(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "https://app.test.local/logout/callback" {
		t.Fatalf("location = %q", rr.Header().Get("Location"))
	}
}

func TestEndSessionIgnoresUnknownPostLogoutURI(t *testing.T) {
	h, cfg, _, sessionStore := newTestOIDCHandlers(t)
	cfg.OIDCClients[0].PostLogoutRedirectURIs = []string{"https://app.test.local/logout/callback"}
	cfg.BuildIndexes()

	if err := sessionStore.Register(&core.SessionRecord{
		SID:       "sid-1",
		Sub:       "user@test.local",
		Email:     "user@test.local",
		Clients:   []string{"testclient"},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("register session: %v", err)
	}

	idToken, err := GenerateIDToken(h.kp, cfg.BaseURL, "testclient", "user@test.local", "user@test.local", "", "sid-1", time.Hour)
	if err != nil {
		t.Fatalf("generate id token: %v", err)
	}

	req := httptest.NewRequest("GET", "/end_session?id_token_hint="+url.QueryEscape(idToken)+"&post_logout_redirect_uri="+url.QueryEscape("https://evil.test/logout"), nil)
	rr := httptest.NewRecorder()
	h.HandleEndSession(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "https://app.test.local/" {
		t.Fatalf("location = %q", rr.Header().Get("Location"))
	}
}

func TestEndSessionRendersFrontChannelPage(t *testing.T) {
	h, cfg, _, sessionStore := newTestOIDCHandlers(t)
	cfg.OIDCClients[0].PostLogoutRedirectURIs = []string{"https://app.test.local/logout/callback"}
	cfg.OIDCClients[0].FrontChannelLogoutURI = "https://app.test.local/frontchannel-logout"
	cfg.OIDCClients[0].FrontChannelLogoutSession = true
	cfg.BuildIndexes()

	if err := sessionStore.Register(&core.SessionRecord{
		SID:       "sid-1",
		Sub:       "user@test.local",
		Email:     "user@test.local",
		Clients:   []string{"testclient"},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("register session: %v", err)
	}

	idToken, err := GenerateIDToken(h.kp, cfg.BaseURL, "testclient", "user@test.local", "user@test.local", "", "sid-1", time.Hour)
	if err != nil {
		t.Fatalf("generate id token: %v", err)
	}

	req := httptest.NewRequest("GET", "/end_session?id_token_hint="+url.QueryEscape(idToken)+"&post_logout_redirect_uri="+url.QueryEscape("https://app.test.local/logout/callback"), nil)
	rr := httptest.NewRecorder()
	h.HandleEndSession(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "https://app.test.local/frontchannel-logout") {
		t.Fatalf("body missing frontchannel url: %s", body)
	}
	if !strings.Contains(body, "sid=sid-1") {
		t.Fatalf("body missing sid: %s", body)
	}
}

func TestEndSessionGeneratesValidLogoutToken(t *testing.T) {
	h, cfg, _, _ := newTestOIDCHandlers(t)
	token, err := GenerateLogoutToken(h.kp, cfg.BaseURL, "testclient", "user@test.local", "sid-1")
	if err != nil {
		t.Fatalf("generate logout token: %v", err)
	}

	var claims logoutTokenClaims
	if err := VerifySignedClaims(token, &h.kp.PrivateKey.PublicKey, &claims); err != nil {
		t.Fatalf("verify logout token: %v", err)
	}

	if claims.Aud != "testclient" {
		t.Fatalf("aud = %q", claims.Aud)
	}
	if claims.Sid != "sid-1" {
		t.Fatalf("sid = %q", claims.Sid)
	}
	if _, ok := claims.Events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Fatalf("events = %#v", claims.Events)
	}
}

func TestEndSessionMakesUserinfoFail(t *testing.T) {
	h, cfg, _, sessionStore := newTestOIDCHandlers(t)
	cfg.OIDCClients[0].PostLogoutRedirectURIs = []string{"https://app.test.local/logout/callback"}
	cfg.BuildIndexes()

	registerSessionForTest(t, sessionStore, "sid-1", "user@test.local")
	accessToken := issueAccessTokenForTest(t, h, cfg, "testclient", "sid-1", time.Hour)
	idToken, err := GenerateIDToken(h.kp, cfg.BaseURL, "testclient", "user@test.local", "user@test.local", "", "sid-1", time.Hour)
	if err != nil {
		t.Fatalf("generate id token: %v", err)
	}

	req := httptest.NewRequest("GET", "/end_session?id_token_hint="+url.QueryEscape(idToken)+"&post_logout_redirect_uri="+url.QueryEscape("https://app.test.local/logout/callback"), nil)
	rr := httptest.NewRecorder()
	h.HandleEndSession(rr, req)

	userinfoReq := httptest.NewRequest("GET", "/userinfo", nil)
	userinfoReq.Header.Set("Authorization", "Bearer "+accessToken)
	userinfoRR := httptest.NewRecorder()
	h.HandleUserinfo(userinfoRR, userinfoReq)
	if userinfoRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", userinfoRR.Code)
	}
}

func TestSessionStoreLookupAndRevoke(t *testing.T) {
	store := memory.NewSessionStore()
	rec := &core.SessionRecord{
		SID:       "sid-1",
		Sub:       "user@test.local",
		Email:     "user@test.local",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	if err := store.Register(rec); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := store.AddClient("sid-1", "testclient"); err != nil {
		t.Fatalf("add client: %v", err)
	}

	found, err := store.Lookup("sid-1")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if found == nil || len(found.Clients) != 1 || found.Clients[0] != "testclient" {
		t.Fatalf("lookup result = %#v", found)
	}

	bySub, err := store.LookupBySub("user@test.local")
	if err != nil {
		t.Fatalf("lookup by sub: %v", err)
	}
	if len(bySub) != 1 || bySub[0].SID != "sid-1" {
		t.Fatalf("lookup by sub = %#v", bySub)
	}

	if err := store.Revoke("sid-1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	found, err = store.Lookup("sid-1")
	if err != nil {
		t.Fatalf("lookup after revoke: %v", err)
	}
	if found != nil {
		t.Fatalf("expected nil after revoke, got %#v", found)
	}
}
