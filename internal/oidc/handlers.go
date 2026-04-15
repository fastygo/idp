package oidc

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"idp-cyberos/internal/auth"
	"idp-cyberos/internal/config"
)

type Handlers struct {
	cfg       *config.Config
	kp        *auth.IdPKeyPair
	codeStore *CodeStore
}

func NewHandlers(cfg *config.Config, kp *auth.IdPKeyPair, codeStore *CodeStore) *Handlers {
	return &Handlers{
		cfg:       cfg,
		kp:        kp,
		codeStore: codeStore,
	}
}

func (h *Handlers) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	base := strings.TrimRight(h.cfg.BaseURL, "/")
	doc := map[string]any{
		"issuer":                 base,
		"authorization_endpoint": base + "/authorize",
		"token_endpoint":         base + "/token",
		"userinfo_endpoint":      base + "/userinfo",
		"jwks_uri":               base + "/jwks",
		"response_types_supported": []string{"code"},
		"subject_types_supported":  []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":       []string{"openid", "email"},
		"grant_types_supported":  []string{"authorization_code"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"claims_supported":       []string{"sub", "email", "iss", "aud", "exp", "iat"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

type ShowLoginFunc func(w http.ResponseWriter, r *http.Request)

func (h *Handlers) HandleAuthorize(showLogin ShowLoginFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID := r.URL.Query().Get("client_id")
		redirectURI := r.URL.Query().Get("redirect_uri")
		responseType := r.URL.Query().Get("response_type")
		scope := r.URL.Query().Get("scope")
		state := r.URL.Query().Get("state")
		nonce := r.URL.Query().Get("nonce")

		if responseType != "code" {
			http.Error(w, "unsupported_response_type", http.StatusBadRequest)
			return
		}

		client := h.cfg.FindOIDCClient(clientID)
		if client == nil {
			http.Error(w, "invalid client_id", http.StatusBadRequest)
			return
		}

		if !client.ValidRedirectURI(redirectURI) {
			http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
			return
		}

		sess := auth.GetSession(r, h.cfg.SessionKey)
		if sess != nil {
			h.IssueCode(w, r, client, redirectURI, state, nonce, scope, sess.Email)
			return
		}

		auth.SaveOIDCPendingRequest(w, &auth.PendingOIDCRequest{
			ClientID:    clientID,
			RedirectURI: redirectURI,
			State:       state,
			Nonce:       nonce,
			Scope:       scope,
		}, h.cfg.SessionKey)

		showLogin(w, r)
	}
}

func (h *Handlers) IssueCode(w http.ResponseWriter, r *http.Request, client *config.OIDCClient, redirectURI, state, nonce, scope, email string) {
	code := GenerateCode()
	h.codeStore.Save(&AuthCode{
		Code:        code,
		ClientID:    client.ClientID,
		RedirectURI: redirectURI,
		Email:       email,
		Sub:         email,
		Nonce:       nonce,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	})

	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (h *Handlers) HandleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request", "malformed form body")
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		tokenError(w, "unsupported_grant_type", "only authorization_code is supported")
		return
	}

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	client := h.cfg.FindOIDCClient(clientID)
	if client == nil {
		tokenError(w, "invalid_client", "unknown client")
		return
	}

	if !secureCompare(client.ClientSecret, clientSecret) {
		tokenError(w, "invalid_client", "bad credentials")
		return
	}

	ac := h.codeStore.Consume(code)
	if ac == nil {
		tokenError(w, "invalid_grant", "code expired or already used")
		return
	}

	if ac.ClientID != clientID {
		tokenError(w, "invalid_grant", "code was issued to a different client")
		return
	}

	if ac.RedirectURI != redirectURI {
		tokenError(w, "invalid_grant", "redirect_uri mismatch")
		return
	}

	idToken, err := GenerateIDToken(h.kp, h.cfg.BaseURL, clientID, ac.Sub, ac.Email, ac.Nonce, time.Hour)
	if err != nil {
		log.Printf("OIDC id_token generation error: %v", err)
		tokenError(w, "server_error", "token generation failed")
		return
	}

	accessToken, err := GenerateAccessToken(h.kp, h.cfg.BaseURL, ac.Sub, ac.Email, time.Hour)
	if err != nil {
		log.Printf("OIDC access_token generation error: %v", err)
		tokenError(w, "server_error", "token generation failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (h *Handlers) HandleUserinfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := h.verifyAccessToken(tokenStr)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"sub":   claims.Sub,
		"email": claims.Email,
	})
}

func (h *Handlers) verifyAccessToken(tokenStr string) (*AccessTokenClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, http.ErrNoCookie
	}

	payloadJSON, err := auth.Base64URLDecode(parts[1])
	if err != nil {
		return nil, err
	}

	var claims AccessTokenClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, err
	}

	if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
		return nil, http.ErrNoCookie
	}

	sigBytes, err := auth.Base64URLDecode(parts[2])
	if err != nil {
		return nil, err
	}

	signed := parts[0] + "." + parts[1]
	hsh := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(&h.kp.PrivateKey.PublicKey, crypto.SHA256, hsh[:], sigBytes); err != nil {
		return nil, err
	}

	return &claims, nil
}

func (h *Handlers) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	jwk := PublicKeyJWK(h.kp)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(map[string]any{
		"keys": []any{jwk},
	})
}

func tokenError(w http.ResponseWriter, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

func secureCompare(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}
