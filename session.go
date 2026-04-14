package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	idpSessionCookie      = "idp_session"
	idpPendingCookie      = "idp_pending"
	idpOIDCPendingCookie  = "idp_oidc_pending"
	sessionDuration       = 8 * time.Hour
)

type IdPSession struct {
	Email     string `json:"email"`
	ExpiresAt int64  `json:"exp"`
}

type PendingAuthnRequest struct {
	RequestID  string `json:"rid"`
	SPEntityID string `json:"sp"`
	ACSUrl     string `json:"acs"`
	RelayState string `json:"rs"`
	ExpiresAt  int64  `json:"exp"`
}

func createSession(w http.ResponseWriter, email, sessionKey string) {
	sess := IdPSession{
		Email:     email,
		ExpiresAt: time.Now().Add(sessionDuration).Unix(),
	}
	val := signedEncode(sess, sessionKey)
	http.SetCookie(w, &http.Cookie{
		Name:     idpSessionCookie,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		MaxAge:   int(sessionDuration.Seconds()),
	})
}

func getSession(r *http.Request, sessionKey string) *IdPSession {
	cookie, err := r.Cookie(idpSessionCookie)
	if err != nil {
		return nil
	}
	var sess IdPSession
	if err := signedDecode(cookie.Value, sessionKey, &sess); err != nil {
		return nil
	}
	if time.Now().Unix() > sess.ExpiresAt {
		return nil
	}
	return &sess
}

func savePendingRequest(w http.ResponseWriter, req *ParsedRequest, sessionKey string) {
	pending := PendingAuthnRequest{
		RequestID:  req.ID,
		SPEntityID: req.SP.EntityID,
		ACSUrl:     req.SP.ACSUrl,
		RelayState: req.RelayState,
		ExpiresAt:  time.Now().Add(10 * time.Minute).Unix(),
	}
	val := signedEncode(pending, sessionKey)
	http.SetCookie(w, &http.Cookie{
		Name:     idpPendingCookie,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
}

func getPendingRequest(r *http.Request, sessionKey string) *PendingAuthnRequest {
	cookie, err := r.Cookie(idpPendingCookie)
	if err != nil {
		return nil
	}
	var pending PendingAuthnRequest
	if err := signedDecode(cookie.Value, sessionKey, &pending); err != nil {
		return nil
	}
	if time.Now().Unix() > pending.ExpiresAt {
		return nil
	}
	return &pending
}

func clearPendingRequest(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     idpPendingCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// OIDC pending request

type PendingOIDCRequest struct {
	ClientID    string `json:"cid"`
	RedirectURI string `json:"ru"`
	State       string `json:"st"`
	Nonce       string `json:"n"`
	Scope       string `json:"sc"`
	ExpiresAt   int64  `json:"exp"`
}

func saveOIDCPendingRequest(w http.ResponseWriter, req *PendingOIDCRequest, sessionKey string) {
	req.ExpiresAt = time.Now().Add(10 * time.Minute).Unix()
	val := signedEncode(req, sessionKey)
	http.SetCookie(w, &http.Cookie{
		Name:     idpOIDCPendingCookie,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
}

func getOIDCPendingRequest(r *http.Request, sessionKey string) *PendingOIDCRequest {
	cookie, err := r.Cookie(idpOIDCPendingCookie)
	if err != nil {
		return nil
	}
	var pending PendingOIDCRequest
	if err := signedDecode(cookie.Value, sessionKey, &pending); err != nil {
		return nil
	}
	if time.Now().Unix() > pending.ExpiresAt {
		return nil
	}
	return &pending
}

func clearOIDCPendingRequest(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     idpOIDCPendingCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// signedEncode serializes data to JSON, base64-encodes it, and appends HMAC-SHA256.
func signedEncode(data any, key string) string {
	payload, _ := json.Marshal(data)
	b64 := base64.RawURLEncoding.EncodeToString(payload)
	mac := computeHMAC(b64, key)
	return b64 + "." + mac
}

// signedDecode verifies HMAC and decodes the payload.
func signedDecode(value, key string, dst any) error {
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid format")
	}
	expected := computeHMAC(parts[0], key)
	if !hmac.Equal([]byte(parts[1]), []byte(expected)) {
		return fmt.Errorf("invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, dst)
}

func computeHMAC(data, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
