package auth

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
	IdpSessionCookie     = "idp_session"
	IdpPendingCookie     = "idp_pending"
	IdpOIDCPendingCookie = "idp_oidc_pending"
	SessionDuration      = 8 * time.Hour
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

type PendingOIDCRequest struct {
	ClientID    string `json:"cid"`
	RedirectURI string `json:"ru"`
	State       string `json:"st"`
	Nonce       string `json:"n"`
	Scope       string `json:"sc"`
	ExpiresAt   int64  `json:"exp"`
}

func CreateSession(w http.ResponseWriter, email, sessionKey string) {
	sess := IdPSession{
		Email:     email,
		ExpiresAt: time.Now().Add(SessionDuration).Unix(),
	}
	val := SignedEncode(sess, sessionKey)
	http.SetCookie(w, &http.Cookie{
		Name:     IdpSessionCookie,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		MaxAge:   int(SessionDuration.Seconds()),
	})
}

func ClearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     IdpSessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
}

func GetSession(r *http.Request, sessionKey string) *IdPSession {
	cookie, err := r.Cookie(IdpSessionCookie)
	if err != nil {
		return nil
	}
	var sess IdPSession
	if err := SignedDecode(cookie.Value, sessionKey, &sess); err != nil {
		return nil
	}
	if time.Now().Unix() > sess.ExpiresAt {
		return nil
	}
	return &sess
}

func SavePendingRequest(w http.ResponseWriter, requestID, spEntityID, acsURL, relayState, sessionKey string) {
	pending := PendingAuthnRequest{
		RequestID:  requestID,
		SPEntityID: spEntityID,
		ACSUrl:     acsURL,
		RelayState: relayState,
		ExpiresAt:  time.Now().Add(10 * time.Minute).Unix(),
	}
	val := SignedEncode(pending, sessionKey)
	http.SetCookie(w, &http.Cookie{
		Name:     IdpPendingCookie,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
}

func GetPendingRequest(r *http.Request, sessionKey string) *PendingAuthnRequest {
	cookie, err := r.Cookie(IdpPendingCookie)
	if err != nil {
		return nil
	}
	var pending PendingAuthnRequest
	if err := SignedDecode(cookie.Value, sessionKey, &pending); err != nil {
		return nil
	}
	if time.Now().Unix() > pending.ExpiresAt {
		return nil
	}
	return &pending
}

func ClearPendingRequest(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     IdpPendingCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func SaveOIDCPendingRequest(w http.ResponseWriter, req *PendingOIDCRequest, sessionKey string) {
	req.ExpiresAt = time.Now().Add(10 * time.Minute).Unix()
	val := SignedEncode(req, sessionKey)
	http.SetCookie(w, &http.Cookie{
		Name:     IdpOIDCPendingCookie,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
}

func GetOIDCPendingRequest(r *http.Request, sessionKey string) *PendingOIDCRequest {
	cookie, err := r.Cookie(IdpOIDCPendingCookie)
	if err != nil {
		return nil
	}
	var pending PendingOIDCRequest
	if err := SignedDecode(cookie.Value, sessionKey, &pending); err != nil {
		return nil
	}
	if time.Now().Unix() > pending.ExpiresAt {
		return nil
	}
	return &pending
}

func ClearOIDCPendingRequest(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     IdpOIDCPendingCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func SignedEncode(data any, key string) string {
	payload, _ := json.Marshal(data)
	b64 := base64.RawURLEncoding.EncodeToString(payload)
	mac := computeHMAC(b64, key)
	return b64 + "." + mac
}

func SignedDecode(value, key string, dst any) error {
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
