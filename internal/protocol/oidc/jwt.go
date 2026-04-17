package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"idp-cyberos/internal/auth"
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type idTokenClaims struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Aud   string `json:"aud"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Jti   string `json:"jti,omitempty"`
	Sid   string `json:"sid,omitempty"`
	Email string `json:"email,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

type AccessTokenClaims struct {
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
	Aud      string `json:"aud,omitempty"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	Jti      string `json:"jti,omitempty"`
	Sid      string `json:"sid,omitempty"`
	Email    string `json:"email,omitempty"`
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}

type logoutTokenClaims struct {
	Iss    string         `json:"iss"`
	Sub    string         `json:"sub"`
	Aud    string         `json:"aud"`
	Iat    int64          `json:"iat"`
	Jti    string         `json:"jti"`
	Sid    string         `json:"sid,omitempty"`
	Events map[string]any `json:"events"`
}

func ComputeKID(kp *auth.IdPKeyPair) string {
	h := sha256.Sum256(kp.CertDER)
	return base64.RawURLEncoding.EncodeToString(h[:8])
}

func GenerateIDToken(kp *auth.IdPKeyPair, issuer, audience, sub, email, nonce, sid string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := idTokenClaims{
		Iss:   issuer,
		Sub:   sub,
		Aud:   audience,
		Exp:   now.Add(ttl).Unix(),
		Iat:   now.Unix(),
		Jti:   randomJTI(),
		Sid:   sid,
		Email: email,
		Nonce: nonce,
	}
	return signJWT(kp, claims)
}

func GenerateAccessToken(kp *auth.IdPKeyPair, issuer, audience, sub, email, scope, sid string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := AccessTokenClaims{
		Iss:      issuer,
		Sub:      sub,
		Aud:      audience,
		Exp:      now.Add(ttl).Unix(),
		Iat:      now.Unix(),
		Jti:      randomJTI(),
		Sid:      sid,
		Email:    email,
		Scope:    scope,
		ClientID: audience,
	}
	return signJWT(kp, claims)
}

func GenerateLogoutToken(kp *auth.IdPKeyPair, issuer, audience, sub, sid string) (string, error) {
	claims := logoutTokenClaims{
		Iss: issuer,
		Sub: sub,
		Aud: audience,
		Iat: time.Now().Unix(),
		Jti: randomJTI(),
		Sid: sid,
		Events: map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}
	return signJWT(kp, claims)
}

func signJWT(kp *auth.IdPKeyPair, claims any) (string, error) {
	header := jwtHeader{Alg: "RS256", Typ: "JWT", Kid: ComputeKID(kp)}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, kp.PrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("RSA sign: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func PublicKeyJWK(kp *auth.IdPKeyPair) map[string]string {
	pub := &kp.PrivateKey.PublicKey
	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": ComputeKID(kp),
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func Base64URLDecode(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func randomJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func VerifySignedClaims(token string, publicKey *rsa.PublicKey, dst any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format")
	}

	payloadJSON, err := Base64URLDecode(parts[1])
	if err != nil {
		return err
	}

	sigBytes, err := Base64URLDecode(parts[2])
	if err != nil {
		return err
	}

	signed := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], sigBytes); err != nil {
		return err
	}

	return json.Unmarshal(payloadJSON, dst)
}
