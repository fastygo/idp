package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

type oidcJWTHeader struct {
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
	Email string `json:"email,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

type accessTokenClaims struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Email string `json:"email,omitempty"`
	Scope string `json:"scope,omitempty"`
}

func computeKID(kp *IdPKeyPair) string {
	h := sha256.Sum256(kp.CertDER)
	return base64.RawURLEncoding.EncodeToString(h[:8])
}

func GenerateIDToken(kp *IdPKeyPair, issuer, audience, sub, email, nonce string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := idTokenClaims{
		Iss:   issuer,
		Sub:   sub,
		Aud:   audience,
		Exp:   now.Add(ttl).Unix(),
		Iat:   now.Unix(),
		Email: email,
		Nonce: nonce,
	}
	return signJWT(kp, claims)
}

func GenerateAccessToken(kp *IdPKeyPair, issuer, sub, email string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := accessTokenClaims{
		Iss:   issuer,
		Sub:   sub,
		Exp:   now.Add(ttl).Unix(),
		Iat:   now.Unix(),
		Email: email,
		Scope: "openid email",
	}
	return signJWT(kp, claims)
}

func signJWT(kp *IdPKeyPair, claims any) (string, error) {
	header := oidcJWTHeader{Alg: "RS256", Typ: "JWT", Kid: computeKID(kp)}

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

// PublicKeyJWK returns the IdP public key as a JWK map for the /jwks endpoint.
func PublicKeyJWK(kp *IdPKeyPair) map[string]string {
	pub := &kp.PrivateKey.PublicKey
	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": computeKID(kp),
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}
