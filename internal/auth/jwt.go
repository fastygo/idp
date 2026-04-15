package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type HankoClaims struct {
	Sub   string         `json:"sub"`
	Email HankoEmailClaim `json:"email"`
	Exp   int64          `json:"exp"`
	Iss   string         `json:"iss"`
}

type HankoEmailClaim struct {
	Address    string `json:"address"`
	IsPrimary  bool   `json:"is_primary"`
	IsVerified bool   `json:"is_verified"`
}

func (c *HankoEmailClaim) UnmarshalJSON(data []byte) error {
	var address string
	if err := json.Unmarshal(data, &address); err == nil {
		c.Address = address
		return nil
	}

	var obj struct {
		Address    string `json:"address"`
		IsPrimary  bool   `json:"is_primary"`
		IsVerified bool   `json:"is_verified"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}

	c.Address = obj.Address
	c.IsPrimary = obj.IsPrimary
	c.IsVerified = obj.IsVerified
	return nil
}

type JWTVerifier struct {
	jwksURL string
	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

func NewJWTVerifier(hankoAPIURL string) *JWTVerifier {
	url := strings.TrimRight(hankoAPIURL, "/") + "/.well-known/jwks.json"
	return &JWTVerifier{
		jwksURL: url,
		keys:    make(map[string]*rsa.PublicKey),
	}
}

func (v *JWTVerifier) VerifyToken(tokenStr string) (*HankoClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	headerJSON, err := Base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}

	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	pubKey, err := v.getKey(header.Kid)
	if err != nil {
		return nil, fmt.Errorf("get key: %w", err)
	}

	sigBytes, err := Base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	signed := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(signed))

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sigBytes); err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	payloadJSON, err := Base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	var claims HankoClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

func (v *JWTVerifier) getKey(kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	if key, ok := v.keys[kid]; ok && time.Since(v.fetched) < 5*time.Minute {
		v.mu.RUnlock()
		return key, nil
	}
	v.mu.RUnlock()

	if err := v.fetchJWKS(); err != nil {
		return nil, err
	}

	v.mu.RLock()
	defer v.mu.RUnlock()
	key, ok := v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("key %q not found in JWKS", kid)
	}
	return key, nil
}

func (v *JWTVerifier) fetchJWKS() error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(v.jwksURL)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS returned status %d", resp.StatusCode)
	}

	var jwks JWKSet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	v.keys = make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		if jwk.Kty != "RSA" {
			continue
		}
		pubKey, err := jwkToRSAPublicKey(jwk)
		if err != nil {
			continue
		}
		v.keys[jwk.Kid] = pubKey
	}
	v.fetched = time.Now()

	return nil
}

func jwkToRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	nBytes, err := Base64URLDecode(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("decode N: %w", err)
	}
	eBytes, err := Base64URLDecode(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("decode E: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
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
