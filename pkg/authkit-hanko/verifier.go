package hanko

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

	"idp-cyberos/pkg/core"
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

type hankoClaims struct {
	Sub   string          `json:"sub"`
	Email hankoEmailClaim `json:"email"`
	Exp   int64           `json:"exp"`
	Iss   string          `json:"iss"`
	Aud   audienceClaim   `json:"aud,omitempty"`
}

// audienceClaim accepts both string and []string per RFC 7519 §4.1.3.
type audienceClaim []string

func (a *audienceClaim) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s != "" {
			*a = audienceClaim{s}
		}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*a = audienceClaim(arr)
	return nil
}

func (a audienceClaim) Has(want string) bool {
	for _, v := range a {
		if v == want {
			return true
		}
	}
	return false
}

type hankoEmailClaim struct {
	Address    string `json:"address"`
	IsPrimary  bool   `json:"is_primary"`
	IsVerified bool   `json:"is_verified"`
}

func (c *hankoEmailClaim) UnmarshalJSON(data []byte) error {
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

// JWTVerifier validates Hanko-issued JWTs. It caches the JWKS, enforces
// RS256, and (when configured) checks the issuer and audience claims.
//
// expectedIssuer / expectedAudience may be empty for backward compatibility
// with deployments that have not yet configured them, but production setups
// MUST set them — otherwise a token from any RSA-signing Hanko-compatible
// issuer would be accepted as long as the key turns up in the configured
// JWKS endpoint.
type JWTVerifier struct {
	jwksURL          string
	expectedIssuer   string
	expectedAudience string
	mu               sync.RWMutex
	keys             map[string]*rsa.PublicKey
	fetched          time.Time
}

// JWTVerifierOptions tunes the issuer / audience checks. Empty values mean
// "do not check this claim" so the verifier stays drop-in compatible with
// existing single-tenant Hanko setups while letting hardened deployments
// pin the trust boundary.
type JWTVerifierOptions struct {
	ExpectedIssuer   string
	ExpectedAudience string
}

func NewJWTVerifier(hankoAPIURL string) *JWTVerifier {
	return NewJWTVerifierWithOptions(hankoAPIURL, JWTVerifierOptions{})
}

func NewJWTVerifierWithOptions(hankoAPIURL string, opts JWTVerifierOptions) *JWTVerifier {
	url := strings.TrimRight(hankoAPIURL, "/") + "/.well-known/jwks.json"
	return &JWTVerifier{
		jwksURL:          url,
		expectedIssuer:   strings.TrimSpace(opts.ExpectedIssuer),
		expectedAudience: strings.TrimSpace(opts.ExpectedAudience),
		keys:             make(map[string]*rsa.PublicKey),
	}
}

func (v *Verifier) VerifyToken(token string) (*core.IdentityClaims, error) {
	return v.jwtVerifier.VerifyToken(token)
}

func (v *JWTVerifier) VerifyToken(tokenStr string) (*core.IdentityClaims, error) {
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

	// Strict alg allowlist: refuse anything other than RS256 to defeat
	// classic alg-substitution attacks (e.g. switching to "none" or to a
	// symmetric HS256 that we'd then verify with the public key bytes).
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported JWT alg %q (only RS256 accepted)", header.Alg)
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

	var claims hankoClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("token expired")
	}

	if v.expectedIssuer != "" && claims.Iss != v.expectedIssuer {
		return nil, fmt.Errorf("unexpected issuer %q", claims.Iss)
	}
	if v.expectedAudience != "" && !claims.Aud.Has(v.expectedAudience) {
		return nil, fmt.Errorf("token audience does not include %q", v.expectedAudience)
	}

	return &core.IdentityClaims{
		Sub:           claims.Sub,
		Email:         claims.Email.Address,
		EmailVerified: claims.Email.IsVerified,
		Exp:           claims.Exp,
		Issuer:        claims.Iss,
	}, nil
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
