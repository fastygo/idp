package hanko

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// jwtForTest builds a signed JWT with the supplied alg header and claim
// JSON. It also seeds the verifier's key cache so getKey() returns the
// matching public half without having to fetch /.well-known/jwks.json.
func jwtForTest(t *testing.T, v *JWTVerifier, alg string, claims any) string {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	v.mu.Lock()
	v.keys["test-kid"] = &priv.PublicKey
	v.fetched = time.Now()
	v.mu.Unlock()

	header := map[string]string{"alg": alg, "typ": "JWT", "kid": "test-kid"}
	hdrJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signing := hdrB64 + "." + claimsB64

	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerifyToken_RejectsNonRS256(t *testing.T) {
	v := NewJWTVerifier("https://hanko.example.com")

	tok := jwtForTest(t, v, "HS256", map[string]any{
		"sub": "u1", "email": "u@example.com", "exp": time.Now().Add(time.Hour).Unix(),
	})

	if _, err := v.VerifyToken(tok); err == nil {
		t.Fatal("expected rejection for non-RS256 alg")
	} else if !strings.Contains(err.Error(), "unsupported JWT alg") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyToken_RejectsAlgNone(t *testing.T) {
	v := NewJWTVerifier("https://hanko.example.com")

	header := map[string]string{"alg": "none", "typ": "JWT", "kid": "test-kid"}
	claims := map[string]any{"sub": "u1", "email": "u@example.com", "exp": time.Now().Add(time.Hour).Unix()}
	hdrB64 := base64.RawURLEncoding.EncodeToString(mustJSON(header))
	claimsB64 := base64.RawURLEncoding.EncodeToString(mustJSON(claims))
	tok := hdrB64 + "." + claimsB64 + "."

	if _, err := v.VerifyToken(tok); err == nil {
		t.Fatal("expected rejection for alg=none")
	}
}

func TestVerifyToken_AcceptsExpectedIssAud(t *testing.T) {
	v := NewJWTVerifierWithOptions("https://hanko.example.com", JWTVerifierOptions{
		ExpectedIssuer:   "https://hanko.example.com",
		ExpectedAudience: "idp-cyberos",
	})

	tok := jwtForTest(t, v, "RS256", map[string]any{
		"sub":   "u1",
		"email": "u@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iss":   "https://hanko.example.com",
		"aud":   []string{"idp-cyberos", "other"},
	})

	if _, err := v.VerifyToken(tok); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
}

func TestVerifyToken_RejectsBadIssuer(t *testing.T) {
	v := NewJWTVerifierWithOptions("https://hanko.example.com", JWTVerifierOptions{
		ExpectedIssuer: "https://hanko.example.com",
	})

	tok := jwtForTest(t, v, "RS256", map[string]any{
		"sub":   "u1",
		"email": "u@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iss":   "https://attacker.example.com",
	})

	if _, err := v.VerifyToken(tok); err == nil {
		t.Fatal("expected issuer rejection")
	} else if !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyToken_RejectsMissingAudience(t *testing.T) {
	v := NewJWTVerifierWithOptions("https://hanko.example.com", JWTVerifierOptions{
		ExpectedAudience: "idp-cyberos",
	})

	tok := jwtForTest(t, v, "RS256", map[string]any{
		"sub":   "u1",
		"email": "u@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"aud":   "someone-else",
	})

	if _, err := v.VerifyToken(tok); err == nil {
		t.Fatal("expected audience rejection")
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
