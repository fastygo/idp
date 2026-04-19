package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestComputeAtHash_LengthAndDeterminism(t *testing.T) {
	got := computeAtHash("some-access-token")
	if got == "" {
		t.Fatal("expected non-empty at_hash")
	}
	// SHA-256 produces 32 bytes; left half is 16 bytes; base64url with
	// no padding of 16 bytes is 22 chars.
	if len(got) != 22 {
		t.Fatalf("expected 22-char base64url, got %d (%q)", len(got), got)
	}
	if got != computeAtHash("some-access-token") {
		t.Fatal("at_hash must be deterministic")
	}
	if got == computeAtHash("different") {
		t.Fatal("at_hash must depend on the access token")
	}
}

func TestGenerateIDTokenWithAccess_BindsAtHash(t *testing.T) {
	kp := generateTestKeyPair(t)

	access := "test-access-token-value"
	idToken, err := GenerateIDTokenWithAccess(kp, "https://idp.test.local", "client", "sub", "u@example.com", "nonce", "sid", access, time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWT to have 3 parts")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	want := computeAtHash(access)
	if !strings.Contains(string(payload), `"at_hash":"`+want+`"`) {
		t.Fatalf("expected at_hash %q in payload, got %s", want, string(payload))
	}

	// Sanity: matches the SHA-256 left-128 manual computation.
	sum := sha256.Sum256([]byte(access))
	manual := base64.RawURLEncoding.EncodeToString(sum[:16])
	if manual != want {
		t.Fatalf("manual at_hash %q != computeAtHash %q", manual, want)
	}
}

func TestScopeContainsOpenID(t *testing.T) {
	cases := map[string]bool{
		"":                false,
		"openid":          true,
		"email openid":    true,
		" openid ":        true,
		"openidx":         false,
		"profile email":   false,
		"OpenID":          false,
		"openid profile": true,
	}
	for in, want := range cases {
		if got := scopeContainsOpenID(in); got != want {
			t.Fatalf("scopeContainsOpenID(%q) = %v, want %v", in, got, want)
		}
	}
}
