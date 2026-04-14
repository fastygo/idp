package main

import (
	"encoding/json"
	"testing"
)

func TestHankoEmailClaimUnmarshalString(t *testing.T) {
	var claims HankoClaims
	if err := json.Unmarshal([]byte(`{"sub":"u1","email":"user@example.com","exp":123}`), &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	if claims.Email.Address != "user@example.com" {
		t.Fatalf("email address = %q", claims.Email.Address)
	}
}

func TestHankoEmailClaimUnmarshalObject(t *testing.T) {
	var claims HankoClaims
	payload := `{
		"sub":"u1",
		"email":{
			"address":"user@example.com",
			"is_primary":true,
			"is_verified":false
		},
		"exp":123
	}`
	if err := json.Unmarshal([]byte(payload), &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	if claims.Email.Address != "user@example.com" {
		t.Fatalf("email address = %q", claims.Email.Address)
	}
	if !claims.Email.IsPrimary {
		t.Fatal("expected primary email")
	}
	if claims.Email.IsVerified {
		t.Fatal("expected unverified email")
	}
}
