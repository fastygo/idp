package config

import (
	"strings"
	"testing"
)

func TestValidate_RejectsPlaceholder(t *testing.T) {
	cases := []string{
		"change-me-to-a-long-random-secret",
		"CHANGE-ME-IS-NOT-OK",
		"changeme",
	}
	for _, in := range cases {
		c := &Config{SessionKey: in}
		err := c.Validate()
		if err == nil {
			t.Fatalf("expected rejection for %q", in)
		}
		if !strings.Contains(err.Error(), "placeholder") {
			t.Fatalf("expected placeholder error for %q, got %v", in, err)
		}
	}
}

func TestValidate_RejectsShortKey(t *testing.T) {
	c := &Config{SessionKey: "short-key"}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected rejection for short key")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Fatalf("expected length error, got %v", err)
	}
}

func TestValidate_RejectsEmpty(t *testing.T) {
	c := &Config{SessionKey: ""}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected rejection for empty key")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected required error, got %v", err)
	}
}

func TestValidate_AcceptsRealKey(t *testing.T) {
	c := &Config{SessionKey: "abcdefghijklmnopqrstuvwxyz0123456789"}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
}
