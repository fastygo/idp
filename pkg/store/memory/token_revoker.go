package memory

import (
	"sync"
	"time"
)

// TokenRevoker is an in-memory implementation of core.TokenRevoker.
//
// Each revocation is stored together with the access-token's natural
// expiry. Cleanup() then drops every entry whose expiry already passed,
// which keeps the working set bounded by the number of currently *valid*
// tokens — without it the map grew forever (one entry per token /revoke
// call ever made), which is a genuine, observed Go memory-leak pattern.
//
// Without an expiry hint we fall back to a bounded "forget after one
// week" TTL so a misconfigured client cannot exhaust the host's RAM by
// looping /revoke.
type TokenRevoker struct {
	mu        sync.RWMutex
	revoked   map[string]time.Time
	defaultFn func() time.Duration
}

const defaultRevokerEntryTTL = 7 * 24 * time.Hour

func NewTokenRevoker() *TokenRevoker {
	return &TokenRevoker{
		revoked:   make(map[string]time.Time),
		defaultFn: func() time.Duration { return defaultRevokerEntryTTL },
	}
}

// Revoke marks jti as revoked with the default fallback TTL.
func (r *TokenRevoker) Revoke(jti string) error {
	return r.RevokeUntil(jti, time.Now().Add(r.defaultFn()))
}

// RevokeUntil pins the revocation entry to the access-token's own
// expiry — once the underlying token can no longer pass signature/exp
// checks the revocation list entry is no longer needed and may be
// reclaimed by Cleanup().
func (r *TokenRevoker) RevokeUntil(jti string, expiresAt time.Time) error {
	if jti == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.revoked[jti]; ok && existing.After(expiresAt) {
		// Keep the more conservative (later) expiry.
		return nil
	}
	r.revoked[jti] = expiresAt
	return nil
}

func (r *TokenRevoker) IsRevoked(jti string) (bool, error) {
	if jti == "" {
		return false, nil
	}

	r.mu.RLock()
	exp, ok := r.revoked[jti]
	r.mu.RUnlock()
	if !ok {
		return false, nil
	}
	if time.Now().After(exp) {
		// Lazy cleanup so callers don't need to wait for the periodic
		// Cleanup() goroutine to free a single entry.
		r.mu.Lock()
		if exp2, ok := r.revoked[jti]; ok && time.Now().After(exp2) {
			delete(r.revoked, jti)
		}
		r.mu.Unlock()
		return false, nil
	}
	return true, nil
}

// Cleanup drops every entry whose TTL has elapsed. Safe to call from a
// background goroutine.
func (r *TokenRevoker) Cleanup() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for k, exp := range r.revoked {
		if now.After(exp) {
			delete(r.revoked, k)
		}
	}
	return nil
}

// Len is exposed for tests / metrics.
func (r *TokenRevoker) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.revoked)
}
