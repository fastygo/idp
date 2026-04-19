package core

import "time"

// TokenRevoker stores a denylist of token IDs (jti) so an issued JWT can
// be invalidated before its natural expiry.
//
// Implementations are expected to expire entries automatically — see
// Cleanup. The optional RevokeUntil hint lets callers bind the entry to
// the real exp claim of the underlying token so the deny-list cannot
// grow without bound.
type TokenRevoker interface {
	Revoke(jti string) error
	IsRevoked(jti string) (bool, error)
	Cleanup() error
}

// TokenRevokerWithExpiry is an optional extension implemented by stores
// that can pin each revocation to a specific expiry time. Callers should
// type-assert and only fall back to Revoke() when the implementation
// does not support it.
type TokenRevokerWithExpiry interface {
	TokenRevoker
	RevokeUntil(jti string, expiresAt time.Time) error
}
