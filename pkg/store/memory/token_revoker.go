package memory

import "sync"

type TokenRevoker struct {
	mu      sync.RWMutex
	revoked map[string]struct{}
}

func NewTokenRevoker() *TokenRevoker {
	return &TokenRevoker{
		revoked: make(map[string]struct{}),
	}
}

func (r *TokenRevoker) Revoke(jti string) error {
	if jti == "" {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[jti] = struct{}{}
	return nil
}

func (r *TokenRevoker) IsRevoked(jti string) (bool, error) {
	if jti == "" {
		return false, nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.revoked[jti]
	return ok, nil
}

func (r *TokenRevoker) Cleanup() error {
	return nil
}
