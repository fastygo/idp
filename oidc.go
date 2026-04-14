package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type AuthCode struct {
	Code        string
	ClientID    string
	RedirectURI string
	Email       string
	Sub         string
	Nonce       string
	ExpiresAt   time.Time
}

type CodeStore struct {
	mu    sync.Mutex
	codes map[string]*AuthCode
}

func NewCodeStore() *CodeStore {
	return &CodeStore{codes: make(map[string]*AuthCode)}
}

func (s *CodeStore) Save(ac *AuthCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[ac.Code] = ac
}

// Consume retrieves and deletes the code (one-time use).
func (s *CodeStore) Consume(code string) *AuthCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.codes[code]
	if !ok {
		return nil
	}
	delete(s.codes, code)
	if time.Now().After(ac.ExpiresAt) {
		return nil
	}
	return ac
}

func (s *CodeStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.codes {
		if now.After(v.ExpiresAt) {
			delete(s.codes, k)
		}
	}
}

func generateCode() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
