package memory

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"idp-cyberos/pkg/core"
)

type CodeStore struct {
	mu    sync.Mutex
	codes map[string]*core.AuthCode
}

func NewCodeStore() *CodeStore {
	return &CodeStore{codes: make(map[string]*core.AuthCode)}
}

func (s *CodeStore) Save(ac *core.AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[ac.Code] = ac
	return nil
}

func (s *CodeStore) Consume(code string) (*core.AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.codes[code]
	if !ok {
		return nil, nil
	}
	delete(s.codes, code)
	if time.Now().After(ac.ExpiresAt) {
		return nil, nil
	}
	return ac, nil
}

func (s *CodeStore) Cleanup() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.codes {
		if now.After(v.ExpiresAt) {
			delete(s.codes, k)
		}
	}
	return nil
}

// Len is exposed for tests / metrics.
func (s *CodeStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.codes)
}

func GenerateCode() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
