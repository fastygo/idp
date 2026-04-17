package memory

import (
	"slices"
	"sync"

	"idp-cyberos/pkg/core"
)

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*core.SessionRecord
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*core.SessionRecord),
	}
}

func (s *SessionStore) Register(rec *core.SessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	copyRec := *rec
	copyRec.Clients = append([]string(nil), rec.Clients...)
	s.sessions[rec.SID] = &copyRec
	return nil
}

func (s *SessionStore) AddClient(sid, clientID string) error {
	if sid == "" || clientID == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.sessions[sid]
	if !ok {
		return nil
	}
	if !slices.Contains(rec.Clients, clientID) {
		rec.Clients = append(rec.Clients, clientID)
	}
	return nil
}

func (s *SessionStore) Lookup(sid string) (*core.SessionRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, ok := s.sessions[sid]
	if !ok {
		return nil, nil
	}

	copyRec := *rec
	copyRec.Clients = append([]string(nil), rec.Clients...)
	return &copyRec, nil
}

func (s *SessionStore) LookupBySub(sub string) ([]*core.SessionRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []*core.SessionRecord
	for _, rec := range s.sessions {
		if rec.Sub != sub {
			continue
		}
		copyRec := *rec
		copyRec.Clients = append([]string(nil), rec.Clients...)
		out = append(out, &copyRec)
	}
	return out, nil
}

func (s *SessionStore) Revoke(sid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sid)
	return nil
}

func (s *SessionStore) Cleanup() error {
	return nil
}
