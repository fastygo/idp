package core

import "time"

type SessionRecord struct {
	SID       string
	Sub       string
	Email     string
	Clients   []string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type SessionStore interface {
	Register(rec *SessionRecord) error
	AddClient(sid, clientID string) error
	Lookup(sid string) (*SessionRecord, error)
	LookupBySub(sub string) ([]*SessionRecord, error)
	Revoke(sid string) error
	Cleanup() error
}

type Session struct {
	ID        string
	UserID    string
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
	IP        string
	UserAgent string
}
