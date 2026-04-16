package core

import "time"

type Session struct {
	ID        string
	UserID    string
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
	IP        string
	UserAgent string
}
