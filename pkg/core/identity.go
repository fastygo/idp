package core

import "time"

type Identity struct {
	ID            string
	Email         string
	EmailVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Metadata      map[string]string
}
