package core

import "time"

type AuthCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	Email               string
	Sub                 string
	Nonce               string
	Scope               string
	SID                 string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

type AuthCodeStore interface {
	Save(code *AuthCode) error
	Consume(code string) (*AuthCode, error)
	Cleanup() error
}
