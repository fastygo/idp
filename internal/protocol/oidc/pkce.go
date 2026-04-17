package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

func verifyPKCE(challenge, method, verifier string) bool {
	switch method {
	case "S256":
		hash := sha256.Sum256([]byte(verifier))
		return hmac.Equal(
			[]byte(base64.RawURLEncoding.EncodeToString(hash[:])),
			[]byte(challenge),
		)
	case "plain":
		return hmac.Equal([]byte(challenge), []byte(verifier))
	default:
		return false
	}
}
