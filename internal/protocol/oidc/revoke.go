package oidc

import (
	"net/http"
	"time"

	"idp-cyberos/pkg/core"
)

func (h *Handlers) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	_, clientID, ok := h.authenticateClient(r)
	if !ok {
		tokenError(w, "invalid_client", "bad credentials")
		return
	}

	token := r.FormValue("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	var claims AccessTokenClaims
	if err := VerifySignedClaims(token, &h.kp.PrivateKey.PublicKey, &claims); err == nil {
		if claims.ClientID == "" || claims.ClientID == clientID {
			if h.revoker != nil {
				// Pin the deny-list entry to the token's natural expiry
				// when the revoker supports it: that lets the periodic
				// Cleanup() free entries as soon as signature/exp checks
				// alone reject the token, and prevents the revoker map
				// from growing forever (a real-world Go memory leak).
				if exp, ok := h.revoker.(core.TokenRevokerWithExpiry); ok && claims.Exp > 0 {
					_ = exp.RevokeUntil(claims.Jti, time.Unix(claims.Exp, 0))
				} else {
					_ = h.revoker.Revoke(claims.Jti)
				}
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}
