package oidc

import (
	"net/http"
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
				_ = h.revoker.Revoke(claims.Jti)
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}
