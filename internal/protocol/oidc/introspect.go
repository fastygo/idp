package oidc

import (
	"encoding/json"
	"net/http"
)

func (h *Handlers) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
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
	if err := VerifySignedClaims(token, &h.kp.PrivateKey.PublicKey, &claims); err != nil {
		writeIntrospectionResponse(w, map[string]any{"active": false})
		return
	}

	active, err := h.isAccessTokenActive(&claims)
	if err != nil || !active {
		writeIntrospectionResponse(w, map[string]any{"active": false})
		return
	}

	if claims.Aud != "" && claims.Aud != clientID {
		writeIntrospectionResponse(w, map[string]any{
			"active": true,
			"exp":    claims.Exp,
			"iss":    claims.Iss,
		})
		return
	}

	writeIntrospectionResponse(w, map[string]any{
		"active":     true,
		"scope":      claims.Scope,
		"client_id":  claims.ClientID,
		"username":   claims.Email,
		"token_type": "Bearer",
		"exp":        claims.Exp,
		"iat":        claims.Iat,
		"sub":        claims.Sub,
		"iss":        claims.Iss,
		"jti":        claims.Jti,
	})
}

func writeIntrospectionResponse(w http.ResponseWriter, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(payload)
}
