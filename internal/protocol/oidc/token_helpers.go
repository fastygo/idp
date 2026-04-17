package oidc

import (
	"errors"
	"net/http"
	"time"

	"idp-cyberos/internal/config"
)

func (h *Handlers) authenticateClient(r *http.Request) (*config.OIDCClient, string, bool) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	client := h.cfg.FindOIDCClient(clientID)
	if client == nil {
		return nil, "", false
	}
	if !secureCompare(client.ClientSecret, clientSecret) {
		return nil, "", false
	}
	return client, clientID, true
}

func (h *Handlers) verifyAccessToken(tokenStr string) (*AccessTokenClaims, error) {
	var claims AccessTokenClaims
	if err := VerifySignedClaims(tokenStr, &h.kp.PrivateKey.PublicKey, &claims); err != nil {
		return nil, err
	}

	active, err := h.isAccessTokenActive(&claims)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, errors.New("inactive token")
	}
	return &claims, nil
}

func (h *Handlers) isAccessTokenActive(claims *AccessTokenClaims) (bool, error) {
	if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
		return false, nil
	}

	if h.revoker != nil && claims.Jti != "" {
		revoked, err := h.revoker.IsRevoked(claims.Jti)
		if err != nil {
			return false, err
		}
		if revoked {
			return false, nil
		}
	}

	if h.sessionStore != nil && claims.Sid != "" {
		rec, err := h.sessionStore.Lookup(claims.Sid)
		if err != nil {
			return false, err
		}
		if rec == nil {
			return false, nil
		}
	}

	return true, nil
}
