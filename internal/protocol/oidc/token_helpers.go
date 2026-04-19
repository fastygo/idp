package oidc

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
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

	// Defence in depth: even though the token is signed by us, refuse it if
	// the iss claim does not match the issuer we are currently configured
	// for. This prevents an attacker who somehow ferrets out an old token
	// (e.g. from a previous BaseURL value during a re-deploy) from using it
	// against a re-keyed/re-named IdP.
	expectedIss := strings.TrimRight(h.cfg.BaseURL, "/")
	if claims.Iss != "" && expectedIss != "" && claims.Iss != expectedIss {
		return nil, fmt.Errorf("issuer mismatch: token=%q expected=%q", claims.Iss, expectedIss)
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
