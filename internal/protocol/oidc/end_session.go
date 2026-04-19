package oidc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"idp-cyberos/internal/auth"
	"idp-cyberos/internal/config"
	"idp-cyberos/pkg/core"
)

type frontChannelLogoutPageData struct {
	ReturnTo string
	Targets  []string
}

var frontChannelLogoutPage = template.Must(template.New("frontchannel-logout").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Signing out</title>
</head>
<body>
  {{range .Targets}}<iframe src="{{.}}" hidden loading="eager"></iframe>{{end}}
  <script>
    window.setTimeout(function () {
      window.location.replace({{printf "%q" .ReturnTo}});
    }, 1200);
  </script>
</body>
</html>`))

func (h *Handlers) HandleEndSession(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
	}

	clientID := logoutParam(r, "client_id")
	postLogoutRedirectURI := logoutParam(r, "post_logout_redirect_uri")
	state := logoutParam(r, "state")
	idTokenHint := logoutParam(r, "id_token_hint")

	sid := ""
	sub := ""
	if idTokenHint != "" {
		var claims idTokenClaims
		if err := VerifySignedClaims(idTokenHint, &h.kp.PrivateKey.PublicKey, &claims); err != nil {
			http.Error(w, "invalid id_token_hint", http.StatusBadRequest)
			return
		}
		if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
			http.Error(w, "expired id_token_hint", http.StatusBadRequest)
			return
		}
		if clientID == "" {
			clientID = claims.Aud
		}
		sid = claims.Sid
		sub = claims.Sub
	}

	if sess := auth.GetSession(r, h.cfg.SessionKey); sess != nil {
		if sid == "" {
			sid = sess.SID
		}
		if sub == "" {
			sub = sess.Sub
		}
	}

	redirectURI := h.cfg.DefaultLogoutReturnURL()
	allowState := false
	if postLogoutRedirectURI != "" && clientID != "" {
		client := h.cfg.FindOIDCClient(clientID)
		if client != nil && client.ValidPostLogoutRedirectURI(postLogoutRedirectURI) {
			redirectURI = postLogoutRedirectURI
			allowState = true
		}
	}
	if allowState && state != "" {
		redirectURI = appendStateParam(redirectURI, state)
	}

	targets, err := h.performLogout(w, sid, sub)
	if err != nil {
		http.Error(w, "logout failed", http.StatusInternalServerError)
		return
	}

	if len(targets) == 0 {
		http.Redirect(w, r, redirectURI, http.StatusFound)
		return
	}

	var buf bytes.Buffer
	if err := frontChannelLogoutPage.Execute(&buf, frontChannelLogoutPageData{
		ReturnTo: redirectURI,
		Targets:  targets,
	}); err != nil {
		http.Error(w, "logout page render failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func (h *Handlers) HandleBrowserLogout(w http.ResponseWriter, r *http.Request) error {
	sid := ""
	sub := ""
	if sess := auth.GetSession(r, h.cfg.SessionKey); sess != nil {
		sid = sess.SID
		sub = sess.Sub
	}

	_, err := h.performLogout(w, sid, sub)
	return err
}

func (h *Handlers) performLogout(w http.ResponseWriter, sid, sub string) ([]string, error) {
	auth.ClearSession(w)
	auth.ClearPendingRequest(w)
	auth.ClearOIDCPendingRequest(w)

	records, err := h.lookupLogoutRecords(sid, sub)
	if err != nil || len(records) == 0 {
		return nil, err
	}

	targets := make([]string, 0, len(records))
	seenTargets := make(map[string]struct{})
	for _, record := range records {
		for _, clientID := range record.Clients {
			client := h.cfg.FindOIDCClient(clientID)
			if client == nil {
				continue
			}

			if frontURL := buildFrontChannelLogoutURL(client, h.cfg.BaseURL, record.SID); frontURL != "" {
				if _, ok := seenTargets[frontURL]; !ok {
					targets = append(targets, frontURL)
					seenTargets[frontURL] = struct{}{}
				}
			}

			if client.BackChannelLogoutURI != "" {
				if h.bgWG != nil {
					h.bgWG.Add(1)
				}
				// Use the lifecycle-bound bgCtx so a graceful shutdown
				// can cancel in-flight back-channel logout calls. The
				// previous code used context.Background() and let the
				// goroutine outlive the process — a small but real
				// goroutine-leak vector flagged in 2025/2026 audits of
				// fire-and-forget patterns in Go.
				go func(c *config.OIDCClient, sub, sid string) {
					defer func() {
						if h.bgWG != nil {
							h.bgWG.Done()
						}
					}()
					h.sendBackChannelLogout(h.bgCtx, c, sub, sid)
				}(client, record.Sub, record.SID)
			}
		}

		if h.sessionStore != nil {
			_ = h.sessionStore.Revoke(record.SID)
		}
	}

	return targets, nil
}

func (h *Handlers) lookupLogoutRecords(sid, sub string) ([]*core.SessionRecord, error) {
	if h.sessionStore == nil {
		return nil, nil
	}

	if sid != "" {
		rec, err := h.sessionStore.Lookup(sid)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			return []*core.SessionRecord{rec}, nil
		}
	}

	if sub == "" {
		return nil, nil
	}
	return h.sessionStore.LookupBySub(sub)
}

// backchannelLogoutClient is a process-wide client tuned for short
// fire-and-forget POSTs. Reusing a single transport prevents the goroutine
// pool from creating fresh connections on every logout — under load this
// also avoided a noticeable goroutine pile-up because http.DefaultClient
// has no per-call timeout.
var backchannelLogoutClient = &http.Client{
	Timeout: 10 * time.Second,
}

func (h *Handlers) sendBackChannelLogout(ctx context.Context, client *config.OIDCClient, sub, sid string) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	logoutToken, err := GenerateLogoutToken(h.kp, h.cfg.BaseURL, client.ClientID, sub, sid)
	if err != nil {
		log.Printf("OIDC back-channel logout token generation error for %s: %v", client.ClientID, err)
		return
	}

	form := url.Values{}
	form.Set("logout_token", logoutToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.BackChannelLogoutURI, bytes.NewBufferString(form.Encode()))
	if err != nil {
		log.Printf("OIDC back-channel logout request build error for %s: %v", client.ClientID, err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := backchannelLogoutClient.Do(req)
	if err != nil {
		log.Printf("OIDC back-channel logout request failed for %s (sid_hash=%s): %v", client.ClientID, hashForLog(sid), err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		log.Printf("OIDC back-channel logout non-success for %s (sid_hash=%s): %s", client.ClientID, hashForLog(sid), resp.Status)
	}
}

// hashForLog returns a short, non-reversible identifier for log lines so
// we can correlate logout / failure entries without leaking the raw
// session id (which is treated as a credential).
func hashForLog(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

func buildFrontChannelLogoutURL(client *config.OIDCClient, issuer, sid string) string {
	if client.FrontChannelLogoutURI == "" {
		return ""
	}

	u, err := url.Parse(client.FrontChannelLogoutURI)
	if err != nil {
		return ""
	}

	q := u.Query()
	q.Set("iss", strings.TrimRight(issuer, "/"))
	if client.FrontChannelLogoutSession && sid != "" {
		q.Set("sid", sid)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func appendStateParam(raw, state string) string {
	if raw == "" || state == "" {
		return raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}

func logoutParam(r *http.Request, name string) string {
	if r.Method == http.MethodPost {
		if value := r.FormValue(name); value != "" {
			return value
		}
	}
	return r.URL.Query().Get(name)
}
