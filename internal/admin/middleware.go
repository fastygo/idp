package admin

import (
	"net/http"

	"idp-cyberos/internal/auth"
	"idp-cyberos/internal/config"
)

func AdminOnly(cfg *config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := auth.GetSession(r, cfg.SessionKey)
		if sess == nil {
			http.Redirect(w, r, "/sso?admin=1", http.StatusFound)
			return
		}

		if !cfg.IsAdmin(sess.Email) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
