package hanko

import (
	"net/http"
	"strings"
)

func ExtractToken(r *http.Request, cookieName string) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	if cookie, err := r.Cookie(cookieName); err == nil {
		return cookie.Value
	}
	if token := r.URL.Query().Get("token"); token != "" {
		return token
	}
	return ""
}
