package hanko

import (
	"net/http"
	"strings"
)

// ExtractToken returns the Hanko-issued JWT for the request.
//
// Accepted carriers (in priority order):
//   - Authorization: Bearer <jwt>
//   - <cookieName> cookie
//
// The previous `?token=<jwt>` query-string path was deliberately removed:
// query strings get logged by every reverse proxy and access log along the
// way and routinely show up in Referer headers, search-engine indexes,
// and shared shell histories — exactly the kind of credential leakage we
// want to prevent. If integrators need a query-string carrier they should
// build it explicitly at the integration layer.
func ExtractToken(r *http.Request, cookieName string) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	if cookie, err := r.Cookie(cookieName); err == nil {
		return cookie.Value
	}
	return ""
}
