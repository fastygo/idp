// Package middleware bundles the small, dependency-free HTTP middlewares
// shared across the IdP: response-security headers, request-body limits
// and a tiny health-check helper.
//
// Everything here is deliberately stdlib-only so it stays cheap to audit.
package middleware

import "net/http"

// SecurityHeaders sets the baseline production-grade response headers
// every IdP endpoint should emit:
//
//   - HSTS: force the browser onto HTTPS for a year and cover subdomains
//   - X-Content-Type-Options: nosniff
//   - X-Frame-Options: DENY (the IdP must never be framable; the OIDC
//     and SAML responses must not be exposed via clickjacking)
//   - Referrer-Policy: strict-origin-when-cross-origin
//   - Cross-Origin-Opener-Policy: same-origin (browsing-context isolation)
//   - Permissions-Policy: drop the powerful features we never use
//   - Content-Security-Policy: a self-only baseline that still allows the
//     templ-rendered inline JSON config (`<script id="auth-config" …>`).
//     Inline scripts are forbidden — the AuthKit bundle is loaded with
//     SRI from /static/.
//
// CSP is deliberately conservative: unsafe-inline is NOT included for
// scripts (we use external bundles + JSONScript), but the existing
// stylesheet shipped with the templ layout is allowed via 'self'.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		// Browser-side hardening.
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")

		// CSP: scripts from self only (no eval, no inline). Allow data:
		// images for icons embedded by templ. Hanko's frontend SDK runs
		// from the same /static/ origin as the page, so 'self' is enough.
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"base-uri 'self'; "+
				"frame-ancestors 'none'; "+
				"form-action 'self'; "+
				"object-src 'none'; "+
				"img-src 'self' data:; "+
				"font-src 'self' data:; "+
				"style-src 'self' 'unsafe-inline'; "+
				"script-src 'self'; "+
				"connect-src 'self'; "+
				"manifest-src 'self'")

		next.ServeHTTP(w, r)
	})
}

// MaxBodyBytes wraps next so r.Body is capped at maxBytes. Anything
// larger is rejected with a 413. Use it for POST endpoints whose payload
// shape is bounded (token, revoke, introspect, end_session) — keeping
// these tight stops a hostile client from streaming an unbounded body
// just to tie up a goroutine.
func MaxBodyBytes(maxBytes int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r)
	})
}

// MaxBodyBytesFunc is the http.HandlerFunc-friendly variant of
// MaxBodyBytes.
func MaxBodyBytesFunc(maxBytes int64, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next(w, r)
	}
}
