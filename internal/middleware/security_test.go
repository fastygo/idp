package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders_SetsBaselineHeaders(t *testing.T) {
	h := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	want := map[string]string{
		"Strict-Transport-Security":  "max-age=31536000; includeSubDomains",
		"X-Content-Type-Options":     "nosniff",
		"X-Frame-Options":            "DENY",
		"Referrer-Policy":            "strict-origin-when-cross-origin",
		"Cross-Origin-Opener-Policy": "same-origin",
	}
	for k, v := range want {
		if got := rr.Header().Get(k); got != v {
			t.Fatalf("%s = %q, want %q", k, got, v)
		}
	}
	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP missing frame-ancestors 'none': %s", csp)
	}
	if !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("CSP missing strict script-src: %s", csp)
	}
}

func TestMaxBodyBytes_RejectsLarge(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, err := io.ReadAll(r.Body)
		if err == nil {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
		}
	})
	h := MaxBodyBytes(8, inner)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader("this body is much larger than 8 bytes"))
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatal("inner handler must still be invoked so it can write the error")
	}
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
}

func TestMaxBodyBytes_AllowsSmall(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(body)
	})
	h := MaxBodyBytes(64, inner)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader("small"))
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if rr.Body.String() != "small" {
		t.Fatalf("body = %q", rr.Body.String())
	}
}
