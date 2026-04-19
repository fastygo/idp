package hanko

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractToken_BearerHeaderWins(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer header-token")
	r.AddCookie(&http.Cookie{Name: "hanko", Value: "cookie-token"})

	if got := ExtractToken(r, "hanko"); got != "header-token" {
		t.Fatalf("got %q", got)
	}
}

func TestExtractToken_FallsBackToCookie(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "hanko", Value: "cookie-token"})

	if got := ExtractToken(r, "hanko"); got != "cookie-token" {
		t.Fatalf("got %q", got)
	}
}

// TestExtractToken_IgnoresQueryString is the hardening regression —
// `?token=` was a common credential-leak vector (URLs hit access logs
// and Referer headers), so we explicitly do NOT accept it any more.
func TestExtractToken_IgnoresQueryString(t *testing.T) {
	r := httptest.NewRequest("GET", "/?token=query-token", nil)

	if got := ExtractToken(r, "hanko"); got != "" {
		t.Fatalf("expected empty, got %q (query-string token must be ignored)", got)
	}
}
