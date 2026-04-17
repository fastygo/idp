package authkit

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func newTestFS(t *testing.T) (*AssetManifest, []byte) {
	t.Helper()

	jsBody := []byte(strings.Repeat("// authkit hanko bundle\nconsole.log('hi');\n", 80))
	cssBody := []byte("body{background:#000}\n" + strings.Repeat("/*pad*/", 100))
	pngBody := []byte("\x89PNG\r\n\x1a\n" + strings.Repeat("\x00", 1024))

	srcFS := fstest.MapFS{
		"js/authkit-hanko.js": &fstest.MapFile{Data: jsBody},
		"css/login.css":       &fstest.MapFile{Data: cssBody},
		"img/icon.png":        &fstest.MapFile{Data: pngBody},
	}

	m, err := BuildManifest(srcFS)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("manifest invalid: %v", err)
	}
	return m, jsBody
}

func TestBuildManifestProducesFingerprintAndIntegrity(t *testing.T) {
	m, jsBody := newTestFS(t)

	entry, ok := m.LookupLogical("js/authkit-hanko.js")
	if !ok {
		t.Fatal("expected logical entry for js/authkit-hanko.js")
	}
	if entry.FingerprintedPath == entry.LogicalPath {
		t.Fatalf("expected fingerprinted path to differ from logical, got %q", entry.LogicalPath)
	}
	if !strings.HasPrefix(entry.IntegritySHA384, "sha384-") {
		t.Fatalf("expected sha384- prefix, got %q", entry.IntegritySHA384)
	}

	expected := sha256.Sum256(jsBody)
	if entry.SHA256Hex != hex.EncodeToString(expected[:]) {
		t.Fatalf("sha256 mismatch")
	}

	if _, ok := m.LookupFingerprinted(entry.FingerprintedPath); !ok {
		t.Fatalf("fingerprinted lookup failed for %q", entry.FingerprintedPath)
	}
}

func TestFingerprintedHandlerCachesImmutableAndGzips(t *testing.T) {
	m, jsBody := newTestFS(t)
	entry, _ := m.LookupLogical("js/authkit-hanko.js")
	h := FingerprintedHandler(m, http.NotFoundHandler())

	req := httptest.NewRequest(http.MethodGet, "/"+entry.FingerprintedPath, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d", res.StatusCode)
	}
	if got := res.Header.Get("Cache-Control"); !strings.Contains(got, "immutable") || !strings.Contains(got, "max-age=31536000") {
		t.Fatalf("expected immutable cache-control, got %q", got)
	}
	if res.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected gzip encoding, got %q", res.Header.Get("Content-Encoding"))
	}
	if res.Header.Get("Vary") != "Accept-Encoding" {
		t.Fatalf("expected Vary header")
	}

	gzr, err := gzip.NewReader(res.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	decoded, _ := io.ReadAll(gzr)
	if !bytes.Equal(decoded, jsBody) {
		t.Fatalf("decoded body differs from source")
	}
}

func TestFingerprintedHandlerLogicalPathRevalidates(t *testing.T) {
	m, _ := newTestFS(t)
	h := FingerprintedHandler(m, http.NotFoundHandler())

	req := httptest.NewRequest(http.MethodGet, "/js/authkit-hanko.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d", res.StatusCode)
	}
	cc := res.Header.Get("Cache-Control")
	if !strings.Contains(cc, "no-cache") || !strings.Contains(cc, "must-revalidate") {
		t.Fatalf("expected revalidation cache-control, got %q", cc)
	}
	if res.Header.Get("ETag") == "" {
		t.Fatalf("expected ETag for logical path")
	}
}

func TestFingerprintedHandlerHonorsIfNoneMatch(t *testing.T) {
	m, _ := newTestFS(t)
	entry, _ := m.LookupLogical("js/authkit-hanko.js")
	h := FingerprintedHandler(m, http.NotFoundHandler())

	req := httptest.NewRequest(http.MethodGet, "/js/authkit-hanko.js", nil)
	req.Header.Set("If-None-Match", `"`+entry.SHA256Hex[:16]+`"`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotModified {
		t.Fatalf("expected 304, got %d", rec.Code)
	}
}

func TestFingerprintedHandlerSkipsGzipForBinaryAssets(t *testing.T) {
	m, _ := newTestFS(t)
	entry, ok := m.LookupLogical("img/icon.png")
	if !ok {
		t.Fatal("expected png entry")
	}
	if entry.Gzipped() != nil {
		t.Fatalf("expected png to skip pre-compression")
	}
}

func TestFingerprintedHandlerFallsBack(t *testing.T) {
	m, _ := newTestFS(t)
	called := false
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	})
	h := FingerprintedHandler(m, fallback)

	req := httptest.NewRequest(http.MethodGet, "/missing.txt", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected fallback to be called")
	}
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status: want 418, got %d", rec.Code)
	}
}

func TestAcceptsGzip(t *testing.T) {
	cases := []struct {
		header string
		want   bool
	}{
		{"", false},
		{"gzip", true},
		{"identity", false},
		{"gzip, deflate, br", true},
		{"deflate, gzip;q=0.5", true},
		{"br", false},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if tc.header != "" {
			req.Header.Set("Accept-Encoding", tc.header)
		}
		if got := acceptsGzip(req); got != tc.want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", tc.header, got, tc.want)
		}
	}
}

func TestIntegrityFor(t *testing.T) {
	m, _ := newTestFS(t)
	got := m.IntegrityFor("js/authkit-hanko.js")
	if !strings.HasPrefix(got, "sha384-") {
		t.Fatalf("expected sha384- prefix, got %q", got)
	}
	if got := m.IntegrityFor("nope"); got != "" {
		t.Fatalf("expected empty integrity for unknown path, got %q", got)
	}
}
