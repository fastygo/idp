package authkit

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// AssetEntry is a single immutable, pre-compressed file served by the
// fingerprinted static handler.
//
// The entry holds two URL forms for the same payload:
//
//   - LogicalPath is the human-readable path embedded in the source tree
//     (e.g. "js/authkit-hanko.js"). It is what authors reference and what
//     fallback links keep working when a deployment serves a stale HTML
//     page.
//   - FingerprintedPath embeds an 8-character SHA-256 prefix into the
//     filename ("js/authkit-hanko.abcdef12.js") so the URL changes with
//     the bytes. This is what the IdP advertises in <script> tags so
//     the browser/CDN can cache the file with `immutable`.
type AssetEntry struct {
	LogicalPath       string
	FingerprintedPath string
	ContentType       string
	ModTime           time.Time
	SHA256Hex         string
	IntegritySHA384   string
	plain             []byte
	gzipped           []byte
}

// Body returns the raw asset bytes (do not mutate).
func (e *AssetEntry) Body() []byte { return e.plain }

// Gzipped returns the pre-compressed asset, or nil if compression is
// disabled for this file (typically for already-compressed assets such as
// PNG/JPEG/WOFF2).
func (e *AssetEntry) Gzipped() []byte { return e.gzipped }

// AssetManifest indexes embedded static assets by both logical and
// fingerprinted paths.
//
// Look up by logical path is the typical authoring concern; look up by
// fingerprinted path is what the HTTP handler uses to validate incoming
// requests and decide whether to send aggressive cache headers.
type AssetManifest struct {
	byLogical       map[string]*AssetEntry
	byFingerprinted map[string]*AssetEntry
}

// LookupLogical returns the entry for a logical (un-fingerprinted) path.
func (m *AssetManifest) LookupLogical(p string) (*AssetEntry, bool) {
	e, ok := m.byLogical[normalisePath(p)]
	return e, ok
}

// LookupFingerprinted returns the entry for a fingerprinted path.
func (m *AssetManifest) LookupFingerprinted(p string) (*AssetEntry, bool) {
	e, ok := m.byFingerprinted[normalisePath(p)]
	return e, ok
}

// FingerprintedPathFor returns the cache-busting URL for a logical asset
// path. If the asset is unknown, it returns the input unchanged so that
// callers can still hand off to a generic handler.
func (m *AssetManifest) FingerprintedPathFor(p string) string {
	if e, ok := m.LookupLogical(p); ok {
		return "/" + e.FingerprintedPath
	}
	return p
}

// IntegrityFor returns the SRI attribute value (e.g. "sha384-...") for the
// asset at the given logical path, or "" if unknown.
func (m *AssetManifest) IntegrityFor(p string) string {
	if e, ok := m.LookupLogical(p); ok {
		return e.IntegritySHA384
	}
	return ""
}

// BuildManifest walks the given fs.FS, hashes every file and returns an
// AssetManifest that the static handler can use to serve them with
// fingerprinted URLs, immutable caching, gzip, and SRI digests.
//
// Pre-compression is skipped for inputs that would not benefit (small
// files or already-compressed types).
func BuildManifest(srcFS fs.FS) (*AssetManifest, error) {
	m := &AssetManifest{
		byLogical:       map[string]*AssetEntry{},
		byFingerprinted: map[string]*AssetEntry{},
	}

	walkErr := fs.WalkDir(srcFS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		body, readErr := fs.ReadFile(srcFS, p)
		if readErr != nil {
			return readErr
		}

		info, infoErr := d.Info()
		modTime := time.Time{}
		if infoErr == nil {
			modTime = info.ModTime()
		}
		if modTime.IsZero() {
			// embed.FS returns the zero time. Use a fixed epoch so the
			// HTTP handler can emit a deterministic Last-Modified header.
			modTime = time.Unix(0, 0).UTC()
		}

		sum256 := sha256.Sum256(body)
		sum384 := sha512.Sum384(body)

		entry := &AssetEntry{
			LogicalPath:     normalisePath(p),
			ContentType:     detectContentType(p, body),
			ModTime:         modTime,
			SHA256Hex:       hex.EncodeToString(sum256[:]),
			IntegritySHA384: "sha384-" + base64.StdEncoding.EncodeToString(sum384[:]),
			plain:           body,
		}
		entry.FingerprintedPath = injectFingerprint(entry.LogicalPath, entry.SHA256Hex)

		if shouldPrecompress(entry.ContentType, len(body)) {
			gz, gzErr := gzipBytes(body)
			if gzErr == nil && len(gz) < len(body) {
				entry.gzipped = gz
			}
		}

		m.byLogical[entry.LogicalPath] = entry
		m.byFingerprinted[entry.FingerprintedPath] = entry
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	return m, nil
}

// FingerprintedHandler returns an http.Handler that serves files described by
// the manifest. Lookup order:
//
//  1. exact fingerprinted path → served with `Cache-Control: public,
//     max-age=31536000, immutable` and gzip when appropriate.
//  2. exact logical path → served with `Cache-Control: no-cache,
//     must-revalidate` so a stale HTML never pins users to a stale asset.
//  3. otherwise the request is delegated to `fallback` (use this to chain
//     a plain http.FileServerFS for files that were intentionally not put
//     into the manifest — e.g. user uploads).
func FingerprintedHandler(m *AssetManifest, fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		clean := normalisePath(strings.TrimPrefix(r.URL.Path, "/"))

		if e, ok := m.LookupFingerprinted(clean); ok {
			serveAsset(w, r, e, true)
			return
		}
		if e, ok := m.LookupLogical(clean); ok {
			serveAsset(w, r, e, false)
			return
		}
		if fallback != nil {
			fallback.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

func serveAsset(w http.ResponseWriter, r *http.Request, e *AssetEntry, immutable bool) {
	header := w.Header()
	header.Set("Content-Type", e.ContentType)
	header.Set("Vary", "Accept-Encoding")
	header.Set("X-Content-Type-Options", "nosniff")

	if immutable {
		// Fingerprinted URLs can be safely cached forever — bytes change
		// → URL changes.
		header.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		// Logical paths must always be revalidated so stale HTML cannot
		// trap clients on an outdated bundle.
		header.Set("Cache-Control", "public, no-cache, must-revalidate")
		header.Set("ETag", `"`+e.SHA256Hex[:16]+`"`)
		if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, e.SHA256Hex[:16]) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	body := e.plain
	if e.gzipped != nil && acceptsGzip(r) {
		header.Set("Content-Encoding", "gzip")
		body = e.gzipped
	}

	header.Set("Content-Length", lenStr(len(body)))

	if r.Method == http.MethodHead {
		return
	}

	_, _ = w.Write(body)
}

func acceptsGzip(r *http.Request) bool {
	enc := r.Header.Get("Accept-Encoding")
	if enc == "" {
		return false
	}
	for _, part := range strings.Split(enc, ",") {
		token := strings.TrimSpace(part)
		// Ignore q-values for simplicity: a client that lists "gzip"
		// even with q=0 is a pathological case and modern browsers
		// always advertise gzip with q=1.
		if strings.EqualFold(token, "gzip") || strings.HasPrefix(strings.ToLower(token), "gzip;") {
			return true
		}
	}
	return false
}

// shouldPrecompress decides whether it is worth gzipping a payload at
// startup. Tiny files do not benefit; already-compressed media types
// expand under deflate.
func shouldPrecompress(contentType string, size int) bool {
	if size < 256 {
		return false
	}
	switch {
	case strings.HasPrefix(contentType, "text/"):
		return true
	case strings.HasPrefix(contentType, "application/json"):
		return true
	case strings.HasPrefix(contentType, "application/javascript"),
		strings.HasPrefix(contentType, "text/javascript"):
		return true
	case strings.HasPrefix(contentType, "application/xml"),
		strings.HasPrefix(contentType, "image/svg+xml"):
		return true
	case strings.HasPrefix(contentType, "font/") ||
		strings.HasPrefix(contentType, "application/font-"):
		// modern font formats (.woff2, .woff, .otf) are already
		// compressed; skip deflate to avoid expansion.
		return false
	}
	return false
}

func gzipBytes(body []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(body); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func injectFingerprint(p, hashHex string) string {
	const prefixLen = 8
	if len(hashHex) < prefixLen {
		return p
	}
	prefix := hashHex[:prefixLen]
	dir, base := path.Split(p)
	ext := path.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return path.Join(dir, stem+"."+prefix+ext)
}

func detectContentType(p string, body []byte) string {
	if ct := mime.TypeByExtension(filepath.Ext(p)); ct != "" {
		return ct
	}
	return http.DetectContentType(body)
}

func normalisePath(p string) string {
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	p = path.Clean(p)
	if p == "." {
		return ""
	}
	return p
}

func lenStr(n int) string {
	const buf = "0123456789"
	if n == 0 {
		return "0"
	}
	if n < 10 {
		return string(buf[n])
	}
	var b [20]byte
	pos := len(b)
	for n > 0 {
		pos--
		b[pos] = buf[n%10]
		n /= 10
	}
	return string(b[pos:])
}

// Verify a manifest is fully built (used in tests / startup smoke):
// returns an error if any entry is missing critical fields. Exposed for
// embedders that want to fail loud on mis-embedded assets instead of
// shipping a broken bundle.
func (m *AssetManifest) Validate() error {
	if m == nil {
		return errors.New("authkit: nil asset manifest")
	}
	for logical, e := range m.byLogical {
		if e.SHA256Hex == "" || e.IntegritySHA384 == "" || e.FingerprintedPath == "" {
			return errors.New("authkit: incomplete manifest entry: " + logical)
		}
	}
	return nil
}

// Compile-time assertion that gzip.Writer satisfies io.WriteCloser.
var _ io.WriteCloser = (*gzip.Writer)(nil)