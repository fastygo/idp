package authkit

import (
	"embed"
	"io/fs"
)

//go:embed static i18n
var embeddedFS embed.FS

// UIStaticFS returns the embedded "static" sub-tree of the authkit package
// (CSS, JS shipped by the renderer itself). It is exported so that callers
// can build a single merged static manifest together with provider-specific
// assets (e.g. authkit-hanko's vendored UMD bundle) in pkg/authkit/static.go.
func UIStaticFS() fs.FS {
	sub, err := fs.Sub(embeddedFS, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
