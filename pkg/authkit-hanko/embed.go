package hanko

import (
	"embed"
	"io/fs"
)

//go:embed static
var embeddedFS embed.FS

func (v *Verifier) StaticFS() fs.FS {
	sub, err := fs.Sub(embeddedFS, "static")
	if err != nil {
		panic(err)
	}

	return sub
}
