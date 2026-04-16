package authkit

import (
	"errors"
	"io/fs"
	"net/http"

	"idp-cyberos/pkg/core"
)

type ViewConfig struct {
	BrandName string
	BaseURL   string
	Flow      core.FlowConfig
	Features  core.FeatureFlags
	Locales   []string
}

type Renderer interface {
	RenderLogin(w http.ResponseWriter, r *http.Request)
	RenderLogout(w http.ResponseWriter, r *http.Request, returnTo string)
	RenderError(w http.ResponseWriter, r *http.Request, message string, code int)
	StaticFS() fs.FS
}

type renderer struct {
	cfg ViewConfig
}

func New(cfg ViewConfig) Renderer {
	return &renderer{cfg: cfg}
}

func (r *renderer) StaticFS() fs.FS {
	sub, err := fs.Sub(embeddedFS, "static")
	if err != nil {
		panic(err)
	}

	return sub
}

type mergedFS struct {
	parts []fs.FS
}

func MergedFS(parts ...fs.FS) fs.FS {
	return mergedFS{parts: parts}
}

func (m mergedFS) Open(name string) (fs.File, error) {
	for _, part := range m.parts {
		file, err := part.Open(name)
		if err == nil {
			return file, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}

	return nil, fs.ErrNotExist
}
