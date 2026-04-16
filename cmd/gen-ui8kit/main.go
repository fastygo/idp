//go:generate go run .

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	ui8kitjs "github.com/fastygo/ui8kit/js"
)

var bundleOrder = []string{
	"core.js",
	"theme.js",
	"dialog.js",
	"accordion.js",
	"tabs.js",
	"combobox.js",
	"tooltip.js",
	"alert.js",
	"locale.js",
}

func main() {
	var buf bytes.Buffer
	for i, name := range bundleOrder {
		data, err := ui8kitjs.FS.ReadFile(name)
		if err != nil {
			panic(fmt.Errorf("read %s: %w", name, err))
		}
		buf.Write(data)
		if i < len(bundleOrder)-1 && len(data) > 0 && data[len(data)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}

	root := "."
	if _, err := os.Stat("go.mod"); err != nil {
		root = filepath.Join("..", "..")
	}

	target := filepath.Join(root, "pkg", "authkit", "static", "js", "ui8kit.js")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		panic(fmt.Errorf("mkdir target dir: %w", err))
	}
	if err := os.WriteFile(target, buf.Bytes(), 0o644); err != nil {
		panic(fmt.Errorf("write bundle: %w", err))
	}
}
