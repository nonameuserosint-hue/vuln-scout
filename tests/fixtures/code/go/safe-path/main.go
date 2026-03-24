package main

import (
	"os"
	"path/filepath"
	"strings"
)

func openUpload(root string, name string) (*os.File, error) {
	candidate := filepath.Join(root, filepath.Base(name))
	resolved := filepath.Clean(candidate)
	if !strings.HasPrefix(resolved, filepath.Clean(root)) {
		return nil, os.ErrPermission
	}
	return os.Open(resolved)
}
