package pocs

import (
	"embed"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/zan8in/afrog/pkg/catalog"
)

//go:embed afrog-pocs/*
var f embed.FS

func GetPocs() ([]string, error) {
	c := catalog.New("")
	allTargets := []string{}
	err := fs.WalkDir(f, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// fmt.Printf("path=%q, isDir=%v\n", path, d.IsDir())
		if !d.IsDir() && strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			file := filepath.Base(path)
			absPath, err := c.ResolvePath(filepath.Dir(path), "")
			if err != nil {
				return err
			}
			allTargets = append(allTargets, filepath.Join(absPath, file))
		}
		return nil
	})
	return allTargets, err
}
