package pocs

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

//go:embed afrog-pocs/*
var f embed.FS

func GetPocs() ([]string, error) {
	allPocs := []string{}
	err := fs.WalkDir(f, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// fmt.Printf("path=%q, isDir=%v\n", path, d.IsDir())
		if !d.IsDir() && strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			file := filepath.Base(path)
			absPath, err := resolvePath(filepath.Dir(path))
			if err != nil {
				return err
			}
			allPocs = append(allPocs, filepath.Join(absPath, file))
		}
		return nil
	})
	return allPocs, err
}

func resolvePath(pocName string) (string, error) {
	if filepath.IsAbs(pocName) {
		return pocName, nil
	}

	curDirectory, err := os.Getwd()
	if err != nil {
		return "", err
	}

	pocPath := filepath.Join(curDirectory, "pocs", pocName)
	if len(pocPath) > 0 {
		return pocPath, nil
	}

	return "", fmt.Errorf("no such path found: %s", pocName)
}
