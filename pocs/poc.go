package pocs

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"github.com/zan8in/afrog/pkg/poc"
	"gopkg.in/yaml.v2"
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
			allPocs = append(allPocs, path)
		}
		return nil
	})

	return allPocs, err
}

func GetPocDetail(pocname string) (string, error) {
	var result string

	err := fs.WalkDir(f, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// fmt.Printf("path=%q, isDir=%v\n", path, d.IsDir())
		if !d.IsDir() && strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			name := d.Name()
			if pocname == name || pocname+".yaml" == name || pocname+".yml" == name {
				result = path
				return nil
			}
		}
		return nil
	})

	if len(result) == 0 {
		return result, fmt.Errorf("result is empty")
	}

	return result, err
}

func ReadPocs(path string) (poc.Poc, error) {
	var poc = poc.Poc{}

	file, err := f.Open(path)
	if err != nil {
		return poc, err
	}
	defer file.Close()

	if err := yaml.NewDecoder(file).Decode(&poc); err != nil {
		return poc, err
	}
	return poc, nil
}
