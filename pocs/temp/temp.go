package temp

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"
)

//go:embed afrog-pocs
var f embed.FS

func PrintPocs() ([]string, error) {
	allPocs := []string{}

	err := fs.WalkDir(f, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// fmt.Printf("path=%q, isDir=%v\n", path, d.IsDir())
		if !d.IsDir() && strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			fmt.Println(d.Name())
			allPocs = append(allPocs, d.Name())
		}
		return nil
	})

	return allPocs, err
}
