package pocs

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/poc"
	"gopkg.in/yaml.v2"
)

//go:embed afrog-pocs/*
var f embed.FS
var EmbedFileList []string

func init() {
	EmbedFileList, _ = EmbedFile()
	// 设置embed poc查找函数
	poc.SetEmbedPocFinder(EmbedReadContentByName)
}

func EmbedFile() ([]string, error) {
	files := []string{}

	err := fs.WalkDir(f, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

// read poc content by name
func EmbedReadContentByName(name string) ([]byte, error) {
	var (
		err    error
		result []byte
	)

	if len(EmbedFileList) == 0 {
		return nil, fmt.Errorf("embed file list is empty")
	}

	for _, file := range EmbedFileList {
		lastSlashIndex := strings.LastIndex(file, "/")
		if lastSlashIndex != -1 {
			fname := file[lastSlashIndex+1:]
			if name == fname || name+".yaml" == fname || name+".yml" == fname {
				// fmt.Println(fname)
				return f.ReadFile(file)
			}
		}
	}

	return result, err
}

// read poc struct by path
func EmbedReadPocByPath(path string) (poc.Poc, error) {
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

// 仅解析嵌入 POC 的元数据（不解析 rules）
func EmbedReadPocMetaByPath(path string) (poc.PocMeta, error) {
	var pm poc.PocMeta

	file, err := f.Open(path)
	if err != nil {
		return pm, err
	}
	defer file.Close()

	if err := yaml.NewDecoder(file).Decode(&pm); err != nil {
		return pm, err
	}
	return pm, nil
}
