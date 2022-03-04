package catalog

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// ResolvePath resolves the path to an absolute one in various ways.
//
// It checks if the filename is an absolute path, looks in the current directory
// or checking the nuclei pocs directory. If a second path is given,
// it also tries to find paths relative to that second path.
func (c *Catalog) ResolvePath(pocName, second string) (string, error) {
	if filepath.IsAbs(pocName) {
		return pocName, nil
	}
	if second != "" {
		secondBasePath := filepath.Join(filepath.Dir(second), pocName)
		if potentialPath, err := c.tryResolve(secondBasePath); err != errNoValidCombination {
			return potentialPath, nil
		}
	}

	curDirectory, err := os.Getwd()
	if err != nil {
		return "", err
	}

	pocPath := filepath.Join(curDirectory, pocName)
	if potentialPath, err := c.tryResolve(pocPath); err != errNoValidCombination {
		return potentialPath, nil
	}

	if c.pocsDirectory != "" {
		pocPath := filepath.Join(c.pocsDirectory, pocName)
		if potentialPath, err := c.tryResolve(pocPath); err != errNoValidCombination {
			return potentialPath, nil
		}
	}
	return "", fmt.Errorf("no such path found: %s", pocName)
}

var errNoValidCombination = errors.New("no valid combination found")

// tryResolve attempts to load locate the target by iterating across all the folders tree
func (c *Catalog) tryResolve(fullPath string) (string, error) {
	dir, filename := filepath.Split(fullPath)
	pathInfo, err := NewPathInfo(dir)
	if err != nil {
		return "", err
	}
	pathInfoItems, err := pathInfo.MeshWith(filename)
	if err != nil {
		return "", err
	}
	for _, pathInfoItem := range pathInfoItems {
		if _, err := os.Stat(pathInfoItem); !os.IsNotExist(err) {
			return pathInfoItem, nil
		}
	}

	return "", errNoValidCombination
}
