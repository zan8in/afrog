// Package examplepath resolves paths inside the afrog repository for the
// runnable examples.
//
// The examples used to hardcode relative paths such as "../pocs/afrog-pocs",
// which resolve against the caller's working directory and therefore broke
// depending on where `go run` was invoked from. Resolving against this source
// file's location instead makes the examples work from any directory.
package examplepath

import (
	"flag"
	"path/filepath"
	"runtime"
)

// RepoRoot returns the absolute path of the afrog repository root.
func RepoRoot() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	// <root>/examples/internal/examplepath/examplepath.go -> <root>
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
}

// DefaultPocs returns the absolute path of the bundled PoC directory.
func DefaultPocs() string {
	return filepath.Join(RepoRoot(), "pocs", "afrog-pocs")
}

// VulnwebPocs returns the absolute path of the local test-lab PoC directory
// that pairs with examples/vulnweb.
func VulnwebPocs() string {
	return filepath.Join(RepoRoot(), "examples", "vulnweb", "pocs")
}

// PocsFlag registers a -pocs flag defaulting to the bundled PoC directory and
// returns a pointer to its value. Call flag.Parse before dereferencing it.
func PocsFlag() *string {
	return flag.String("pocs", DefaultPocs(), "PoC file, directory or glob pattern")
}
