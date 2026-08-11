package config

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Distinct PoCs that happen to share a filename must all survive: silently
// dropping one would make the user scan less than they asked for, with no
// diagnostic to explain it.
func TestCreatePocList_KeepsSameNamedPocsFromDifferentDirs(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	writePoc(t, dirA, "shared.yaml", "poc-from-dir-a")
	writePoc(t, dirB, "shared.yaml", "poc-from-dir-b")

	opt := &Options{
		PocPaths:     []string{dirA, dirB},
		PocPathsOnly: true,
		SDKMode:      true,
	}

	got := opt.CreatePocList()
	ids := make([]string, 0, len(got))
	for _, p := range got {
		ids = append(ids, p.Id)
	}
	sort.Strings(ids)

	want := []string{"poc-from-dir-a", "poc-from-dir-b"}
	if len(ids) != len(want) {
		t.Fatalf("loaded %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("loaded %v, want %v", ids, want)
		}
	}
}

func TestCreatePocList_ExplicitPathOverridesBuiltinOfSameName(t *testing.T) {
	// A PoC named after a built-in one should replace it rather than run twice.
	dir := t.TempDir()
	writePoc(t, dir, "afrog-demo.yaml", "my-override")

	opt := &Options{PocPaths: []string{dir}, SDKMode: true}
	got := opt.CreatePocList()

	var overrides, builtins int
	for _, p := range got {
		switch p.Id {
		case "my-override":
			overrides++
		case "afrog-demo":
			builtins++
		}
	}
	if overrides != 1 {
		t.Errorf("explicit poc appeared %d times, want 1", overrides)
	}
	if builtins != 0 {
		t.Errorf("built-in poc of the same filename appeared %d times, want 0", builtins)
	}
}

func TestResolvePocInputs_DeduplicatesByAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	p := writePoc(t, dir, "one.yaml", "one")

	// The same file reachable two ways must resolve to a single entry.
	paths, diags := ResolvePocInputs([]string{p, dir, filepath.Join(dir, "*.yaml")})
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if len(paths) != 1 {
		t.Fatalf("resolved %d paths, want 1: %v", len(paths), paths)
	}
}

func TestLoadConfigReadOnly_MissingHomeConfigReturnsDefaults(t *testing.T) {
	cfg, err := LoadConfigReadOnly(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("an explicitly requested missing file should error")
	}
	if cfg != nil {
		t.Fatal("no config should be returned on error")
	}

	// The default path falls back to in-memory defaults without touching disk.
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg, err = LoadConfigReadOnly("")
	if err != nil {
		t.Fatalf("LoadConfigReadOnly: %v", err)
	}
	if cfg == nil || cfg.ServerAddress == "" {
		t.Fatal("expected populated defaults when no config file exists")
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "afrog")); !os.IsNotExist(err) {
		t.Error("LoadConfigReadOnly must not create the config directory")
	}
}
