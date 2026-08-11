package config

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// writePoc creates a minimal valid PoC file and returns its path.
func writePoc(t *testing.T, dir, name, id string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	body := "id: " + id + `
info:
  name: ` + id + `
  author: test
  severity: info
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.status == 200
expression: r0()
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write poc %s: %v", path, err)
	}
	return path
}

func pocIDs(pocs []struct{ ID string }) []string {
	out := make([]string, 0, len(pocs))
	for _, p := range pocs {
		out = append(out, p.ID)
	}
	sort.Strings(out)
	return out
}

func TestResolvePocInputs(t *testing.T) {
	dir := t.TempDir()
	single := writePoc(t, dir, "single.yaml", "single")
	writePoc(t, dir, "second.yml", "second")

	nested := filepath.Join(dir, "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writePoc(t, nested, "deep.yaml", "deep")

	tests := []struct {
		name      string
		inputs    []string
		wantCount int
		wantDiags int
	}{
		{name: "single file", inputs: []string{single}, wantCount: 1},
		{name: "directory is walked recursively", inputs: []string{dir}, wantCount: 3},
		{name: "glob pattern", inputs: []string{filepath.Join(dir, "*.yaml")}, wantCount: 1},
		{name: "glob matches both extensions", inputs: []string{filepath.Join(dir, "*.y*ml")}, wantCount: 2},
		{name: "duplicates are removed", inputs: []string{single, single}, wantCount: 1},
		{name: "missing path is reported", inputs: []string{filepath.Join(dir, "nope.yaml")}, wantCount: 0, wantDiags: 1},
		{name: "empty input is ignored", inputs: []string{"  "}, wantCount: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, diags := ResolvePocInputs(tt.inputs)
			if len(got) != tt.wantCount {
				t.Errorf("resolved %d paths, want %d (%v)", len(got), tt.wantCount, got)
			}
			if len(diags) != tt.wantDiags {
				t.Errorf("got %d diagnostics, want %d (%v)", len(diags), tt.wantDiags, diags)
			}
		})
	}
}

func TestValidatePocInputs(t *testing.T) {
	dir := t.TempDir()
	writePoc(t, dir, "a.yaml", "a")

	tests := []struct {
		name    string
		inputs  []string
		wantErr bool
	}{
		{name: "no input is valid", inputs: nil},
		{name: "existing directory", inputs: []string{dir}},
		{name: "glob that matches", inputs: []string{filepath.Join(dir, "*.yaml")}},
		{name: "glob that matches nothing", inputs: []string{filepath.Join(dir, "*.json")}, wantErr: true},
		{name: "missing path", inputs: []string{filepath.Join(dir, "missing")}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePocInputs(tt.inputs)
			if tt.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// AppendPoc used to be silently dropped whenever PocFile was set.
func TestCreatePocList_MergesPocFileAndAppendPoc(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	fromPocFile := writePoc(t, dirA, "a.yaml", "from-pocfile")
	writePoc(t, dirB, "b.yaml", "from-appendpoc")

	opt := &Options{
		PocFile:   fromPocFile,
		AppendPoc: []string{dirB},
		SDKMode:   true,
	}

	got := opt.CreatePocList()
	ids := make([]string, 0, len(got))
	for _, p := range got {
		ids = append(ids, p.Id)
	}
	sort.Strings(ids)

	want := []string{"from-appendpoc", "from-pocfile"}
	if len(ids) != len(want) {
		t.Fatalf("loaded %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("loaded %v, want %v", ids, want)
		}
	}
}

func TestCreatePocList_PocPathsSupportsGlob(t *testing.T) {
	dir := t.TempDir()
	writePoc(t, dir, "one.yaml", "one")
	writePoc(t, dir, "two.yaml", "two")
	writePoc(t, dir, "skip.txt", "skip")

	opt := &Options{
		PocPaths:     []string{filepath.Join(dir, "*.yaml")},
		PocPathsOnly: true,
		SDKMode:      true,
	}

	got := opt.CreatePocList()
	if len(got) != 2 {
		ids := make([]string, 0, len(got))
		for _, p := range got {
			ids = append(ids, p.Id)
		}
		t.Fatalf("loaded %d pocs %v, want 2", len(got), ids)
	}
}

func TestCreatePocListWithDiagnostics_ReportsSkippedPocs(t *testing.T) {
	dir := t.TempDir()
	writePoc(t, dir, "good.yaml", "good")

	// Legacy v2 OOB syntax is skipped; the caller should be able to find out why.
	legacy := filepath.Join(dir, "legacy.yaml")
	legacyBody := `id: legacy-oob
info:
  name: legacy
  author: test
  severity: info
set:
  oob: oob()
rules:
  r0:
    request:
      method: GET
      path: /?x={{oobDNS}}
    expression: oobCheck(oob, 5)
expression: r0()
`
	if err := os.WriteFile(legacy, []byte(legacyBody), 0o644); err != nil {
		t.Fatalf("write legacy poc: %v", err)
	}

	opt := &Options{PocPaths: []string{dir}, PocPathsOnly: true, SDKMode: true}
	pocs, diags := opt.CreatePocListWithDiagnostics()

	if len(pocs) != 1 || pocs[0].Id != "good" {
		t.Fatalf("expected only the valid poc, got %d", len(pocs))
	}

	var found bool
	for _, d := range diags {
		if d.Reason == PocLoadLegacyOOB {
			found = true
			if d.Detail == "" {
				t.Error("legacy diagnostic should explain which syntax was matched")
			}
		}
	}
	if !found {
		t.Fatalf("expected a %s diagnostic, got %v", PocLoadLegacyOOB, diags)
	}
}

func TestPocLoadError_UnwrapsUnderlyingError(t *testing.T) {
	sentinel := errors.New("boom")
	err := PocLoadError{Path: "/tmp/x.yaml", Reason: PocLoadReadFailed, Err: sentinel}

	if !errors.Is(err, sentinel) {
		t.Fatal("PocLoadError should unwrap to the underlying error")
	}
	if err.Error() == "" {
		t.Fatal("PocLoadError should render a message")
	}
}

func TestLoadConfigReadOnly_DoesNotWriteAnything(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "afrog-config.yaml")

	// Missing file must not be created.
	if _, err := LoadConfigReadOnly(path); err == nil {
		t.Fatal("expected an error for an explicitly requested missing config file")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("LoadConfigReadOnly must not create the config file")
	}

	// Existing file must be read back without being rewritten.
	if err := os.WriteFile(path, []byte("server: \":9999\"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	cfg, err := LoadConfigReadOnly(path)
	if err != nil {
		t.Fatalf("LoadConfigReadOnly: %v", err)
	}
	if cfg.ServerAddress != ":9999" {
		t.Errorf("ServerAddress = %q, want \":9999\"", cfg.ServerAddress)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("re-read config: %v", err)
	}
	if string(before) != string(after) {
		t.Error("LoadConfigReadOnly must not rewrite an existing config file")
	}
}
