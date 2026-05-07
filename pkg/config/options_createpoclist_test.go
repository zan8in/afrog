package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreatePocList_AssignsFallbackIDFromFilename(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "missing-id.yaml")
	raw := `
info:
  name: missing-id
  author: test
  severity: info
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.status == 200
`
	if err := os.WriteFile(p, []byte(raw), 0o644); err != nil {
		t.Fatalf("write poc: %v", err)
	}

	opt := &Options{PocFile: p}
	got := opt.CreatePocList()
	if len(got) != 1 {
		t.Fatalf("expected 1 poc, got %d", len(got))
	}
	if got[0].Id != "missing-id" {
		t.Fatalf("expected fallback id missing-id, got %q", got[0].Id)
	}
}
