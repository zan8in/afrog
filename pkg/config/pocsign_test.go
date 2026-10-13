package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/pocsign"
)

// writeJSPoc creates a minimal javascript PoC (capability >= Network).
func writeJSPoc(t *testing.T, dir, name, id string) string {
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
      type: javascript
      code: |
        var net = require("afrog/net");
        Export("ok");
    expression: response.raw.bcontains(b"ok")
expression: r0()
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write js poc %s: %v", path, err)
	}
	return path
}

func countReason(diags []PocLoadError, reason string) int {
	n := 0
	for _, d := range diags {
		if d.Reason == reason {
			n++
		}
	}
	return n
}

func TestLoaderRequireSignedJSPoc(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	pocPath := writeJSPoc(t, dir, "js.yaml", "js-demo")

	// 宽松模式（默认）：未签名也照常加载。
	opt := &Options{PocPaths: []string{dir}, PocPathsOnly: true, SDKMode: true, EnableJSPoc: true}
	loaded, diags := opt.CreatePocListWithDiagnostics()
	if len(loaded) != 1 {
		t.Fatalf("lenient mode should load the unsigned JS poc, got %d (diags=%v)", len(loaded), diags)
	}

	// 严格模式：未签名一律跳过，并给出机器可读原因。
	optStrict := &Options{PocPaths: []string{dir}, PocPathsOnly: true, SDKMode: true, EnableJSPoc: true, RequireSignedJSPoc: true}
	loaded, diags = optStrict.CreatePocListWithDiagnostics()
	if len(loaded) != 0 {
		t.Fatalf("strict mode should skip the unsigned JS poc, got %d", len(loaded))
	}
	if countReason(diags, PocLoadUnsignedJSPoc) != 1 {
		t.Fatalf("expected one %s diagnostic, got %v", PocLoadUnsignedJSPoc, diags)
	}

	// 用用户自己的密钥签名后，严格模式应放行。
	priv, err := pocsign.LoadOrCreateSigningKey()
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey: %v", err)
	}
	if err := pocsign.SignFile(pocPath, priv); err != nil {
		t.Fatalf("SignFile: %v", err)
	}
	loaded, diags = optStrict.CreatePocListWithDiagnostics()
	if len(loaded) != 1 {
		t.Fatalf("strict mode should load the signed JS poc, got %d (diags=%v)", len(loaded), diags)
	}
}

func TestLoaderLenientWarnsOnTamperedSignature(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	pocPath := writeJSPoc(t, dir, "js.yaml", "js-demo")

	priv, err := pocsign.LoadOrCreateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := pocsign.SignFile(pocPath, priv); err != nil {
		t.Fatal(err)
	}
	// 篡改正文但保留原签名。
	raw, _ := os.ReadFile(pocPath)
	raw = []byte(strings.Replace(string(raw), `Export("ok")`, `Export("evil")`, 1))
	if err := os.WriteFile(pocPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	// 宽松模式：不拦截，仍加载（行为零变化）。
	opt := &Options{PocPaths: []string{dir}, PocPathsOnly: true, SDKMode: true, EnableJSPoc: true}
	if loaded, _ := opt.CreatePocListWithDiagnostics(); len(loaded) != 1 {
		t.Fatalf("lenient mode should still load a tampered poc, got %d", len(loaded))
	}

	// 严格模式：签名无效，跳过。
	optStrict := &Options{PocPaths: []string{dir}, PocPathsOnly: true, SDKMode: true, EnableJSPoc: true, RequireSignedJSPoc: true}
	loaded, diags := optStrict.CreatePocListWithDiagnostics()
	if len(loaded) != 0 {
		t.Fatalf("strict mode should skip the tampered poc, got %d", len(loaded))
	}
	if countReason(diags, PocLoadUnsignedJSPoc) != 1 {
		t.Fatalf("expected one %s diagnostic, got %v", PocLoadUnsignedJSPoc, diags)
	}
}
