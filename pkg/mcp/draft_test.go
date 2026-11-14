package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleDraft = `
id: demo-draft
info:
  name: demo draft
  author: model
  severity: medium
rules:
  r0:
    request:
      method: GET
      path: /probe
    expression: response.status == 200 && response.body.bcontains(b"marker")
expression: r0()
`

// poc.draft 只做静态校验：默认只读策略下可用，且不产生任何网络请求。
func callDraft(t *testing.T, args map[string]any) (map[string]any, error) {
	t.Helper()
	srv := New(Options{})
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	out, err := srv.tools["poc.draft"].Handler(context.Background(), raw)
	if err != nil {
		return nil, err
	}
	return out.(map[string]any), nil
}

func TestPocDraftAcceptsValidYAML(t *testing.T) {
	out, err := callDraft(t, map[string]any{"yaml": sampleDraft})
	if err != nil {
		t.Fatalf("call: %v", err)
	}

	if out["valid"] != true {
		t.Fatalf("valid = %v, errors = %v", out["valid"], out["errors"])
	}
	if out["id"] != "demo-draft" || out["severity"] != "medium" {
		t.Fatalf("unexpected meta: %+v", out)
	}
	if out["rules"] != 1 {
		t.Fatalf("rules = %v, want 1", out["rules"])
	}
	if out["capability"] != "declarative" {
		t.Fatalf("capability = %v, want declarative", out["capability"])
	}
	if out["estimated_requests"] != 1 {
		t.Fatalf("estimated_requests = %v, want 1", out["estimated_requests"])
	}
	if w := out["warnings"].([]string); len(w) != 0 {
		t.Fatalf("unexpected warnings: %v", w)
	}
}

func TestPocDraftRejectsBrokenYAML(t *testing.T) {
	out, err := callDraft(t, map[string]any{"yaml": "id: [unclosed"})
	if err != nil {
		t.Fatalf("broken yaml should be reported, not raised: %v", err)
	}
	if out["valid"] != false {
		t.Fatalf("valid = %v, want false", out["valid"])
	}
	if len(out["errors"].([]string)) == 0 {
		t.Fatal("expected a yaml error")
	}
}

func TestPocDraftReportsMissingFields(t *testing.T) {
	out, err := callDraft(t, map[string]any{"yaml": "id: ''\nrules: {}\n"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	joined := strings.Join(out["errors"].([]string), "|")
	if out["valid"] != false || !strings.Contains(joined, "id is required") || !strings.Contains(joined, "rules is required") {
		t.Fatalf("errors = %q", joined)
	}
}

// 草稿 id 会成为落盘文件名，路径穿越必须在校验阶段被拒绝。
func TestPocDraftRejectsUnsafeID(t *testing.T) {
	out, err := callDraft(t, map[string]any{"yaml": strings.Replace(sampleDraft, "id: demo-draft", "id: ../evil", 1)})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if out["valid"] != false {
		t.Fatalf("valid = %v, want false", out["valid"])
	}
	if joined := strings.Join(out["errors"].([]string), "|"); !strings.Contains(joined, "id must be") {
		t.Fatalf("errors = %q", joined)
	}
}

// brute 字典与 exec 级脚本都算破坏性资产，需要提前告诉调用方。
func TestPocDraftFlagsDestructive(t *testing.T) {
	brute := `
id: brute-draft
info:
  name: brute
  severity: high
rules:
  r0:
    brute:
      password:
        - a
        - b
    request:
      path: /login
    expression: response.status == 200
expression: r0()
`
	out, err := callDraft(t, map[string]any{"yaml": brute})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if out["destructive"] != true {
		t.Fatalf("destructive = %v, want true", out["destructive"])
	}
	if out["estimated_requests"] != 2 {
		t.Fatalf("estimated_requests = %v, want 2", out["estimated_requests"])
	}
}

func TestPocDraftSaveWritesFileWithTightPermissions(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	out, err := callDraft(t, map[string]any{"yaml": sampleDraft, "save": true})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	path, _ := out["poc_path"].(string)
	if path == "" {
		t.Fatalf("poc_path missing: %+v", out)
	}
	if want := filepath.Join(".config", "afrog", "drafts", "demo-draft.yaml"); !strings.HasSuffix(path, want) {
		t.Fatalf("poc_path = %q, want suffix %q", path, want)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read draft: %v", err)
	}
	if string(data) != sampleDraft {
		t.Fatal("saved draft is not the original bytes")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat draft: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("draft perm = %o, want 600", perm)
	}
}

func TestPocDraftSaveRefusesInvalidDraft(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	_, err := callDraft(t, map[string]any{"yaml": "id: ''\n", "save": true})
	if err == nil || !strings.Contains(err.Error(), "draft is invalid") {
		t.Fatalf("err = %v, want invalid draft", err)
	}
}
