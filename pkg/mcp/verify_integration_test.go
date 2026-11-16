package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/policy"
)

const (
	verifyHitMarker = "AFROG_MCP_VERIFY_HIT"
	// verifyHitID 是这份命中 PoC 的 id：scan.start 用 -s 按 id 选中它。
	verifyHitID = "mcp-verify-hit"
)

// newIntegrationServer 构建一个可验证的 MCP 服务端：HOME 指向临时目录并关掉 curated
// 源，测试因此只跑本地 PoC，既不访问网络，也不会碰用户的 afrog-config.yaml。
//
// 它不注入扫描执行器：只用于「不真正发包」的用例（策略拒绝、只读回读）。需要真跑扫描
// 的用例改用 newSubprocessServer。
func newIntegrationServer(t *testing.T, policyYAML string) *Server {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	confDir := filepath.Join(home, ".config", "afrog")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	conf := []byte("curated:\n  enabled: \"off\"\n")
	if err := os.WriteFile(filepath.Join(confDir, "afrog-config.yaml"), conf, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	p, err := policy.Parse([]byte(policyYAML))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	return New(Options{Policy: p})
}

// hitPocYAML 是一份最小命中 PoC 的 YAML 原文：目标返回的正文里带 verifyHitMarker 即命中。
func hitPocYAML() string {
	return `id: ` + verifyHitID + `
info:
  name: mcp verify hit
  author: afrog-test
  severity: info
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.status == 200 && response.body.bcontains(b"` + verifyHitMarker + `")
expression: r0()
`
}

func writeHitPoc(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), verifyHitID+".yaml")
	if err := os.WriteFile(path, []byte(hitPocYAML()), 0o644); err != nil {
		t.Fatalf("write poc: %v", err)
	}
	return path
}

// scan.start 的真实命中路径：按 -s 关键词选中 PoC，一次子进程跑出可重放证据。
func TestScanStartToolReturnsEvidenceOnRealHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>" + verifyHitMarker + "</html>"))
	}))
	t.Cleanup(srv.Close)

	s := newSubprocessServer(t, "mode: safe\nbudget:\n  requests: 50\n  duration: 2m\n")
	installPoc(t, verifyHitID, hitPocYAML())

	out := runTool(t, s, "scan.start", map[string]any{"target": srv.URL, "search": verifyHitID})
	res, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result type %T", out)
	}
	if res["found"] != true {
		t.Fatalf("found = %v, want true (status=%v error=%v)", res["found"], res["status"], res["error"])
	}
	items, ok := res["results"].([]map[string]any)
	if !ok || len(items) == 0 {
		t.Fatalf("results = %#v, want at least one hit", res["results"])
	}

	ev := firstEvidence(items)
	if ev == nil {
		t.Fatalf("evidence missing: %#v", items[0]["evidence"])
	}
	if !strings.HasPrefix(ev.ID, "evd_") {
		t.Fatalf("evidence id = %q, want evd_ prefix", ev.ID)
	}
	if len(ev.Steps) == 0 || !ev.Steps[0].Matched {
		t.Fatalf("evidence steps = %+v, want a matched confirm step", ev.Steps)
	}
	if ev.Replay.Command == "" || !ev.Replay.Deterministic {
		t.Fatalf("evidence replay = %+v, want a deterministic command", ev.Replay)
	}

	// 预留额度按关键词估算，必须真的扣掉：剩余不再是 50。
	if got := s.gate.Budget().Remaining(); got >= 50 {
		t.Fatalf("budget remaining = %d, want it consumed by the scan", got)
	}
}

// 默认只读策略下 scan.start 必须被拒绝，且拒绝不能扣预算。
func TestScanStartToolDeniedByReadOnlyPolicy(t *testing.T) {
	s := newIntegrationServer(t, "mode: readonly\n")

	if _, err := s.tools["scan.start"].Handler(context.Background(),
		mustJSON(t, map[string]any{"target": "http://127.0.0.1:1", "search": verifyHitID})); err == nil ||
		!strings.Contains(err.Error(), "policy denied") {
		t.Fatalf("err = %v, want a policy denial", err)
	}
	if got := s.gate.Budget().Remaining(); got != policy.DefaultRequests {
		t.Fatalf("budget after denial = %d, want %d", got, policy.DefaultRequests)
	}
}
