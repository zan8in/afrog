package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/evidence"
	"github.com/zan8in/afrog/v3/pkg/policy"
)

const verifyHitMarker = "AFROG_MCP_VERIFY_HIT"

// newIntegrationServer 构建一个可验证的 MCP 服务端：HOME 指向临时目录并关掉 curated
// 源，测试因此只跑本地 PoC，既不访问网络，也不会碰用户的 afrog-config.yaml。
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

func writeHitPoc(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "mcp-verify-hit.yaml")
	body := `id: mcp-verify-hit
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
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write poc: %v", err)
	}
	return path
}

// verify.poc 的真实命中路径曾经因为 SDK 的首命中停止语义整体失效（fail-closed），
// 这里直接驱动工具处理器，锁住「参数 → SDK → 证据 → 返回值」这条链路。
func TestVerifyPocToolReturnsEvidenceOnRealHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>" + verifyHitMarker + "</html>"))
	}))
	t.Cleanup(srv.Close)

	s := newIntegrationServer(t, "mode: safe\nbudget:\n  requests: 20\n  duration: 2m\n")
	args, err := json.Marshal(map[string]any{"poc_path": writeHitPoc(t), "target": srv.URL})
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}

	out, err := s.tools["verify.poc"].Handler(context.Background(), args)
	if err != nil {
		t.Fatalf("verify.poc: %v", err)
	}

	res, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result type %T", out)
	}
	if res["found"] != true {
		t.Fatalf("found = %v, want true", res["found"])
	}
	items, ok := res["results"].([]map[string]any)
	if !ok || len(items) != 1 {
		t.Fatalf("results = %#v, want one item", res["results"])
	}

	ev, ok := items[0]["evidence"].(*evidence.Evidence)
	if !ok || ev == nil {
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

	// 单规则 PoC 估算 1 次请求：预算必须从 20 扣到 19。
	if got := s.gate.Budget().Remaining(); got != 19 {
		t.Fatalf("budget remaining = %d, want 19", got)
	}
}

// 默认只读策略下 verify.poc 必须被拒绝，且拒绝不能扣预算。
func TestVerifyPocToolDeniedByReadOnlyPolicy(t *testing.T) {
	s := newIntegrationServer(t, "mode: readonly\n")
	args, err := json.Marshal(map[string]any{"poc_path": writeHitPoc(t), "target": "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}

	if _, err := s.tools["verify.poc"].Handler(context.Background(), args); err == nil ||
		!strings.Contains(err.Error(), "policy denied") {
		t.Fatalf("err = %v, want a policy denial", err)
	}
	if got := s.gate.Budget().Remaining(); got != policy.DefaultRequests {
		t.Fatalf("budget after denial = %d, want %d", got, policy.DefaultRequests)
	}
}
