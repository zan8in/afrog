package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/mcp"
	"github.com/zan8in/afrog/v3/pkg/policy"
)

// withAgentCallFixture 准备隔离环境（HOME / 配置 / DB），并把工具面固定成给定策略，
// 让 /api/v1/call 的判定只取决于这份策略，不受用户本机配置影响。
func withAgentCallFixture(t *testing.T, policyYAML string) {
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

	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	p, err := policy.Parse([]byte(policyYAML))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	agentToolMu.Lock()
	agentToolSrv, agentToolErr, agentToolBuilt = mcp.New(mcp.Options{Policy: p}), nil, true
	agentToolMu.Unlock()
	t.Cleanup(func() {
		agentToolMu.Lock()
		agentToolSrv, agentToolErr, agentToolBuilt = nil, nil, false
		agentToolMu.Unlock()
	})
}

func callAgent(t *testing.T, name string, args map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"name": name, "arguments": args})
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	rec := httptest.NewRecorder()
	agentCallHandler(rec, httptest.NewRequest(http.MethodPost, "/api/v1/call", bytes.NewReader(body)))
	return rec
}

// 默认（只读）下，写动作即使参数合法也必须被策略拒绝，且返回 403。
func TestAgentCallDeniedByDefaultReadOnly(t *testing.T) {
	withAgentCallFixture(t, "")

	rec := callAgent(t, "probe.http", map[string]any{"url": "http://example.com/"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "policy denied") {
		t.Fatalf("denial reason must be surfaced: %s", rec.Body.String())
	}
}

// safe 档位放行写动作：probe.http 应真正打出去并回 200。
func TestAgentCallAllowsWriteInSafeMode(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(target.Close)

	withAgentCallFixture(t, "mode: safe\nbudget:\n  requests: 50\n  duration: 2m\n")

	rec := callAgent(t, "probe.http", map[string]any{"url": target.URL + "/"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	if res["status"] != float64(http.StatusOK) {
		t.Fatalf("probe result = %+v, want status 200", res)
	}
}

// 未知工具名回 404，而不是把它当成失败的工具调用。
func TestAgentCallUnknownTool(t *testing.T) {
	withAgentCallFixture(t, "mode: safe\nbudget:\n  requests: 10\n  duration: 2m\n")

	rec := callAgent(t, "nope.nothing", map[string]any{})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}
}

// 预算耗尽回 429：写动作的预算与 MCP 共用同一份计数器，超限后不再放行。
func TestAgentCallBudgetExhausted(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	withAgentCallFixture(t, "mode: safe\nbudget:\n  requests: 1\n  duration: 2m\n")

	if rec := callAgent(t, "probe.http", map[string]any{"url": target.URL + "/"}); rec.Code != http.StatusOK {
		t.Fatalf("first call status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	rec := callAgent(t, "probe.http", map[string]any{"url": target.URL + "/"})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second call status = %d, want 429 (body=%s)", rec.Code, rec.Body.String())
	}
}
