package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/config"
)

// withAgentMCPFixture 隔离 MCP 面板用到的全局（配置路径与已注入的 agent 段），
// 让 PUT 写回落到临时配置而不是真实 HOME。
func withAgentMCPFixture(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "afrog-config.yaml")
	if err := os.WriteFile(configPath, []byte("curated:\n  enabled: \"off\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	prevMCP, prevPolicy, prevAudit, prevOOB, prevConfig := agentMCP, agentPolicyPath, agentAuditPath, agentOOBAdapter, agentConfigPath
	agentMCP = config.AgentMCP{}
	agentPolicyPath, agentAuditPath, agentOOBAdapter = "", "", ""
	agentConfigPath = configPath
	t.Cleanup(func() {
		agentMCP, agentPolicyPath, agentAuditPath, agentOOBAdapter, agentConfigPath = prevMCP, prevPolicy, prevAudit, prevOOB, prevConfig
	})
	return configPath
}

// normalizeMCPAddr 是界面输入的唯一净化点：使用者的写法五花八门，
// 这里统一成 host:port。
func TestNormalizeMCPAddr(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"127.0.0.1:16870", "127.0.0.1:16870"},
		{" 127.0.0.1:16870 ", "127.0.0.1:16870"},
		{"http://127.0.0.1:16870", "127.0.0.1:16870"},
		{"https://127.0.0.1:16870/mcp", "127.0.0.1:16870"},
		{"http://127.0.0.1:16870/sse?x=1", "127.0.0.1:16870"},
		{"127.0.0.1:16870/path", "127.0.0.1:16870"},
		{"", ""},
		{"   ", ""},
	}
	for _, c := range cases {
		if got := normalizeMCPAddr(c.in); got != c.want {
			t.Errorf("normalizeMCPAddr(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// 没有地址可探时不算错误：仍返回配置区与一句说明，界面据此渲染配置编辑器。
func TestAgentMCPProbeHandlerNoAddr(t *testing.T) {
	withAgentMCPFixture(t)

	rec := httptest.NewRecorder()
	agentMCPProbeHandler(rec, httptest.NewRequest(http.MethodGet, "/api/agent/mcp", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var env struct {
		Success bool                `json:"success"`
		Data    agentMCPProbeResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	if !env.Success {
		t.Fatalf("success = false: %s", rec.Body.String())
	}
	if env.Data.Status.Note == "" {
		t.Fatalf("note should explain there is no addr to probe (data=%+v)", env.Data)
	}
	if env.Data.Status.Running || env.Data.Status.Reachable {
		t.Fatalf("should not report running/reachable without addr: %+v", env.Data.Status)
	}
}

// /healthz 返回 200 时，判定为「这是一个 MCP 服务」，并且能给出接入片段。
func TestProbeMCPHealthRunning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	st := probeMCPHealth(context.Background(), strings.TrimPrefix(srv.URL, "http://"))
	if !st.Running || !st.Reachable {
		t.Fatalf("running/reachable = %v/%v, want true/true (status=%+v)", st.Running, st.Reachable, st)
	}
	if !st.Loopback {
		t.Fatalf("loopback = false, want true for 127.0.0.1 (status=%+v)", st)
	}
	if st.Note != "" {
		t.Fatalf("note = %q, want empty", st.Note)
	}
}

// 端口有响应但不是 MCP：reachable=true / running=false，且给出解释性 note。
func TestProbeMCPHealthReachableNotMCP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	st := probeMCPHealth(context.Background(), strings.TrimPrefix(srv.URL, "http://"))
	if st.Running || !st.Reachable {
		t.Fatalf("running/reachable = %v/%v, want false/true (status=%+v)", st.Running, st.Reachable, st)
	}
	if st.Note == "" {
		t.Fatalf("note should explain the non-200 result (status=%+v)", st)
	}
}

// 连不上（端口没人听）时应归为「未侦测到」，而不是让请求报错冒泡。
func TestProbeMCPHealthUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := strings.TrimPrefix(srv.URL, "http://")
	srv.Close() // 关掉，制造一个没人监听的端口

	st := probeMCPHealth(context.Background(), addr)
	if st.Running || st.Reachable {
		t.Fatalf("running/reachable = %v/%v, want false/false (status=%+v)", st.Running, st.Reachable, st)
	}
	if st.Note == "" {
		t.Fatalf("note should explain the miss (status=%+v)", st)
	}
}

// 完整走一遍 GET：能拿到 running 状态与两段接入片段。
func TestAgentMCPProbeHandlerRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	rec := httptest.NewRecorder()
	agentMCPProbeHandler(rec, httptest.NewRequest(http.MethodGet, "/api/agent/mcp?addr="+addr, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var env struct {
		Success bool                `json:"success"`
		Data    agentMCPProbeResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	if !env.Success || !env.Data.Status.Running {
		t.Fatalf("running = false: %s", rec.Body.String())
	}
	if env.Data.Status.Depth != "shallow" {
		t.Fatalf("depth = %q, want shallow", env.Data.Status.Depth)
	}
	if env.Data.Clients.Stdio.Command != "afrog" || len(env.Data.Clients.Stdio.Args) != 1 || env.Data.Clients.Stdio.Args[0] != "mcp" {
		t.Fatalf("stdio client = %+v, want afrog mcp", env.Data.Clients.Stdio)
	}
	if want := "http://" + addr + "/mcp"; env.Data.Clients.HTTP.URL != want {
		t.Fatalf("http client url = %q, want %q", env.Data.Clients.HTTP.URL, want)
	}
}

// 深检测：initialize 成功（200）→ auth=ok；并确认请求带上了 Bearer token。
func TestProbeMCPDeepAuthOK(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`))
	}))
	defer srv.Close()

	st := probeMCPDeep(context.Background(), strings.TrimPrefix(srv.URL, "http://"), "s3cr3t")
	if st.Auth != "ok" || !st.Running {
		t.Fatalf("auth/running = %q/%v, want ok/true (status=%+v)", st.Auth, st.Running, st)
	}
	if gotAuth != "Bearer s3cr3t" {
		t.Fatalf("server saw Authorization %q, want Bearer s3cr3t", gotAuth)
	}
}

// 深检测：401 → auth=unauthorized，且 running=false（服务在跑但没通过校验）。
func TestProbeMCPDeepUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	st := probeMCPDeep(context.Background(), strings.TrimPrefix(srv.URL, "http://"), "bad")
	if st.Auth != "unauthorized" {
		t.Fatalf("auth = %q, want unauthorized (status=%+v)", st.Auth, st)
	}
	if st.Running {
		t.Fatalf("running = true, want false (status=%+v)", st)
	}
	if !st.Reachable {
		t.Fatalf("reachable = false, want true (status=%+v)", st)
	}
}

// PUT 往返：保存 listen 并生成 token，写回配置文件，GET 能读到掩码后的配置。
func TestAgentMCPPutRoundTrip(t *testing.T) {
	configPath := withAgentMCPFixture(t)

	rec := httptest.NewRecorder()
	agentMCPPutHandler(rec, newJSONRequest(http.MethodPut, "/api/agent/mcp", `{"listen":"http://127.0.0.1:16871/mcp","generate_token":true}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var env struct {
		Success bool                `json:"success"`
		Data    agentMCPProbeResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	if !env.Success {
		t.Fatalf("success = false: %s", rec.Body.String())
	}
	if env.Data.Config.Listen != "127.0.0.1:16871" {
		t.Fatalf("listen = %q, want 127.0.0.1:16871", env.Data.Config.Listen)
	}
	if env.Data.Config.Token == "" || env.Data.Config.Token == env.Data.Clients.HTTP.Token {
		t.Fatalf("config token should be masked while clients.http.token is plaintext once: %+v", env.Data)
	}
	plain := env.Data.Clients.HTTP.Token
	if len(plain) != 48 {
		t.Fatalf("generated token len = %d, want 48 (token=%q)", len(plain), plain)
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "mcp:") || !strings.Contains(string(raw), plain) {
		t.Fatalf("config file should hold the mcp subsection with the token:\n%s", raw)
	}

	// GET（不带 addr）应回落到 agent.mcp.listen，并把 token 掩码回显。
	rec2 := httptest.NewRecorder()
	agentMCPProbeHandler(rec2, httptest.NewRequest(http.MethodGet, "/api/agent/mcp", nil))
	var env2 struct {
		Data agentMCPProbeResult `json:"data"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &env2); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if env2.Data.Config.Listen != "127.0.0.1:16871" {
		t.Fatalf("get listen = %q, want 127.0.0.1:16871", env2.Data.Config.Listen)
	}
	if env2.Data.Config.Token != "••••••••" {
		t.Fatalf("get token = %q, want masked", env2.Data.Config.Token)
	}
}

// PUT 校验：监听非本机地址却没有 token 必须被拒（与 `afrog mcp` 的判定一致）。
func TestAgentMCPPutRejectsExposedWithoutToken(t *testing.T) {
	withAgentMCPFixture(t)

	rec := httptest.NewRecorder()
	agentMCPPutHandler(rec, newJSONRequest(http.MethodPut, "/api/agent/mcp", `{"listen":"0.0.0.0:16870"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}
