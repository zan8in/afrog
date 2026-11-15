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

	"github.com/gorilla/mux"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
)

// withAgentPanelFixture 准备一个隔离环境：独立 HOME、可写的 afrog-config.yaml 与 DB，
// 并把「策略 / 审计 / 配置文件」三个全局路径指向它。工具面保持未装配，让测试走真实
// 的 buildAgentTools → 从路径加载策略 这条链路。
func withAgentPanelFixture(t *testing.T) string {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	confDir := filepath.Join(home, ".config", "afrog")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	configPath := filepath.Join(confDir, "afrog-config.yaml")
	if err := os.WriteFile(configPath, []byte("curated:\n  enabled: \"off\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	prevPolicy, prevAudit, prevConfig := agentPolicyPath, agentAuditPath, agentConfigPath
	agentToolMu.Lock()
	agentToolSrv, agentToolErr, agentToolBuilt = nil, nil, false
	agentToolMu.Unlock()
	agentPolicyPath, agentAuditPath, agentConfigPath = "", "", configPath
	t.Cleanup(func() {
		agentToolMu.Lock()
		agentToolSrv, agentToolErr, agentToolBuilt = nil, nil, false
		agentToolMu.Unlock()
		agentPolicyPath, agentAuditPath, agentConfigPath = prevPolicy, prevAudit, prevConfig
	})
	return configPath
}

func newJSONRequest(method, target, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// 未配置 agent.policy 时，面板回显的是只读默认策略，且能看出「能跑到哪一档」。
func TestAgentPolicyGetDefaultReadOnly(t *testing.T) {
	withAgentPanelFixture(t)

	rec := httptest.NewRecorder()
	agentPolicyGetHandler(rec, httptest.NewRequest(http.MethodGet, "/api/agent/policy", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var env struct {
		Success bool             `json:"success"`
		Data    agentPolicyState `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	if !env.Success {
		t.Fatalf("success = false: %s", rec.Body.String())
	}
	if env.Data.Mode != "readonly" || env.Data.MaxCapability != "declarative" {
		t.Fatalf("default policy = %+v, want readonly/declarative", env.Data)
	}
	if env.Data.LoadError != "" {
		t.Fatalf("load_error should be empty, got %q", env.Data.LoadError)
	}
}

// 工具目录是工具台与接入向导的唯一数据来源：能力等级、破坏性标记、当前策略下的可用性。
func TestAgentToolCatalog(t *testing.T) {
	withAgentPanelFixture(t)

	rec := httptest.NewRecorder()
	agentToolsCatalogHandler(rec, httptest.NewRequest(http.MethodGet, "/api/v1/tools", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var cat agentToolCatalog
	if err := json.Unmarshal(rec.Body.Bytes(), &cat); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	if cat.Mode != "readonly" {
		t.Fatalf("mode = %q, want readonly", cat.Mode)
	}
	if len(cat.Tools) == 0 {
		t.Fatal("catalog must not be empty")
	}

	byName := make(map[string]agentToolCatalogEntry, len(cat.Tools))
	for _, entry := range cat.Tools {
		byName[entry.Name] = entry
	}

	// 只读档下，读工具放行，写工具被挡；act.brute 还应标出「破坏性 + exec 级」。
	read, ok := byName["observe.findings"]
	if !ok {
		t.Fatalf("observe.findings missing from catalog: %+v", cat.Tools)
	}
	if !read.Allowed {
		t.Fatalf("observe.findings should be allowed in readonly: %+v", read)
	}

	brute, ok := byName["act.brute"]
	if !ok {
		t.Fatalf("act.brute missing from catalog")
	}
	if brute.Allowed {
		t.Fatalf("act.brute must be denied in readonly: %+v", brute)
	}
	if !brute.Destructive || brute.Capability != "exec" {
		t.Fatalf("act.brute must be flagged destructive+exec: %+v", brute)
	}
}

// 保存策略：写 policy YAML + 回写 agent 段，随即生效（GET 能读到新档位）。
func TestAgentPolicyPutRoundTrip(t *testing.T) {
	configPath := withAgentPanelFixture(t)

	body := `{"mode":"full","destructive":true,"budget":{"requests":123,"duration":"3m"}}`
	rec := httptest.NewRecorder()
	agentPolicyPutHandler(rec, newJSONRequest(http.MethodPut, "/api/agent/policy", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var env struct {
		Success bool             `json:"success"`
		Data    agentPolicyState `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	if !env.Success || env.Data.Mode != "full" || env.Data.MaxCapability != "exec" || !env.Data.Destructive {
		t.Fatalf("saved policy = %+v", env.Data)
	}
	if env.Data.Budget.Requests != 123 || env.Data.Budget.Duration != "3m0s" {
		t.Fatalf("budget = %+v, want 123/3m0s", env.Data.Budget)
	}

	// policy YAML 落到默认位置，agent 段写回 afrog-config.yaml。
	if _, err := os.Stat(env.Data.PolicyPath); err != nil {
		t.Fatalf("policy file not written: %v", err)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(raw), "agent:") || !strings.Contains(string(raw), "policy:") {
		t.Fatalf("agent section not written back:\n%s", raw)
	}

	// 重新读取应与保存一致：证明写文件确实生效，而不是只在响应里回显。
	rec = httptest.NewRecorder()
	agentPolicyGetHandler(rec, httptest.NewRequest(http.MethodGet, "/api/agent/policy", nil))
	var after struct {
		Data agentPolicyState `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &after); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if after.Data.Mode != "full" || !after.Data.Destructive {
		t.Fatalf("policy did not take effect: %+v", after.Data)
	}
}

func TestAgentPolicyPutRejectsBadMode(t *testing.T) {
	withAgentPanelFixture(t)

	rec := httptest.NewRecorder()
	agentPolicyPutHandler(rec, newJSONRequest(http.MethodPut, "/api/agent/policy", `{"mode":"yolo"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

// 候选草稿的列表 / 详情 / 驳回走的是与 `afrog poc` 同一批状态机接口。
func TestAgentDraftsListShowReject(t *testing.T) {
	withAgentPanelFixture(t)

	draftPath := filepath.Join(t.TempDir(), "draft.yaml")
	yamlBody := "id: agent-test-draft\ninfo:\n  name: Agent Test\n  severity: medium\nrules:\n  r0: {}\n"
	if err := os.WriteFile(draftPath, []byte(yamlBody), 0o600); err != nil {
		t.Fatalf("write draft: %v", err)
	}
	if err := sqlite.UpsertPocDraft(sqlite.PocDraft{
		ID: "agent-test-draft", Path: draftPath, Name: "Agent Test",
		Severity: "medium", EvidenceID: "evd_x",
	}); err != nil {
		t.Fatalf("upsert draft: %v", err)
	}

	// list（pending）
	rec := httptest.NewRecorder()
	agentDraftsListHandler(rec, httptest.NewRequest(http.MethodGet, "/api/agent/drafts?status=pending", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Data []sqlite.PocDraft `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v (body=%s)", err, rec.Body.String())
	}
	if len(list.Data) != 1 || list.Data[0].ID != "agent-test-draft" {
		t.Fatalf("list = %+v", list.Data)
	}

	// show：回显草稿 YAML 原文
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agent/drafts/agent-test-draft", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "agent-test-draft"})
	agentDraftShowHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("show status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var show struct {
		Data struct {
			Draft sqlite.PocDraft `json:"draft"`
			YAML  string          `json:"yaml"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &show); err != nil {
		t.Fatalf("decode show: %v", err)
	}
	if !strings.Contains(show.Data.YAML, "agent-test-draft") {
		t.Fatalf("yaml not echoed: %q", show.Data.YAML)
	}

	// reject：推进状态并保留原因
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/agent/drafts/agent-test-draft/reject", bytes.NewReader([]byte(`{"note":"noise"}`)))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "agent-test-draft"})
	agentDraftRejectHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reject status = %d, body = %s", rec.Code, rec.Body.String())
	}
	got, err := sqlite.SelectPocDraft("agent-test-draft")
	if err != nil {
		t.Fatalf("select draft: %v", err)
	}
	if got.Status != sqlite.PocDraftRejected || got.Note != "noise" {
		t.Fatalf("draft after reject = %+v", got)
	}
}

func TestAgentDraftsListRejectsBadStatus(t *testing.T) {
	withAgentPanelFixture(t)

	rec := httptest.NewRecorder()
	agentDraftsListHandler(rec, httptest.NewRequest(http.MethodGet, "/api/agent/drafts?status=nope", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

// 调优建议：列表 / 详情 / 采纳，采纳只记录决策，不自动应用 diff。
func TestAgentSuggestionsAccept(t *testing.T) {
	withAgentPanelFixture(t)

	if err := sqlite.UpsertLearnSuggestion(sqlite.LearnSuggestion{
		ID: "lsg_test", Kind: sqlite.LearnKindThreshold,
		Summary: "raise timeout", Diff: "- 5s\n+ 8s",
	}); err != nil {
		t.Fatalf("upsert suggestion: %v", err)
	}

	rec := httptest.NewRecorder()
	agentSuggestionsListHandler(rec, httptest.NewRequest(http.MethodGet, "/api/agent/suggestions?status=pending", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Data []sqlite.LearnSuggestion `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Data) != 1 || list.Data[0].ID != "lsg_test" {
		t.Fatalf("list = %+v", list.Data)
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/agent/suggestions/lsg_test/accept", bytes.NewReader([]byte(`{"note":"ok"}`)))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "lsg_test"})
	agentSuggestionAcceptHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("accept status = %d, body = %s", rec.Code, rec.Body.String())
	}
	got, err := sqlite.SelectLearnSuggestion("lsg_test")
	if err != nil {
		t.Fatalf("select suggestion: %v", err)
	}
	if got.Status != sqlite.LearnSuggestionAccepted || got.Note != "ok" {
		t.Fatalf("suggestion after accept = %+v", got)
	}
}

// 审计面板：路径为空时只给说明，不整体失败。
func TestAgentAuditEmptyPath(t *testing.T) {
	withAgentPanelFixture(t)

	rec := httptest.NewRecorder()
	agentAuditHandler(rec, httptest.NewRequest(http.MethodGet, "/api/agent/audit", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Data struct {
			Records []any  `json:"records"`
			Note    string `json:"note"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	if len(env.Data.Records) != 0 || env.Data.Note == "" {
		t.Fatalf("audit with empty path = %+v, want empty records + note", env.Data)
	}
}

// 新面板接口挂在 /api/agent/* 与 /api/v1/tools 上，未登录一律 401。
func TestAgentPanelRoutesRequireAuth(t *testing.T) {
	withAgentPanelFixture(t)
	h, err := setupHandler()
	if err != nil {
		t.Fatalf("setupHandler: %v", err)
	}

	for _, path := range []string{"/api/agent/drafts", "/api/agent/policy", "/api/agent/audit", "/api/v1/tools"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("未登录访问 %s 应 401，实际 %d", path, rec.Code)
		}
	}
}
