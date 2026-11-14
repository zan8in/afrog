package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gorilla/mux"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/observation"
	"github.com/zan8in/afrog/v3/pkg/planner"
)

func withAgentFixture(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)
}

func insertPortObservation(t *testing.T, subject string, port int) {
	t.Helper()
	obs, err := observation.New("", observation.SourcePortscan, observation.KindPortOpen,
		subject, observation.PortOpen{Port: port, State: "open", Service: "http"})
	if err != nil {
		t.Fatalf("new observation: %v", err)
	}
	if err := sqlite.InsertObservation(obs); err != nil {
		t.Fatalf("insert observation: %v", err)
	}
}

// /api/v1/observe/observations 与 MCP 同语义：游标、子树过滤、payload 原样返回。
func TestAgentObservationsHandler(t *testing.T) {
	withAgentFixture(t)
	insertPortObservation(t, "10.0.0.5:80", 80)
	insertPortObservation(t, "10.0.0.5:8080", 8080)
	insertPortObservation(t, "10.0.0.5.evil.com:80", 80)

	rec := httptest.NewRecorder()
	agentObservationsHandler(rec, httptest.NewRequest(http.MethodGet,
		"/api/v1/observe/observations?subject=10.0.0.5&subject_under=true&limit=10", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var page sqlite.ObservationPage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	if len(page.Items) != 2 {
		t.Fatalf("items = %d, want 2: %+v", len(page.Items), page.Items)
	}
	if page.NextSeq != page.Items[len(page.Items)-1].Seq {
		t.Fatalf("next_seq = %d, want %d", page.NextSeq, page.Items[len(page.Items)-1].Seq)
	}
	if len(page.Items[0].Payload) == 0 {
		t.Fatal("payload must be returned as-is")
	}

	// 游标翻页：再取一页应为空。
	rec = httptest.NewRecorder()
	agentObservationsHandler(rec, httptest.NewRequest(http.MethodGet,
		"/api/v1/observe/observations?since_seq="+strconv.FormatInt(page.NextSeq, 10), nil))
	var next sqlite.ObservationPage
	if err := json.Unmarshal(rec.Body.Bytes(), &next); err != nil {
		t.Fatalf("decode page 2: %v", err)
	}
	if len(next.Items) != 1 || next.Items[0].Subject != "10.0.0.5.evil.com:80" {
		t.Fatalf("第二页应只剩其它主机: %+v", next.Items)
	}
}

func TestAgentEvidenceHandlerNotFound(t *testing.T) {
	withAgentFixture(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/observe/evidence/evd_missing", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "evd_missing"})
	agentEvidenceHandler(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/observe/evidence/not-a-number", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "not-a-number"})
	agentEvidenceHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestAgentStateHandlerRequiresSubject(t *testing.T) {
	withAgentFixture(t)

	rec := httptest.NewRecorder()
	agentStateHandler(rec, httptest.NewRequest(http.MethodGet, "/api/v1/observe/state", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// /api/v1/plan/next 与 MCP plan.next 同语义：图上的候选 PoC 变成 verify.poc 提议。
func TestAgentPlanHandler(t *testing.T) {
	withAgentFixture(t)
	t.Setenv("AFROG_CURATED_DISABLED", "1")

	endpoint := "http://a.example/admin"
	if err := sqlite.EnsureTechGraph(endpoint, []string{"Nginx"}, map[string][]string{
		"Nginx": {"poc-a"},
	}); err != nil {
		t.Fatalf("ensure tech graph: %v", err)
	}

	rec := httptest.NewRecorder()
	agentPlanHandler(rec, httptest.NewRequest(http.MethodGet,
		"/api/v1/plan/next?subject="+endpoint, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var plan planner.Plan
	if err := json.Unmarshal(rec.Body.Bytes(), &plan); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	if len(plan.Proposals) != 1 {
		t.Fatalf("proposals = %+v, want 1", plan.Proposals)
	}
	got := plan.Proposals[0]
	if got.Action.Name != "verify.poc" || got.Action.PocID != "poc-a" ||
		got.Action.Target != "http://a.example" {
		t.Fatalf("proposal = %+v", got)
	}
}

// 路由注册在 /api/v1 下，且与旧 /api/* 一样受登录态保护。
func TestAgentAPIRoutesRequireAuth(t *testing.T) {
	withAgentFixture(t)
	h, err := setupHandler()
	if err != nil {
		t.Fatalf("setupHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/observe/observations", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未登录访问 /api/v1 应 401，实际 %d", rec.Code)
	}

	initJWTSecret()
	token, _, err := generateJWTToken("admin", "free")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/observe/observations?limit=5", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("带登录态访问 /api/v1 失败: %d body=%s", rec.Code, rec.Body.String())
	}
}
