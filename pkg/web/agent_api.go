package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/zan8in/afrog/v3/pkg/agentapi"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/planner"
	"github.com/zan8in/gologger"
)

// /api/v1 是给 Agent / 脚本用的只读 REST 入口：与 MCP 工具同名同语义。
//
// 与旧 /api/* 的分工：旧接口服务于 Web 控制台，返回 APIResponse 信封；
// 新接口直接返回与 MCP 相同的 JSON，方便同一个 Agent 在两种传输间切换。
// 旧 /api/* 保持不动，作为兼容层。
func registerAgentAPIRoutes(api *mux.Router) {
	v1 := api.PathPrefix("/v1").Subrouter()

	v1.HandleFunc("/health", agentHealthHandler).Methods(http.MethodGet)
	v1.HandleFunc("/observe/findings", jwtAuthMiddleware(agentFindingsHandler)).Methods(http.MethodGet)
	v1.HandleFunc("/observe/evidence/{id}", jwtAuthMiddleware(agentEvidenceHandler)).Methods(http.MethodGet)
	v1.HandleFunc("/observe/state", jwtAuthMiddleware(agentStateHandler)).Methods(http.MethodGet)
	v1.HandleFunc("/observe/observations", jwtAuthMiddleware(agentObservationsHandler)).Methods(http.MethodGet)
	v1.HandleFunc("/plan/next", jwtAuthMiddleware(agentPlanHandler)).Methods(http.MethodGet)
	v1.HandleFunc("/poc/search", jwtAuthMiddleware(agentPocSearchHandler)).Methods(http.MethodGet)
	// 写动作面：与 MCP 同名同语义地调用任意工具，策略、预算、审计与 MCP 共用同一份。
	v1.HandleFunc("/call", jwtAuthMiddleware(agentCallHandler)).Methods(http.MethodPost)
	// 工具目录：列出全部 MCP 工具的能力等级、破坏性标记与当前策略下的可用性，
	// 是工具台与接入向导的唯一数据来源。
	v1.HandleFunc("/tools", jwtAuthMiddleware(agentToolsCatalogHandler)).Methods(http.MethodGet)
	v1.NotFoundHandler = http.HandlerFunc(agentNotFoundHandler)
}

// agentHealthHandler 与 /api/health 同义，但走 /api/v1 前缀，便于探活脚本统一。
func agentHealthHandler(w http.ResponseWriter, r *http.Request) {
	agentJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "afrog-agent-api"})
}

// agentFindingsHandler 对应 MCP observe.findings。
func agentFindingsHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := atoiDefault(q.Get("page"), 1)
	if page <= 0 {
		page = 1
	}
	limit := atoiDefault(q.Get("limit"), 50)
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	result, err := agentapi.Findings(sqlite.LedgerFilter{
		Status:   queryList(q["status"]),
		Severity: queryList(q["severity"]),
		Project:  strings.TrimSpace(q.Get("project_id")),
		Keyword:  strings.TrimSpace(q.Get("keyword")),
		Page:     page,
		PageSize: limit,
	})
	if err != nil {
		agentFailure(w, err)
		return
	}
	agentJSON(w, http.StatusOK, result)
}

// agentEvidenceHandler 对应 MCP observe.evidence。
func agentEvidenceHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(mux.Vars(r)["id"])
	ev, err := agentapi.Evidence(id)
	if err != nil {
		agentJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if ev == nil {
		agentJSON(w, http.StatusNotFound, map[string]any{"error": "evidence not found"})
		return
	}
	agentJSON(w, http.StatusOK, ev)
}

// agentStateHandler 对应 MCP observe.state。
func agentStateHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	subject := strings.TrimSpace(q.Get("subject"))
	if subject == "" {
		agentJSON(w, http.StatusBadRequest, map[string]any{"error": "subject is required"})
		return
	}

	result, err := agentapi.State(subject, q.Get("project_id"), atoiDefault(q.Get("depth"), 0), q.Get("direction"))
	if err != nil {
		agentFailure(w, err)
		return
	}
	agentJSON(w, http.StatusOK, result)
}

// agentObservationsHandler 对应 MCP observe.observations。
func agentObservationsHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since, _ := strconv.ParseInt(strings.TrimSpace(q.Get("since_seq")), 10, 64)

	result, err := agentapi.Observations(sqlite.ObservationFilter{
		SinceSeq:     since,
		Sources:      queryList(q["sources"]),
		Kinds:        queryList(q["kinds"]),
		Subject:      strings.TrimSpace(q.Get("subject")),
		SubjectUnder: queryBool(q.Get("subject_under")),
		ProjectID:    strings.TrimSpace(q.Get("project_id")),
		Limit:        atoiDefault(q.Get("limit"), 100),
	})
	if err != nil {
		agentFailure(w, err)
		return
	}
	agentJSON(w, http.StatusOK, result)
}

// agentPlanHandler 对应 MCP plan.next。
func agentPlanHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	result, err := agentapi.Plan(planner.Options{
		ProjectID: strings.TrimSpace(q.Get("project_id")),
		Subject:   strings.TrimSpace(q.Get("subject")),
		Under:     queryBool(q.Get("subject_under")),
		Limit:     atoiDefault(q.Get("limit"), 0),
	})
	if err != nil {
		agentFailure(w, err)
		return
	}
	agentJSON(w, http.StatusOK, result)
}

// agentPocSearchHandler 对应 MCP poc.search。
func agentPocSearchHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	result, err := agentapi.SearchPocs(
		strings.TrimSpace(q.Get("keyword")),
		queryList(q["severity"]),
		atoiDefault(q.Get("limit"), 50),
	)
	if err != nil {
		agentFailure(w, err)
		return
	}
	agentJSON(w, http.StatusOK, result)
}

func agentNotFoundHandler(w http.ResponseWriter, r *http.Request) {
	agentJSON(w, http.StatusNotFound, map[string]any{
		"error":  "api endpoint not found",
		"path":   r.URL.Path,
		"method": r.Method,
	})
}

// agentJSON 直接写出与 MCP 一致的 payload，不再套 success/message 信封。
func agentJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// agentFailure 把内部错误映射成 500，并保留可读原因。
func agentFailure(w http.ResponseWriter, err error) {
	gologger.Debug().Msgf("agent api 失败: %v", err)
	agentJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
}

// queryList 同时支持 ?k=a&k=b 与 ?k=a,b 两种写法：脚本习惯前者，手工调试习惯后者。
func queryList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, raw := range values {
		for _, p := range strings.Split(raw, ",") {
			if v := strings.TrimSpace(p); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// queryBool 解析布尔查询参数，无法识别时按 false 处理。
func queryBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
