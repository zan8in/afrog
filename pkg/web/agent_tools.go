package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/mcp"
	"github.com/zan8in/afrog/v3/pkg/policy"
	"github.com/zan8in/gologger"
)

// Agent 写动作面：/api/v1/call 与 MCP 复用同一套工具注册表与策略门控。
//
// 这不是第二套实现——工具处理器内部的 gate 就是唯一的执行入口，因此策略、预算、
// 审计在 MCP 与 REST 之间天然一致，不存在「REST 绕过了 MCP 的限额」这种缺口。
// 默认策略为只读：不配置 agent.policy 时，写动作一律被拒，与既有只读语义一致。

// agentPolicyPath / agentAuditPath / agentOOBAdapter / agentReverse 由 cmd 层在启动
// Web 服务前通过 SetAgentConfig 注入。
var (
	agentPolicyPath string
	agentAuditPath  string
	agentOOBAdapter string
	agentReverse    config.Reverse
)

// SetAgentConfig 注入 Agent 工具面的策略、审计与带外来源，由 cmd 层在启动 Web 服务前调用。
//
// reverse 提供反连凭据（ceye / xray / …），配合 agent.oob 里的适配器名，工具面的
// act.oob_payload / act.oob_wait 才有反连能力；未配置时两者会明确报未配置。
func SetAgentConfig(cfg config.Agent, reverse config.Reverse) {
	agentPolicyPath = strings.TrimSpace(cfg.Policy)
	agentAuditPath = strings.TrimSpace(cfg.Audit)
	agentOOBAdapter = strings.TrimSpace(cfg.OOB)
	agentReverse = reverse
}

var (
	agentToolMu    sync.Mutex
	agentToolSrv   *mcp.Server
	agentToolErr   error
	agentToolBuilt bool
)

// agentTools 惰性装配共享的工具面：策略、预算、审计只构建一次，所有 /api/v1/call
// 请求复用同一个 Server。写动作的预算因此是「进程级会话」预算，与 `afrog mcp
// -listen` 的语义一致，不会因为请求分散到多次 HTTP 调用而各自重置。
func agentTools() (*mcp.Server, error) {
	agentToolMu.Lock()
	defer agentToolMu.Unlock()
	if !agentToolBuilt {
		agentToolBuilt = true
		agentToolSrv, agentToolErr = buildAgentTools()
	}
	return agentToolSrv, agentToolErr
}

func buildAgentTools() (*mcp.Server, error) {
	// 装配口径与 gRPC AgentService 完全共用：策略/审计留空即只读默认。
	// 反连适配器配错不应拖垮整个工具面：记日志后按未配置处理，act.oob_* 会明确报未配置。
	oob, err := mcp.NewOOBSource(agentOOBAdapter, agentReverse)
	if err != nil {
		gologger.Error().Msgf("初始化工具面反连后端失败，act.oob_* 将不可用: %v", err)
		oob = nil
	}
	return mcp.NewWithPaths(agentPolicyPath, agentAuditPath, oob, mcp.ServerInfo{})
}

// agentCallHandler 是 /api/v1/call：POST {"name": "...", "arguments": {...}}。
//
// 读工具与写工具走同一入口，参数与 MCP 工具同名同义；策略、预算、审计由工具
// 处理器统一执行。把名称与参数透传而不是为每个动作单开路由，是为了让新增工具
// 不必再补一层 REST 胶水。
func agentCallHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		agentJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json body: " + err.Error()})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		agentJSON(w, http.StatusBadRequest, map[string]any{"error": "name is required"})
		return
	}

	srv, err := agentTools()
	if err != nil {
		agentJSON(w, http.StatusInternalServerError, map[string]any{"error": "agent policy unavailable: " + err.Error()})
		return
	}
	result, err := srv.Call(r.Context(), name, req.Arguments)
	if err != nil {
		agentToolError(w, name, err)
		return
	}
	agentJSON(w, http.StatusOK, result)
}

// agentToolError 把工具错误映射成合适的 HTTP 状态：策略拒绝 403、预算耗尽 429、
// 未知工具 404，其余归为 400（多为参数或校验问题）。
func agentToolError(w http.ResponseWriter, name string, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, policy.ErrDenied):
		status = http.StatusForbidden
	case errors.Is(err, policy.ErrBudgetExceeded):
		status = http.StatusTooManyRequests
	case strings.Contains(err.Error(), "unknown tool"):
		status = http.StatusNotFound
	}
	agentJSON(w, status, map[string]any{"error": err.Error(), "tool": name})
}
