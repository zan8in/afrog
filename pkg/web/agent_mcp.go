package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/mcp"
)

// MCP 服务可见性与接入配置：探活 + 接入片段 + agent.mcp 配置读写，不托管、不启停。
//
// 服务的生命周期始终由 `afrog mcp` 负责——控制台在这里只做三件事：看得见（探活）、
// 记得住（agent.mcp 写回）、接得上（生成客户端片段）。它不会替使用者拉起或停掉服务。

// agentMCPProbeTimeout 是浅检测（GET /healthz）的单次超时。只探一个本机端口，500ms
// 足够；太短会把慢机器误判成「未侦测到」，太长会让界面点一下卡住。
const agentMCPProbeTimeout = 500 * time.Millisecond

// agentMCPDeepTimeout 是深检测（POST /mcp initialize）的超时。深检测要等服务端跑完
// 握手，给得比浅检测宽，但仍要封顶，避免界面长时间无响应。
const agentMCPDeepTimeout = 3 * time.Second

// agentMCPHTTPClient 供探活与深检测共用：不跟随重定向（避免被引向别处），整体由 ctx 控时。
var agentMCPHTTPClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

type agentMCPStatus struct {
	Running   bool   `json:"running"`
	Addr      string `json:"addr"`
	Reachable bool   `json:"reachable"`
	LatencyMS int64  `json:"latency_ms"`
	// Loopback 为 false 表示该地址对外可见——界面据此提示暴露风险。
	Loopback bool `json:"loopback"`
	// Depth 标注本次结论来自哪种检测：shallow（端口活否）或 deep（token/协议对否）。
	Depth string `json:"depth"`
	// Auth 仅在深检测时有意义：ok（token 有效）/ unauthorized（鉴权失败）/ unknown。
	Auth string `json:"auth,omitempty"`
	// Note 非空时界面直接展示，用来解释「为什么是这个结论」。
	Note string `json:"note,omitempty"`
}

type agentMCPConfigState struct {
	Listen string `json:"listen"`
	// Token 掩码回显；明文只在保存/生成的响应里一次性返回（见 clients.http.token）。
	Token      string `json:"token"`
	ConfigPath string `json:"config_path"`
	// ManagedByConsole 恒为 false：本控制台不持有也不托管 MCP 服务。
	ManagedByConsole bool `json:"managed_by_console"`
}

type agentMCPStdioClient struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

type agentMCPHTTPClientSpec struct {
	URL string `json:"url"`
	// Token 默认掩码；保存/生成的那一刻明文回显一次，供界面复制完整片段。
	Token string `json:"token"`
}

type agentMCPClients struct {
	Stdio agentMCPStdioClient    `json:"stdio"`
	HTTP  agentMCPHTTPClientSpec `json:"http"`
}

type agentMCPProbeResult struct {
	Config  agentMCPConfigState `json:"config"`
	Status  agentMCPStatus      `json:"status"`
	Clients agentMCPClients     `json:"clients"`
}

// agentMCPProbeHandler 对应 GET /api/agent/mcp：探活并回显接入配置。
//
// 查询参数：
//
//	addr   要探测的地址；缺省时回落到 agent.mcp.listen
//	depth  shallow（默认，探 /healthz）或 deep（带 token 探 /mcp，可区分鉴权失败）
//
// 无地址可探时不算错误：仍返回配置区（供界面编辑）与一句说明。
func agentMCPProbeHandler(w http.ResponseWriter, r *http.Request) {
	depth := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("depth")))
	if depth != "deep" {
		depth = "shallow"
	}

	addr := normalizeMCPAddr(r.URL.Query().Get("addr"))
	if addr == "" {
		addr = strings.TrimSpace(agentMCP.Listen)
	}

	res := agentMCPProbeResult{Config: agentMCPConfigStateFrom()}
	if addr == "" {
		res.Status = agentMCPStatus{
			Depth: depth,
			Note:  "未配置监听地址：请填写并保存 agent.mcp.listen，或直接输入地址检测",
		}
		res.Clients = agentMCPClientsFor("", "")
		agentReviewOK(w, "ok", res)
		return
	}

	token := strings.TrimSpace(agentMCP.Token)
	if depth == "deep" {
		res.Status = probeMCPDeep(r.Context(), addr, token)
	} else {
		res.Status = probeMCPHealth(r.Context(), addr)
		res.Status.Depth = "shallow"
	}
	res.Clients = agentMCPClientsFor(addr, agentMCPMaskToken(token))
	agentReviewOK(w, "ok", res)
}

// agentMCPUpdateRequest 是保存接入配置的入参。
type agentMCPUpdateRequest struct {
	Listen string `json:"listen"`
	Token  string `json:"token"`
	// GenerateToken 为 true 时忽略 Token，服务端生成一个新 token 并明文回显一次。
	GenerateToken bool `json:"generate_token"`
	// ClearToken 为 true 时清空 token。
	ClearToken bool `json:"clear_token"`
}

// agentMCPPutHandler 对应 PUT /api/agent/mcp：把 listen / token 写回 afrog-config.yaml
// 的 agent.mcp 子段。不启停服务——保存只是让 `afrog mcp` 下次启动用上新口径。
func agentMCPPutHandler(w http.ResponseWriter, r *http.Request) {
	var req agentMCPUpdateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
		agentReviewFail(w, http.StatusBadRequest, "无效的JSON格式")
		return
	}

	listen := strings.TrimSpace(req.Listen)
	// 允许粘贴 "http://host:port/mcp" 这类完整地址，统一成 host:port。
	if listen != "" {
		listen = normalizeMCPAddr(listen)
	}

	token := strings.TrimSpace(req.Token)
	plaintextOnce := ""
	switch {
	case req.GenerateToken:
		generated, err := generateMCPToken()
		if err != nil {
			agentReviewFail(w, http.StatusInternalServerError, "生成 token 失败："+err.Error())
			return
		}
		token, plaintextOnce = generated, generated
	case req.ClearToken:
		token = ""
	case token == "":
		// 未提供 token：沿用当前值，避免「只改监听地址」时把 token 抹掉。
		token = strings.TrimSpace(agentMCP.Token)
	}

	if listen != "" && !mcp.IsLoopbackAddr(listen) && token == "" {
		agentReviewFail(w, http.StatusBadRequest, "监听非本机地址时必须提供 token")
		return
	}

	// agent 段整块替换：必须带上 policy/audit/oob，否则保存 MCP 配置会抹掉它们。
	if err := config.UpdateAgentSection(resolveClusterConfigPath(agentConfigPath), config.Agent{
		Policy: agentPolicyPath,
		Audit:  agentAuditPath,
		OOB:    agentOOBAdapter,
		MCP:    config.AgentMCP{Listen: listen, Token: token},
	}); err != nil {
		agentReviewFail(w, http.StatusInternalServerError, "写入配置文件失败："+err.Error())
		return
	}

	agentMCP = config.AgentMCP{Listen: listen, Token: token}

	res := agentMCPProbeResult{
		Config:  agentMCPConfigStateFrom(),
		Status:  agentMCPStatus{Addr: listen, Loopback: mcp.IsLoopbackAddr(listen), Depth: "shallow", Note: "已保存"},
		Clients: agentMCPClientsFor(listen, plaintextOnce),
	}
	agentReviewOK(w, "已保存到 afrog-config.yaml 的 agent.mcp；重启 `afrog mcp` 后生效", res)
}

// normalizeMCPAddr 把使用者可能输入的几种写法统一成 host:port。
//
// 接受 "127.0.0.1:16870"、"http://127.0.0.1:16870"、"http://127.0.0.1:16870/mcp"
// 等形态：去掉 scheme 与路径后只保留主机与端口。
func normalizeMCPAddr(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// probeMCPHealth 对 addr 的 /healthz 做一次浅检测。
//
//	200            -> running（这是一个 MCP 服务）
//	有响应但非 200 -> reachable（端口被别的服务占用）
//	连不上         -> 未侦测到
func probeMCPHealth(ctx context.Context, addr string) agentMCPStatus {
	st := agentMCPStatus{Addr: addr, Loopback: mcp.IsLoopbackAddr(addr)}

	ctx, cancel := context.WithTimeout(ctx, agentMCPProbeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/healthz", nil)
	if err != nil {
		st.Note = "地址不合法：" + err.Error()
		return st
	}

	start := time.Now()
	resp, err := agentMCPHTTPClient.Do(req)
	st.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		st.Note = "未侦测到服务，请确认已运行 `afrog mcp -listen " + addr + "`"
		return st
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))

	st.Reachable = true
	if resp.StatusCode == http.StatusOK {
		st.Running = true
		return st
	}
	st.Note = fmt.Sprintf("端口有响应但不是 MCP 服务（HTTP %d）", resp.StatusCode)
	return st
}

// probeMCPDeep 向 /mcp 发一次 initialize 握手，据响应区分：
//
//	200                  -> 运行中（token 有效，auth=ok）
//	401 / 403            -> 运行中但鉴权失败（auth=unauthorized）
//	连不上               -> 未侦测到
//	其它状态             -> 有响应但不是预期端点（auth=unknown）
//
// 注意：initialize 不是 tools/call，预期不会进入策略审计流水（审计只记工具调用）。
func probeMCPDeep(ctx context.Context, addr, token string) agentMCPStatus {
	st := agentMCPStatus{Addr: addr, Loopback: mcp.IsLoopbackAddr(addr), Depth: "deep"}

	ctx, cancel := context.WithTimeout(ctx, agentMCPDeepTimeout)
	defer cancel()

	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "afrog-web-console", "version": config.Version},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/mcp", bytes.NewReader(payload))
	if err != nil {
		st.Auth = "unknown"
		st.Note = "地址不合法：" + err.Error()
		return st
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	start := time.Now()
	resp, err := agentMCPHTTPClient.Do(req)
	st.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		st.Auth = "unknown"
		st.Note = "未侦测到服务，请确认已运行 `afrog mcp -listen " + addr + "`"
		return st
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<12))

	st.Reachable = true
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		st.Auth = "unauthorized"
		st.Note = "服务在运行，但 token 校验未通过（HTTP " + strconv.Itoa(resp.StatusCode) + "）"
	case resp.StatusCode == http.StatusOK:
		st.Running = true
		st.Auth = "ok"
	default:
		st.Auth = "unknown"
		st.Note = fmt.Sprintf("端口有响应但不是预期的 MCP 端点（HTTP %d）", resp.StatusCode)
	}
	return st
}

// agentMCPConfigStateFrom 组装配置区，token 以掩码回显。
func agentMCPConfigStateFrom() agentMCPConfigState {
	return agentMCPConfigState{
		Listen:           strings.TrimSpace(agentMCP.Listen),
		Token:            agentMCPMaskToken(agentMCP.Token),
		ConfigPath:       resolveClusterConfigPath(agentConfigPath),
		ManagedByConsole: false,
	}
}

// agentMCPClientsFor 按地址与 token 生成两段接入片段，供界面一键复制。
func agentMCPClientsFor(addr, token string) agentMCPClients {
	url := ""
	if addr != "" {
		url = "http://" + addr + "/mcp"
	}
	return agentMCPClients{
		Stdio: agentMCPStdioClient{Command: "afrog", Args: []string{"mcp"}},
		HTTP:  agentMCPHTTPClientSpec{URL: url, Token: token},
	}
}

// agentMCPMaskToken 对 token 做掩码回显：非空时统一显示固定长度圆点，连长度都不泄露。
func agentMCPMaskToken(token string) string {
	if strings.TrimSpace(token) == "" {
		return ""
	}
	return "••••••••"
}

// generateMCPToken 生成一个 48 位十六进制 token（24 字节随机数）。
func generateMCPToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
