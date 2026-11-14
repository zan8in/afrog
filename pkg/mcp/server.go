// Package mcp 把 afrog 的观测、探测与验证能力暴露成 MCP 工具。
//
// 边界：本包只做协议翻译与策略门控，不实现任何检测逻辑。真正发包、判定、
// 出证据的仍然是 pkg/sdk、pkg/runner 与 pkg/db/sqlite。
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/zan8in/afrog/v3/pkg/policy"
	"github.com/zan8in/afrog/v3/pkg/webscan"
)

// ProtocolVersion 是默认协商的 MCP 协议版本。
const ProtocolVersion = "2025-06-18"

// ServerInfo 是 tools/list 与 initialize 里回显的服务信息。
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Options 配置 MCP 服务。
type Options struct {
	Policy  *policy.Policy
	Budget  *policy.Budget
	Auditor *policy.Auditor
	Info    ServerInfo
}

// Tool 是一个可调用的 MCP 工具。
type Tool struct {
	Name        string
	Description string
	InputSchema any
	// Handler 返回可 JSON 序列化的结果；错误会以工具错误（isError）回给调用方。
	Handler func(ctx context.Context, args json.RawMessage) (any, error)
}

// ToolSpec 是工具的对外描述，供 tools/list 与其它传输（gRPC AgentService/ListTools）复用，
// 保证「工具清单」只有一份来源。
type ToolSpec struct {
	Name        string
	Description string
	InputSchema any
}

// Server 是工具面的核心：持有工具注册表与策略门控，本身与传输无关。
//
// MCP（stdio / SSE / streamable）只是它的一种适配器；REST 等其它传输通过
// Call 复用同一份工具与门控，避免每接一种传输就把策略、预算、审计重写一遍。
type Server struct {
	gate  *policy.Gate
	info  ServerInfo
	tools map[string]*Tool

	// verifyMu 串行化验证类工具：SDK 内部有进程级全局状态，不支持并行扫描。
	verifyMu sync.Mutex

	// webscanOnce/webscanMatcher 缓存内置 Web 指纹规则：规则集是只读的，
	// 每次调用都重新解析只会白白拖慢探测。
	webscanOnce    sync.Once
	webscanMatcher *webscan.Matcher
	webscanErr     error
}

// New 创建服务端并注册内置工具。
func New(opts Options) *Server {
	p := opts.Policy
	if p == nil {
		p = policy.Default()
	}
	b := opts.Budget
	if b == nil {
		b = policy.NewBudget(p.Limits, nowFunc())
	}
	info := opts.Info
	if info.Name == "" {
		info.Name = "afrog"
	}

	s := &Server{gate: policy.NewGate(p, b, opts.Auditor), info: info}
	s.tools = s.buildTools()
	return s
}

// NewWithPaths 按策略 YAML 与审计 JSONL 路径装配工具面，供 MCP 之外的传输适配层
// （REST `/api/v1/call`、gRPC `AgentService`）复用同一套装配口径。
//
// 两者都留空即沿用只读默认策略、不落盘审计：Web 服务与 `afrog serve` 因此默认
// 不获得发包能力。策略文件格式与 `afrog mcp -policy` 完全一致。
func NewWithPaths(policyPath, auditPath string, info ServerInfo) (*Server, error) {
	p := policy.Default()
	if strings.TrimSpace(policyPath) != "" {
		loaded, err := policy.Load(policyPath)
		if err != nil {
			return nil, err
		}
		p = loaded
	}
	var auditor *policy.Auditor
	if strings.TrimSpace(auditPath) != "" {
		auditor = policy.NewAuditor(FileAuditWriter{Path: auditPath})
	}
	return New(Options{Policy: p, Auditor: auditor, Info: info}), nil
}

// FileAuditWriter 每次写入都重新打开文件：不持有长驻句柄，日志轮转/删除后能自动重建。
type FileAuditWriter struct{ Path string }

func (w FileAuditWriter) Write(p []byte) (int, error) {
	f, err := os.OpenFile(w.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.Write(p)
}

// ToolNames 返回已注册的工具名，便于测试与自检。
func (s *Server) ToolNames() []string {
	out := make([]string, 0, len(s.tools))
	for name := range s.tools {
		out = append(out, name)
	}
	return out
}

// Specs 返回全部工具的描述（名称、说明、入参 schema），顺序与 toolList 一致。
// tools/list 与其它传输的「列出工具」都从这里取，避免清单出现两份。
func (s *Server) Specs() []ToolSpec {
	out := make([]ToolSpec, 0, len(s.tools))
	for _, t := range s.tools {
		out = append(out, ToolSpec{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
	}
	return out
}

// --- JSON-RPC 传输层 ---

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

// Serve 在给定的读写流上跑 MCP 主循环，直到输入结束。
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	enc := json.NewEncoder(out)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			if err := enc.Encode(response{JSONRPC: "2.0", Error: &rpcError{Code: codeParseError, Message: "parse error"}}); err != nil {
				return err
			}
			continue
		}

		resp, notify := s.handle(ctx, &req)
		if notify {
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func (s *Server) handle(ctx context.Context, req *request) (*response, bool) {
	// 没有 id 的是通知（如 notifications/initialized），按协议不回复。
	notification := len(req.ID) == 0

	switch req.Method {
	case "initialize":
		return s.ok(req.ID, s.initializeResult(req.Params)), false
	case "ping":
		return s.ok(req.ID, map[string]any{}), false
	case "tools/list":
		return s.ok(req.ID, map[string]any{"tools": s.toolList()}), false
	case "tools/call":
		return s.callTool(ctx, req)
	case "notifications/initialized", "notifications/cancelled":
		return nil, true
	default:
		if notification {
			return nil, true
		}
		return &response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{
			Code:    codeMethodNotFound,
			Message: fmt.Sprintf("method not found: %s", req.Method),
		}}, false
	}
}

func (s *Server) initializeResult(params json.RawMessage) map[string]any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	version := p.ProtocolVersion
	if version == "" {
		version = ProtocolVersion
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
		"serverInfo": s.info,
	}
}

func (s *Server) toolList() []map[string]any {
	specs := s.Specs()
	out := make([]map[string]any, 0, len(specs))
	for _, t := range specs {
		out = append(out, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
		})
	}
	return out
}

func (s *Server) callTool(ctx context.Context, req *request) (*response, bool) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{
			Code: codeInvalidParams, Message: "invalid params",
		}}, false
	}

	tool, ok := s.tools[params.Name]
	if !ok {
		return &response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{
			Code: codeMethodNotFound, Message: "unknown tool: " + params.Name,
		}}, false
	}

	result, err := tool.Handler(ctx, params.Arguments)
	if err != nil {
		return s.ok(req.ID, toolError(err)), false
	}
	return s.ok(req.ID, toolContent(result)), false
}

func (s *Server) ok(id json.RawMessage, result any) *response {
	return &response{JSONRPC: "2.0", ID: id, Result: result}
}

func toolError(err error) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": err.Error()}},
		"isError": true,
	}
}

func toolContent(v any) map[string]any {
	var text string
	switch t := v.(type) {
	case string:
		text = t
	default:
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return toolError(err)
		}
		text = string(b)
	}
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
	}
}

// Call 以编程方式调用一个工具，供 MCP 之外的传输（如 REST）复用同一套工具面
// 与策略门控：策略、预算、审计都在工具处理器内部统一执行，调用方无需重复实现。
func (s *Server) Call(ctx context.Context, name string, args json.RawMessage) (any, error) {
	tool, ok := s.tools[name]
	if !ok {
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	return tool.Handler(ctx, args)
}
