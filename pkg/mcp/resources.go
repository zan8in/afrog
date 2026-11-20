package mcp

import (
	"context"
	"encoding/json"
	"strings"
)

// 只读资源：把既有的只读视图（服务状态、结论台账、控制面任务）按 URI 暴露出来，
// 让客户端能「读」而不必都走一次工具调用。
//
// 与工具的关系：资源不新增任何数据通路——读取时直接复用同名工具的 Handler，因而
// 门控、参数校验、返回结构只有一份实现。把 observe.findings 放进策略的 deny 列表，
// 同时也就挡住了 afrog://findings。
//
// 刻意不声明 subscribe：资源订阅是会话级状态，而本包的核心与传输无关（stdio 与
// HTTP 的会话模型并不相同），没有可挂订阅的地方。声明了却发不出
// notifications/resources/updated，比不声明更坏。
const (
	resourceStatusURI   = "afrog://status"
	resourceFindingsURI = "afrog://findings"
	resourceTasksURI    = "afrog://tasks"
	resourceTaskPrefix  = "afrog://tasks/"
)

// resourceList 返回 resources/list 的内容：URI 固定的那几个只读视图。
//
// 这里不枚举具体任务：列目录不该顺带拉起控制面（taskManager 会连带拉起子进程执行器）。
// 任务 id 从 afrog://tasks 的返回里取，再用资源模板读单个任务。
func (s *Server) resourceList() []map[string]any {
	return []map[string]any{
		{
			"uri":         resourceStatusURI,
			"name":        "服务状态",
			"description": "策略档位、剩余请求额度、作用域与版本；不发包也不扣额度。与 server.status 同源。",
			"mimeType":    "application/json",
		},
		{
			"uri":         resourceFindingsURI,
			"name":        "漏洞结论",
			"description": "本机漏洞结论台账的第一页（默认 50 条）。与 observe.findings 同源。",
			"mimeType":    "application/json",
		},
		{
			"uri":         resourceTasksURI,
			"name":        "任务列表",
			"description": "已受理的扫描/动作任务及状态、进度、命中数。与 task.list 同源。",
			"mimeType":    "application/json",
		},
	}
}

// resourceTemplates 返回 resources/templates/list 的内容：任务 id 事先不可枚举，
// 只能用模板让客户端按需拼 URI。
func (s *Server) resourceTemplates() []map[string]any {
	return []map[string]any{
		{
			"uriTemplate": resourceTaskPrefix + "{task_id}",
			"name":        "任务状态",
			"description": "单个任务的完整状态、进度与收尾汇总。与 task.status 同源。",
			"mimeType":    "application/json",
		},
		{
			"uriTemplate": resourceTaskPrefix + "{task_id}/events",
			"name":        "任务事件",
			"description": "单个任务的增量事件（默认从 seq 0 起拉一页）。与 task.events 同源。",
			"mimeType":    "application/json",
		},
	}
}

// resourceRead 处理 resources/read：URI 未知报「找不到」（-32002），工具侧失败（门控
// 拒绝、任务不存在等）报内部错误——两者混为一谈会让调用方分不清「没有这个资源」
// 与「不允许/暂时取不到」。
func (s *Server) resourceRead(ctx context.Context, req *request) (*response, bool) {
	fail := func(code int, msg string) (*response, bool) {
		return &response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: code, Message: msg}}, false
	}

	var p struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return fail(codeInvalidParams, "invalid params")
	}

	uri := strings.TrimSpace(p.URI)
	toolName, toolArgs, ok := resourceTarget(uri)
	if !ok {
		return fail(codeResourceNotFound, "unknown resource: "+uri)
	}
	tool, ok := s.tools[toolName]
	if !ok {
		return fail(codeResourceNotFound, "resource is not available: "+uri)
	}

	args, err := json.Marshal(toolArgs)
	if err != nil {
		return fail(codeInternalError, err.Error())
	}
	// 复用工具自己的 Handler：门控、参数校验、返回结构都只有一份实现。
	v, err := tool.Handler(ctx, args)
	if err != nil {
		return fail(codeInternalError, err.Error())
	}
	body, err := json.Marshal(v)
	if err != nil {
		return fail(codeInternalError, err.Error())
	}
	return s.ok(req.ID, map[string]any{"contents": []map[string]any{{
		"uri":      uri,
		"mimeType": "application/json",
		"text":     string(body),
	}}}), false
}

// resourceTarget 把资源 URI 映射成「哪个工具 + 什么参数」，false 表示 URI 未知。
func resourceTarget(uri string) (string, map[string]any, bool) {
	switch {
	case uri == resourceStatusURI:
		return "server.status", map[string]any{}, true
	case uri == resourceFindingsURI:
		return "observe.findings", map[string]any{}, true
	case uri == resourceTasksURI:
		return "task.list", map[string]any{}, true
	case strings.HasPrefix(uri, resourceTaskPrefix):
		// task_id 里不含 "/"：含则说明 URI 拼错了，不要拿它去查库。
		id, isEvents := strings.CutSuffix(strings.TrimPrefix(uri, resourceTaskPrefix), "/events")
		if strings.TrimSpace(id) == "" || strings.Contains(id, "/") {
			return "", nil, false
		}
		if isEvents {
			return "task.events", map[string]any{"task_id": id}, true
		}
		return "task.status", map[string]any{"task_id": id}, true
	}
	return "", nil, false
}
