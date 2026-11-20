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
// 资源订阅（resources/subscribe）是会话级状态：客户端订阅后，服务端要在「没有调用在途」
// 的时刻也能把变更推出去——长任务收尾正是这种时刻，而它跟任何一次调用都不重叠。
// 因此订阅表按会话登记，推送通道也按会话登记：通道由传输层在会话建立时提供
// （见 RegisterResourcePush），stdio / SSE / Streamable HTTP 各自把自己的通道交出来。
//
// 没有通道的会话照常接受订阅，只是变更推不出去——与进度、日志一样是可选的增强，
// 客户端仍可随时重读一次资源。会话结束时传输层注销通道，订阅随之清掉。
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

// RegisterResourcePush 由传输层登记某会话的服务端通知通道，返回注销函数。
//
// 注销时连该会话的订阅一起清掉：会话都没了，它的订阅只会变成推不出去的垃圾。
// 资源订阅是会话级状态，而资源变更发生在调用之外（长任务收尾），所以通道必须挂在
// 会话上长期持有，而不是随某一次调用用完即弃——这正是各传输在会话建立时登记它的原因。
func (s *Server) RegisterResourcePush(session string, push notifyFunc) func() {
	s.resMu.Lock()
	if s.resPush == nil {
		s.resPush = make(map[string]notifyFunc)
	}
	s.resPush[session] = push
	s.resMu.Unlock()

	return func() {
		s.resMu.Lock()
		delete(s.resPush, session)
		delete(s.resSubs, session)
		s.resMu.Unlock()
	}
}

// notifyResourceUpdated 向订阅了这些 URI 的会话推送 notifications/resources/updated。
//
// 只推「被订阅的」URI：订阅的全部意义就是让客户端声明关心哪些资源，无差别推送等于
// 把订阅当摆设。推送在锁外进行——它可能阻塞（客户端读得慢），不能拿会话锁陪着等。
func (s *Server) notifyResourceUpdated(uris ...string) {
	type target struct {
		push notifyFunc
		uri  string
	}
	var targets []target

	s.resMu.Lock()
	for session, subs := range s.resSubs {
		for _, uri := range uris {
			if _, ok := subs[uri]; ok {
				targets = append(targets, target{push: s.resPush[session], uri: uri})
			}
		}
	}
	s.resMu.Unlock()

	for _, t := range targets {
		if t.push == nil {
			continue
		}
		t.push("notifications/resources/updated", map[string]any{"uri": t.uri})
	}
}

// resourceSubscribe 处理 resources/subscribe：把 URI 记入本会话的订阅集合。
//
// 只校验 URI 的形状（见 resourceTarget），不校验资源是否已经存在——订阅
// afrog://tasks/{task_id} 时任务往往还没跑出来，那正是要等它变化的场景。
func (s *Server) resourceSubscribe(ctx context.Context, req *request) (*response, bool) {
	uri, invalid := s.resourceSubscriptionURI(req)
	if invalid != nil {
		return invalid, false
	}

	session := sessionFrom(ctx)
	s.resMu.Lock()
	if s.resSubs == nil {
		s.resSubs = make(map[string]map[string]struct{})
	}
	subs := s.resSubs[session]
	if subs == nil {
		subs = make(map[string]struct{})
		s.resSubs[session] = subs
	}
	subs[uri] = struct{}{}
	s.resMu.Unlock()

	return s.ok(req.ID, map[string]any{}), false
}

// resourceUnsubscribe 处理 resources/unsubscribe：退订一个从未订阅的 URI 也算成功，
// 退订的语义是「此后别再推」，而不是「必须曾经订阅过」。
func (s *Server) resourceUnsubscribe(ctx context.Context, req *request) (*response, bool) {
	uri, invalid := s.resourceSubscriptionURI(req)
	if invalid != nil {
		return invalid, false
	}

	session := sessionFrom(ctx)
	s.resMu.Lock()
	if subs := s.resSubs[session]; subs != nil {
		delete(subs, uri)
		if len(subs) == 0 {
			delete(s.resSubs, session)
		}
	}
	s.resMu.Unlock()

	return s.ok(req.ID, map[string]any{}), false
}

// resourceSubscriptionURI 解析并校验 subscribe / unsubscribe 的 uri 参数：
// 参数本身不合法报 -32602，URI 不是本服务的资源报 -32002（与 resources/read 一致）。
func (s *Server) resourceSubscriptionURI(req *request) (string, *response) {
	var p struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return "", &response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{
			Code: codeInvalidParams, Message: "invalid params",
		}}
	}
	uri := strings.TrimSpace(p.URI)
	if _, _, ok := resourceTarget(uri); !ok {
		return "", &response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{
			Code: codeResourceNotFound, Message: "unknown resource: " + uri,
		}}
	}
	return uri, nil
}
