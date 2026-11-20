package mcp

import (
	"encoding/json"
	"sort"
	"strings"
)

// completion/complete 是 MCP 的参数自动补全：客户端在用户敲 prompt 参数或资源模板变量
// 时来问「这个位置有哪些可选值」，好把建议摆进下拉框。
//
// 只补本服务真的知道取值空间的字段，其余一律返回空列表。补全只是省事，编出来的候选会
// 直接把用户带偏，比没有补全更糟。当前能补的只有两类：
//
//   - task_id：已受理任务的 id（prompt follow-task、资源模板 afrog://tasks/{task_id}）；
//   - severity：info/low/medium/high/critical（prompt triage-findings）。
//
// 注意方法名是单数的 completion/complete，而能力位是复数的 completions：这是协议自身
// 的不一致（见 2025-06-18 规范 server/utilities/completion），任一边写错客户端都调不通。
const completionsMax = 100

// completionComplete 处理 completion/complete。
//
// 校验松紧的口径：协议明确要求「prompt 名不存在」报 -32602，照办（写错名字是客户端
// 的问题，早点报出来好排查）；而「参数名没声明过」「资源模板不认识」只是补不出建议，
// 返回空列表即可——不该因为用户多问一句就把整条补全链路变成错误。
func (s *Server) completionComplete(req *request) (*response, bool) {
	fail := func(code int, msg string) (*response, bool) {
		return &response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: code, Message: msg}}, false
	}

	var p struct {
		Ref struct {
			Type string `json:"type"`
			Name string `json:"name"`
			URI  string `json:"uri"`
		} `json:"ref"`
		Argument struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"argument"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return fail(codeInvalidParams, "invalid params")
	}
	arg := strings.TrimSpace(p.Argument.Name)
	if arg == "" {
		return fail(codeInvalidParams, "missing argument name")
	}

	var candidates []string
	switch p.Ref.Type {
	case "ref/prompt":
		def, ok := s.promptDefByName(p.Ref.Name)
		if !ok {
			return fail(codeInvalidParams, "unknown prompt: "+p.Ref.Name)
		}
		if declaresArg(def, arg) {
			candidates = s.completionCandidates(arg)
		}
	case "ref/resource":
		if s.isResourceTemplate(p.Ref.URI) {
			candidates = s.completionCandidates(arg)
		}
	default:
		return fail(codeInvalidParams, "unsupported ref type: "+p.Ref.Type)
	}

	return s.ok(req.ID, completionResult(candidates, p.Argument.Value)), false
}

// completionCandidates 返回某个参数名的候选值；参数名不认识就返回 nil（没人可补）。
func (s *Server) completionCandidates(arg string) []string {
	switch arg {
	case "task_id":
		mgr := s.readyTaskManager()
		if mgr == nil {
			return nil
		}
		snaps := mgr.List()
		ids := make([]string, 0, len(snaps))
		for _, snap := range snaps {
			ids = append(ids, snap.ID)
		}
		// 任务表按受理顺序排列，补全按字典序更稳定：用户第二次看到的下拉顺序不该变。
		sort.Strings(ids)
		return ids
	case "severity":
		return []string{"info", "low", "medium", "high", "critical"}
	}
	return nil
}

// completionResult 按已输入的值过滤候选（前缀匹配，不区分大小写），并连同「总命中数」
// 与「是否还有更多」一起返回。value 为空表示还没输入，即返回全部候选的开头一批。
func completionResult(candidates []string, value string) map[string]any {
	prefix := strings.ToLower(strings.TrimSpace(value))
	values := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if prefix == "" || strings.HasPrefix(strings.ToLower(c), prefix) {
			values = append(values, c)
		}
	}

	total := len(values)
	hasMore := total > completionsMax
	if hasMore {
		values = values[:completionsMax]
	}
	return map[string]any{"completion": map[string]any{
		"values":  values,
		"total":   total,
		"hasMore": hasMore,
	}}
}

// promptDefByName 按名字取 prompt 定义；false 表示没这条 prompt。
func (s *Server) promptDefByName(name string) (promptDef, bool) {
	for _, d := range s.promptDefs() {
		if d.Name == name {
			return d, true
		}
	}
	return promptDef{}, false
}

// declaresArg 判断 prompt 是否声明了该参数：只有声明过的参数才谈得上「建议值」。
func declaresArg(d promptDef, name string) bool {
	for _, a := range d.Arguments {
		if a.Name == name {
			return true
		}
	}
	return false
}

// isResourceTemplate 判断 uri 是否为本服务声明的资源模板（resources/templates/list 里那些）。
func (s *Server) isResourceTemplate(uri string) bool {
	for _, t := range s.resourceTemplates() {
		if t["uriTemplate"] == uri {
			return true
		}
	}
	return false
}
