package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// prompts 是 MCP 里「用户可选的入口」：客户端把每条 prompt 呈现成一个斜杠命令，参数由
// 用户填，服务端只负责把模板渲染成一条 user 消息。
//
// 它们把 Instructions 里那套流程固化成可点的模板（并带上具体目标/任务 id），但不改变
// 任何门控——是否放行仍由策略与预算决定。
type promptDef struct {
	Name        string
	Title       string
	Description string
	Arguments   []promptArg
	// Render 按参数生成给模型的消息正文。
	Render func(args map[string]string) string
}

type promptArg struct {
	Name        string
	Description string
	Required    bool
}

// promptDefs 是所有内置 prompt。它是 prompts/list 与 prompts/get 的唯一来源。
func (s *Server) promptDefs() []promptDef {
	return []promptDef{
		{
			Name:        "scan-target",
			Title:       "扫描目标",
			Description: "对单个目标跑一遍「指纹 → PoC 预检 → 一次并发扫描 → 判读结论」。",
			Arguments: []promptArg{
				{Name: "target", Description: "目标 URL 或主机，例如 http://10.0.0.5:8080", Required: true},
				{Name: "project_id", Description: "结论归入的项目 ID；留空为默认项目"},
			},
			Render: func(a map[string]string) string {
				target := strings.TrimSpace(a["target"])
				var b strings.Builder
				fmt.Fprintf(&b, "用 afrog 扫描目标 %s。按这个顺序做：\n\n", target)
				b.WriteString("1. server.status —— 先确认档位（readonly/safe/full）与剩余额度；额度不足就别开工。\n")
				fmt.Fprintf(&b, "2. probe.fingerprint %s —— 拿技术栈；返回体里的 suggested_search 原样透传给下一步。\n", target)
				b.WriteString("3. poc.search <suggested_search> —— 预检本机有没有对应技术栈的 PoC。不要自己把技术栈映射成关键词：曾出现识别出 jQuery、却去搜 wordpress,nginx 之类根本没识别到的产品。\n")
				fmt.Fprintf(&b, "4. scan.start %s + 第 3 步的 keywords —— 一次并发跑完，不要把一个 PoC 拆成多次串行验证。\n", target)
				b.WriteString("5. observe.findings / plan.next —— 确认扫出的结论，并看服务端给出的下一步。\n\n")
				b.WriteString("长任务注意：scan.start 在短等窗口（默认 30 秒）内跑完会直接返回完整结果，否则返回 task_id 句柄（conclusion 为 pending）。pending 不等于「没有漏洞」，用 task.status / task.events 跟到 completed 再下结论；task.events 返回的 last_seq 原样作为下次的 from_seq。\n")
				if pid := strings.TrimSpace(a["project_id"]); pid != "" {
					fmt.Fprintf(&b, "本次结论归入项目 %s。\n", pid)
				}
				return b.String()
			},
		},
		{
			Name:        "triage-findings",
			Title:       "判读结论",
			Description: "判读已扫出的漏洞结论：读台账 → 取证据 → 需要时复测 → 落库研判意见。",
			Arguments: []promptArg{
				{Name: "project_id", Description: "只看某个项目；留空为全局"},
				{Name: "severity", Description: "只看某个级别（info/low/medium/high/critical）；留空为全部"},
			},
			Render: func(a map[string]string) string {
				var b strings.Builder
				b.WriteString("判读 afrog 已扫出的漏洞结论。步骤：\n\n")
				if pid := strings.TrimSpace(a["project_id"]); pid != "" {
					fmt.Fprintf(&b, "1. observe.findings project_id=%s", pid)
				} else {
					b.WriteString("1. observe.findings")
				}
				if sev := strings.TrimSpace(a["severity"]); sev != "" {
					fmt.Fprintf(&b, " severity=%s", sev)
				}
				b.WriteString(" —— 列出台账。\n")
				b.WriteString("2. 对带 evidence[] 的结论用 observe.evidence <evd_ id> 取回可重放证据；取不到证据说明是旧命中，属预期行为。\n")
				b.WriteString("3. 需要复测时把证据交给 verify.replay（单 PoC 短任务，会一直等到跑完，后处理依赖跑完的结果）。\n")
				b.WriteString("4. 判读意见用 judge.brief 看、用 judge.record 落库。\n\n")
				b.WriteString("判读以证据为准，不要凭标题或级别猜：返回为空只说明本机没有这类数据，不代表目标没有漏洞。\n")
				return b.String()
			},
		},
		{
			Name:        "follow-task",
			Title:       "跟踪长任务",
			Description: "跟踪一个 task_id：查状态与汇总、按 last_seq 增量拉事件、必要时取消/暂停。",
			Arguments: []promptArg{
				{Name: "task_id", Description: "scan.start / act.brute 返回的 task_id", Required: true},
			},
			Render: func(a map[string]string) string {
				id := strings.TrimSpace(a["task_id"])
				var b strings.Builder
				fmt.Fprintf(&b, "跟踪 afrog 长任务 %s：\n\n", id)
				fmt.Fprintf(&b, "1. task.status %s —— 看 status / progress / hit_total / summary；completed 之后 summary（executed/found/by_severity/elapsed_ms）就是最终结论。\n", id)
				fmt.Fprintf(&b, "2. task.events %s —— 按 from_seq 增量拉事件；把返回的 last_seq 原样作为下次的 from_seq，即可不重不漏。\n", id)
				fmt.Fprintf(&b, "3. 需要中断或让出额度时用 task.control %s 取消 / 暂停 / 恢复。\n\n", id)
				b.WriteString("注意：status 还是 queued/running 时不要下「没有漏洞」的结论；failed / timeout 要先读 error 字段找原因，不要直接重跑。\n")
				return b.String()
			},
		},
	}
}

// promptList 把 prompt 定义渲染成 prompts/list 的条目。
func (s *Server) promptList() []map[string]any {
	defs := s.promptDefs()
	out := make([]map[string]any, 0, len(defs))
	for _, d := range defs {
		args := make([]map[string]any, 0, len(d.Arguments))
		for _, a := range d.Arguments {
			args = append(args, map[string]any{
				"name":        a.Name,
				"description": a.Description,
				"required":    a.Required,
			})
		}
		out = append(out, map[string]any{
			"name":        d.Name,
			"title":       d.Title,
			"description": d.Description,
			"arguments":   args,
		})
	}
	return out
}

// promptGet 处理 prompts/get：按名字取模板、校验必填参数，再渲染成一条 user 消息。
func (s *Server) promptGet(req *request) (*response, bool) {
	fail := func(code int, msg string) (*response, bool) {
		return &response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: code, Message: msg}}, false
	}

	var p struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return fail(codeInvalidParams, "invalid params")
	}

	for _, d := range s.promptDefs() {
		if d.Name != p.Name {
			continue
		}
		// 必填参数缺失要在渲染前挡住：模板里少一个目标，模型只会拿到一句
		// 「扫描目标 」，然后回头猜——不如直接报错。
		for _, a := range d.Arguments {
			if a.Required && strings.TrimSpace(p.Arguments[a.Name]) == "" {
				return fail(codeInvalidParams, "missing required argument: "+a.Name)
			}
		}
		return s.ok(req.ID, map[string]any{
			"description": d.Description,
			"messages": []map[string]any{{
				"role":    "user",
				"content": map[string]any{"type": "text", "text": d.Render(p.Arguments)},
			}},
		}), false
	}
	return fail(codeInvalidParams, "unknown prompt: "+p.Name)
}
