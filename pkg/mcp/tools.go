package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/zan8in/afrog/v3/pkg/agentapi"
	"github.com/zan8in/afrog/v3/pkg/assetgraph"
	"github.com/zan8in/afrog/v3/pkg/capability"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/drafter"
	"github.com/zan8in/afrog/v3/pkg/evidence"
	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/judge"
	"github.com/zan8in/afrog/v3/pkg/learner"
	"github.com/zan8in/afrog/v3/pkg/observation"
	"github.com/zan8in/afrog/v3/pkg/planner"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/policy"
	"github.com/zan8in/afrog/v3/pkg/portscan"
	"github.com/zan8in/afrog/v3/pkg/webscan"
	"gopkg.in/yaml.v2"
)

// 证据与响应正文统一在这里截断：MCP 的响应会被客户端整段读进上下文，
// 不适合塞进整包大响应。
const (
	toolBodyLimit   = 32 * 1024
	toolHeaderLimit = 8 * 1024

	// 单次验证的请求预算：能解析出 PoC 时按规则数/暴力组合数估算，
	// 解析失败或纯脚本 PoC 则退回保守的固定值。
	defaultVerifyReserve = 10
	maxVerifyReserve     = 500
)

var nowFunc = time.Now

func (s *Server) buildTools() map[string]*Tool {
	tools := []*Tool{
		s.serverStatusTool(),
		s.observeFindingsTool(),
		s.observeEvidenceTool(),
		s.observeStateTool(),
		s.observeObservationsTool(),
		s.planNextTool(),
		s.pocSearchTool(),
		s.pocDraftTool(),
		s.pocSubmitTool(),
		s.probeHTTPTool(),
		s.probePortTool(),
		s.probeFingerprintTool(),
		s.scanStartTool(),
		s.verifyReplayTool(),
		s.actBruteTool(),
		s.actOOBPayloadTool(),
		s.actOOBWaitTool(),
		s.judgeBriefTool(),
		s.judgeRecordTool(),
		s.learnBriefTool(),
		s.learnRecordTool(),
	}
	out := make(map[string]*Tool, len(tools))
	for _, t := range tools {
		out[t.Name] = t
	}
	return out
}

// --- server.status ---

func (s *Server) serverStatusTool() *Tool {
	return &Tool{
		Name:        "server.status",
		Title:       "查看服务状态",
		Description: "只读：返回本次会话的策略档位、剩余请求额度与空闲到期时间、作用域白/黑名单，以及服务与协议版本。它不发包也不扣额度。挑 PoC 前想确认「现在什么档位、还能发多少包」，或想知道某主机在不在作用域内，先调它——比撞上 403 / 429 再回头猜要省事。",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
			"required":   []string{},
		},
		OutputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"server": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name":    map[string]any{"type": "string"},
						"version": map[string]any{"type": "string"},
					},
				},
				"protocol_version": map[string]any{"type": "string", "description": "本服务默认协商到的 MCP 协议版本"},
				"policy": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"mode":        map[string]any{"type": "string", "enum": []string{"readonly", "safe", "full"}},
						"destructive": map[string]any{"type": "boolean", "description": "是否允许破坏性动作"},
						"audit":       map[string]any{"type": "boolean", "description": "是否为每次判定落审计"},
						"allow":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "白名单动作模式；为空表示不按名单限制"},
						"deny":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "黑名单动作模式；命中即拒"},
						"scope": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"allow_hosts": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
								"deny_hosts":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
								"deny_paths":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
							},
						},
					},
				},
				"budget": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"requests_remaining":  map[string]any{"type": "integer", "description": "本会话可用的剩余请求数；-1 表示不限"},
						"requests_limit":      map[string]any{"type": "integer", "description": "本会话的请求额度上限"},
						"idle_window_seconds": map[string]any{"type": "integer", "description": "空闲窗口长度（秒）；0 表示不限时"},
						"expires_at":          map[string]any{"type": "string", "description": "空闲到期时间（RFC3339）；空表示不限时。到时仍未再发包即视作开新会话、额度补满"},
					},
				},
			},
		},
		Handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			if err := s.gate.Take(policy.Action{Name: "server.status"}, 0); err != nil {
				return nil, err
			}
			p := s.gate.Policy()
			b := s.gate.Budget()

			expiresAt := ""
			if d := b.Deadline(); !d.IsZero() {
				expiresAt = d.UTC().Format(time.RFC3339)
			}
			// nil 切片会被序列化成 null；统一成空数组，让 schema 里的 array 名副其实。
			list := func(v []string) []string {
				if v == nil {
					return []string{}
				}
				return v
			}

			return map[string]any{
				"server": map[string]any{
					"name":    s.info.Name,
					"version": s.info.Version,
				},
				"protocol_version": ProtocolVersion,
				"policy": map[string]any{
					"mode":        string(p.Mode),
					"destructive": p.Destructive,
					"audit":       p.Audit,
					"allow":       list(p.Allow),
					"deny":        list(p.Deny),
					"scope": map[string]any{
						"allow_hosts": list(p.Scope.AllowHosts),
						"deny_hosts":  list(p.Scope.DenyHosts),
						"deny_paths":  list(p.Scope.DenyPaths),
					},
				},
				"budget": map[string]any{
					"requests_remaining":  b.Remaining(),
					"requests_limit":      p.Limits.Requests,
					"idle_window_seconds": int(p.Limits.Duration.Duration() / time.Second),
					"expires_at":          expiresAt,
				},
			}, nil
		},
	}
}

// --- observe.findings ---

func (s *Server) observeFindingsTool() *Tool {
	type args struct {
		ProjectID string   `json:"project_id"`
		Status    []string `json:"status"`
		Severity  []string `json:"severity"`
		Keyword   string   `json:"keyword"`
		Page      int      `json:"page"`
		Limit     int      `json:"limit"`
	}
	return &Tool{
		Name:        "observe.findings",
		Title:       "列出漏洞结论",
		Description: "按项目、状态、严重级别列出漏洞结论（Finding）：同一主体上的同一类漏洞聚合为一条，带内容寻址 id 与证据引用（evidence[]）。想知道「已经扫出什么」时先调它；返回为空只说明本地还没有这类数据，不代表目标没有漏洞。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"project_id": map[string]any{"type": "string", "description": "项目 ID；留空表示全局"},
				"status":     map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": []string{"pending", "confirmed", "false_positive", "fixed"}}, "description": "台账状态；留空为全部"},
				"severity":   map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": []string{"info", "low", "medium", "high", "critical"}}, "description": "严重级别；留空为全部"},
				"keyword":    map[string]any{"type": "string", "description": "按目标 / 标题模糊匹配"},
				"page":       map[string]any{"type": "integer", "minimum": 1, "description": "页码，默认 1"},
				"limit":      map[string]any{"type": "integer", "minimum": 1, "maximum": 200, "description": "每页条数，默认 50"},
			},
			"required": []string{},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			if err := s.gate.Take(policy.Action{Name: "observe.findings"}, 0); err != nil {
				return nil, err
			}

			page := a.Page
			if page <= 0 {
				page = 1
			}
			limit := a.Limit
			if limit <= 0 {
				limit = 50
			}
			if limit > 200 {
				limit = 200
			}

			result, err := agentapi.Findings(sqlite.LedgerFilter{
				Status:   a.Status,
				Severity: a.Severity,
				Project:  a.ProjectID,
				Keyword:  a.Keyword,
				Page:     page,
				PageSize: limit,
			})
			if err != nil {
				return nil, err
			}
			return result, nil
		},
	}
}

// --- observe.evidence ---

func (s *Server) observeEvidenceTool() *Tool {
	type args struct {
		ID string `json:"id"`
	}
	return &Tool{
		Name:        "observe.evidence",
		Title:       "取证据",
		Description: "按 result 主键或证据内容寻址 ID（evd_ 前缀）取一条可重放证据。拿到的 evd_ id 可原样交给 verify.replay 复测；没有证据的旧命中原样返回未找到，属预期行为。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id": map[string]any{"type": "string", "description": "result id 或 evd_ 开头的证据 id"},
			},
			"required": []string{"id"},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			id := strings.TrimSpace(a.ID)
			if id == "" {
				return nil, fmt.Errorf("id is required")
			}
			if err := s.gate.Take(policy.Action{Name: "observe.evidence"}, 0); err != nil {
				return nil, err
			}

			ev, err := agentapi.Evidence(id)
			if err != nil {
				return nil, err
			}
			if ev == nil {
				return nil, fmt.Errorf("evidence not found for %q (ids come from observe.findings evidence[] or a result id; evidence is only stored for PoCs that actually fired)", id)
			}
			return ev, nil
		},
	}
}

// --- observe.state ---

func (s *Server) observeStateTool() *Tool {
	type args struct {
		Subject   string `json:"subject"`
		ProjectID string `json:"project_id"`
		Depth     int    `json:"depth"`
		Direction string `json:"direction"`
	}
	return &Tool{
		Name:        "observe.state",
		Title:       "读攻击面子图",
		Description: "以某个资产（id 或地址）为根，返回攻击面子图：上下游资产、端点与参数、技术栈与候选 PoC（tech:/poc: 派生节点）、被动覆盖与命中数。tech: 节点就是技术栈，可把它的关键词交给 poc.search 找同族 PoC；poc: 节点是已给出的候选。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"subject":    map[string]any{"type": "string", "description": "资产 id 或地址，例如 10.0.0.5、http://10.0.0.5:8080/api，或参数节点 http://10.0.0.5/api#query:id"},
				"project_id": map[string]any{"type": "string", "description": "按项目口径统计命中与覆盖；留空为全局"},
				"depth":      map[string]any{"type": "integer", "minimum": 1, "maximum": assetgraph.MaxDepth},
				"direction":  map[string]any{"type": "string", "enum": []string{"up", "down", "both"}, "description": "up=归属，down=穿透，默认 both"},
			},
			"required": []string{"subject"},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			subject := strings.TrimSpace(a.Subject)
			if subject == "" {
				return nil, fmt.Errorf("subject is required")
			}
			if err := s.gate.Take(policy.Action{Name: "observe.state", Target: subject}, 0); err != nil {
				return nil, err
			}
			return agentapi.State(subject, a.ProjectID, a.Depth, a.Direction)
		},
	}
}

// --- observe.observations ---

// observeObservationsTool 按 seq 游标增量拉取观测流。
//
// 与 findings/evidence 的分工：这里给的是「过程中看到了什么」，是 Agent 继续推理的
// 原料，不参与漏洞判定。零预算：只读本机库，不发任何请求。
func (s *Server) observeObservationsTool() *Tool {
	type args struct {
		SinceSeq     int64    `json:"since_seq"`
		Sources      []string `json:"sources"`
		Kinds        []string `json:"kinds"`
		Subject      string   `json:"subject"`
		SubjectUnder bool     `json:"subject_under"`
		ProjectID    string   `json:"project_id"`
		Limit        int      `json:"limit"`
	}
	return &Tool{
		Name:        "observe.observations",
		Title:       "拉观测流",
		Description: "按 seq 游标增量拉取观测流（开放端口 / Web 指纹 / HTTP 事务 / 被动代理流量 / TLS 证书 / 带外回连 / DNS 解析）。只读、零预算；next_seq 直接作为下次的 since_seq。需要「过程事实」而不只是结论时用它。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"since_seq": map[string]any{"type": "integer", "minimum": 0, "description": "只返回 seq 大于它的记录，默认 0"},
				"sources": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
					"description": "过滤 portscan/webscan/http/passive/oob"},
				"kinds": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
					"description": "过滤 port_open/tech/http_transaction/http_passive/tls/oob_hit/dns"},
				"subject":       map[string]any{"type": "string", "description": "只看某个归一化地址"},
				"subject_under": map[string]any{"type": "boolean", "description": "把 subject 当作子树根：主机含其端口，端点含其参数；默认精确匹配"},
				"project_id":    map[string]any{"type": "string", "description": "按项目口径过滤；留空为全局"},
				"limit":         map[string]any{"type": "integer", "minimum": 1, "maximum": 500},
			},
			"required": []string{},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			if err := s.gate.Take(policy.Action{Name: "observe.observations"}, 0); err != nil {
				return nil, err
			}
			return agentapi.Observations(sqlite.ObservationFilter{
				SinceSeq:     a.SinceSeq,
				Sources:      a.Sources,
				Kinds:        a.Kinds,
				Subject:      a.Subject,
				SubjectUnder: a.SubjectUnder,
				ProjectID:    a.ProjectID,
				Limit:        a.Limit,
			})
		},
	}
}

// --- plan.next ---

// planNextTool 把攻击面图压成一份有依据、可排序的 Action 提议列表。
//
// 只读、零预算：它只读图与既有结果行，不发包、不改任何状态。提议里的每一条都要由
// 调用方再走一次 verify.* / probe.* 的策略与预算门控才会真正执行——判定权留在
// 确定性引擎与 Evidence，规划器只回答「下一步试什么更划算」。
func (s *Server) planNextTool() *Tool {
	type args struct {
		ProjectID string `json:"project_id"`
		Subject   string `json:"subject"`
		Under     bool   `json:"subject_under"`
		Limit     int    `json:"limit"`
	}
	return &Tool{
		Name:        "plan.next",
		Title:       "提议下一步",
		Description: "给出下一步的 Action 提议（scan.start / probe.fingerprint），按确定性分数排序；候选与未知面都带依据。只读、零预算，执行仍需 scan.*/probe.* 过策略门控。不确定下一步做什么时调它；若 proposals 为空，说明该主体还没有可复现的候选（例如尚未探测过指纹或端点），此时先 probe.fingerprint / probe.http 补观测，或直接用 poc.search 检索 PoC，而不是就此停下。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"project_id":    map[string]any{"type": "string", "description": "按项目口径跳过已经出过结果的组合；留空为全局"},
				"subject":       map[string]any{"type": "string", "description": "限定范围的端点 URL，例如 http://10.0.0.5:8080；留空为全库"},
				"subject_under": map[string]any{"type": "boolean", "description": "把 subject 当作前缀：包含该主机下的所有端点；默认精确匹配"},
				"limit":         map[string]any{"type": "integer", "minimum": 1, "maximum": planner.MaxLimit, "description": "提议数上限，默认 20"},
			},
			"required": []string{},
		},
		OutputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"project_id": map[string]any{"type": "string"},
				"subject":    map[string]any{"type": "string"},
				"proposals": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"action": map[string]any{
								"type": "object",
								"properties": map[string]any{
									"name":   map[string]any{"type": "string", "description": "scan.start / probe.fingerprint"},
									"target": map[string]any{"type": "string"},
									"search": map[string]any{"type": "string", "description": "scan.start 的技术栈关键词；对 probe.fingerprint 为空"},
								},
							},
							"category":     map[string]any{"type": "string"},
							"score":        map[string]any{"type": "integer"},
							"severity":     map[string]any{"type": "string"},
							"requires_oob": map[string]any{"type": "boolean"},
							"rationale":    map[string]any{"type": "string"},
							"evidence":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
						},
					},
				},
				"truncated": map[string]any{"type": "boolean"},
				"excluded":  map[string]any{"type": "integer", "description": "已有结论、不再提议的数量"},
			},
			"required": []string{"proposals", "truncated", "excluded"},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			if err := s.gate.Take(policy.Action{Name: "plan.next", Target: a.Subject}, 0); err != nil {
				return nil, err
			}
			return agentapi.Plan(planner.Options{
				ProjectID: a.ProjectID,
				Subject:   a.Subject,
				Under:     a.Under,
				Limit:     a.Limit,
			})
		},
	}
}

// recordHTTPObservation 把一次 Agent 主动发起的 HTTP 往返写进观测流。
//
// 只记 Agent 触发的动作（probe.* / verify.*），全量扫描里每个 PoC 的请求不进流：
// 量级不可控，且其价值已经由 evidence 覆盖。
func recordHTTPObservation(pocID, method, url string, status int, matched bool, latencyMs int64, request, response string) {
	if strings.TrimSpace(url) == "" {
		return
	}
	// Agent 主动打过的端点也进资产图，observe.state 才能反映「已经看过的世界」。
	_ = sqlite.EnsureEndpointGraph(url, "")
	obs, err := observation.New("", observation.SourceHTTP, observation.KindHTTPTransaction,
		observation.EndpointSubject(url), observation.HTTPTransaction{
			Method:          strings.ToUpper(strings.TrimSpace(method)),
			URL:             url,
			Status:          status,
			Matched:         matched,
			LatencyMs:       latencyMs,
			RequestExcerpt:  observation.Excerpt(request, observation.ExcerptLimit()),
			ResponseExcerpt: observation.Excerpt(response, observation.ExcerptLimit()),
			PocID:           pocID,
		})
	if err != nil {
		return
	}
	sqlite.RecordObservation(obs)
}

// recordTechObservation 把一次 Web 指纹识别结果写进观测流。
func recordTechObservation(urlStr string, status int, title, server, poweredBy string, matched webscan.Result) {
	if strings.TrimSpace(urlStr) == "" {
		return
	}
	techs := make([]observation.Technology, 0, len(matched.Technologies))
	var waf, cdn []string
	for _, t := range matched.Technologies {
		techs = append(techs, observation.Technology{
			Name:       t.Name,
			Version:    t.Version,
			Category:   t.Category,
			Confidence: t.Confidence.String(),
		})
		switch strings.ToLower(t.Category) {
		case "waf":
			waf = append(waf, t.Name)
		case "cdn":
			cdn = append(cdn, t.Name)
		}
	}

	obs, err := observation.New("", observation.SourceWebscan, observation.KindTech,
		observation.EndpointSubject(urlStr), observation.Tech{
			URL:          urlStr,
			Status:       status,
			Title:        title,
			Server:       server,
			PoweredBy:    poweredBy,
			Technologies: techs,
			WAF:          waf,
			CDN:          cdn,
		})
	if err != nil {
		return
	}
	sqlite.RecordObservation(obs)
}

// describeRequest 生成请求片段：方法 + URL + 排序后的请求头，便于事后复核。
func describeRequest(method, target string, headers map[string]string) string {
	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteByte(' ')
	sb.WriteString(target)

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sb.WriteByte('\n')
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(headers[k])
	}
	return sb.String()
}

// describeResponse 生成响应片段：状态行 + 头 + 正文；正文由调用方按上限截断。
func describeResponse(resp *http.Response, body []byte) string {
	if resp == nil {
		return string(body)
	}
	var sb strings.Builder
	sb.WriteString(resp.Proto)
	sb.WriteByte(' ')
	sb.WriteString(strconv.Itoa(resp.StatusCode))
	sb.WriteByte(' ')
	sb.WriteString(http.StatusText(resp.StatusCode))

	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sb.WriteByte('\n')
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(strings.Join(resp.Header[k], ", "))
	}
	sb.WriteString("\n\n")
	sb.Write(body)
	return sb.String()
}

// --- poc.search ---
func (s *Server) pocSearchTool() *Tool {
	type args struct {
		Keyword  string   `json:"keyword"`
		Severity []string `json:"severity"`
		Limit    int      `json:"limit"`
	}
	return &Tool{
		Name:        "poc.search",
		Title:       "检索 PoC",
		Description: "按关键词与严重级别检索本机已有的 PoC，返回真实存在的 id、名称、级别与本地路径，并带 total（命中总数）与 truncated（是否被 limit 截断）。**它等价于 `afrog -pl -s <keyword>`：用来在扫描前预检「本机有没有这个技术栈的 PoC」——结果为空就别扫，说明 afrog 没有该指纹/产品的漏洞。** 关键词口径与 `-s` 完全一致：按逗号拆成多个词、任一命中 PoC 的 id/名称/标签即算命中（传 \"thinkphp,jquery\" 就是「thinkphp 或 jquery」）。选检口径按优先级：① 有指纹/产品线索时，keyword 用技术栈关键词（jquery、thinkphp、shiro）——这是命中率最高的方式，命中后把同一关键词交给 scan.start 并发扫描（probe.fingerprint 返回的 suggested_search 可直接透传）；② 还没有线索时先用 plan.next，它会按攻击面决定是先做 probe.fingerprint 还是直接给出候选关键词；③ severity 只是「按级别粗筛」的兜底手段，它与目标是否真的跑那个产品无关，别把它当默认策略——用户没有指定等级时留空即可。truncated=true 时应继续收窄条件。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"keyword":  map[string]any{"type": "string", "description": "匹配 id / 名称 / 标签 / requires（与 afrog -s 同一口径，逗号分隔即多关键词 OR）；首选指纹类关键词，如 jquery、thinkphp。requires 也纳入检索，可搜到「依赖该技术栈」的 PoC"},
				"severity": map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": []string{"info", "low", "medium", "high", "critical"}}, "description": "按级别粗筛；仅作兜底，不能替代按指纹检索"},
				"limit":    map[string]any{"type": "integer", "minimum": 1, "maximum": 200, "description": "返回条数上限，默认 50"},
			},
			"required": []string{},
		},
		OutputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"items": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"id":       map[string]any{"type": "string"},
							"name":     map[string]any{"type": "string"},
							"severity": map[string]any{"type": "string"},
							"tags":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
							"path":     map[string]any{"type": "string"},
							"source":   map[string]any{"type": "string"},
						},
					},
				},
				"count":     map[string]any{"type": "integer", "description": "本次返回条数"},
				"total":     map[string]any{"type": "integer", "description": "命中总数"},
				"truncated": map[string]any{"type": "boolean", "description": "命中数超过 limit 被截断"},
				"conclusion": map[string]any{"type": "string", "description": "has_poc（本机有该关键词的 PoC）/ no_poc_for_keyword（本机没有，别据此判定目标无漏洞）"},
				"guidance":   map[string]any{"type": "string", "description": "total 为 0 时给出的下一步建议"},
			},
			"required": []string{"items", "count", "total", "truncated"},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			if err := s.gate.Take(policy.Action{Name: "poc.search"}, 0); err != nil {
				return nil, err
			}

			res, err := agentapi.SearchPocs(a.Keyword, a.Severity, a.Limit)
			if err != nil {
				return nil, err
			}
			out := map[string]any{
				"items":     res.Items,
				"count":     res.Count,
				"total":     res.Total,
				"truncated": res.Truncated,
			}
			// 显式区分「本机没有该关键词的 PoC」与「有」：只有前者才需要把「不能据此判定
			// 无漏洞」讲清楚——否则模型会把「afrog 没有这个产品的 PoC」读成「目标安全」。
			if res.Total == 0 {
				out["conclusion"] = "no_poc_for_keyword"
				out["guidance"] = fmt.Sprintf("本机 PoC 库里没有与关键词 %q 匹配的 PoC——说明 afrog 暂无该技术栈/产品的检测能力，**不能据此判定目标无漏洞**。可换更通用的关键词，或征得用户同意后用空 search 让 scan.start 跑全库。", strings.TrimSpace(a.Keyword))
			} else {
				out["conclusion"] = "has_poc"
			}
			return out, nil
		},
	}
}

// --- poc.draft ---

// draftIDRe 限定草稿 id：id 会直接成为落盘文件名，必须挡住 ../ 之类的路径穿越。
var draftIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// pocDraftTool 校验模型产出的 PoC 草稿，不发包。
//
// 分工：草稿由模型写，afrog 只负责结构校验、能力等级与请求量估算，并可选落盘，
// 让 poc.submit 能直接拿着 poc_path 在真实目标上受限实跑取证据。判定是否漏洞仍然只发生在实跑。
func (s *Server) pocDraftTool() *Tool {
	type args struct {
		Yaml    string `json:"yaml"`
		PocPath string `json:"poc_path"`
		Save    bool   `json:"save"`
	}
	return &Tool{
		Name:        "poc.draft",
		Title:       "校验 PoC 草稿",
		Description: "校验一份 PoC 草稿（yaml 字符串或本地 poc_path），返回结构、能力等级与请求量估算；save=true 时落盘并给出可直接交给 poc.submit 实跑的 poc_path。不发送任何请求。自己写新 PoC 时先经它校验，不要直接把未经校验的 yaml 丢给 poc.submit。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"yaml":     map[string]any{"type": "string", "description": "PoC YAML 内容"},
				"poc_path": map[string]any{"type": "string", "description": "本地 PoC 路径，优先于 yaml"},
				"save":     map[string]any{"type": "boolean", "description": "校验通过后写入 ~/.config/afrog/drafts/<id>.yaml"},
			},
			"required": []string{},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			if err := s.gate.Take(policy.Action{Name: "poc.draft"}, 0); err != nil {
				return nil, err
			}

			data := []byte(a.Yaml)
			source := "yaml"
			if p := strings.TrimSpace(a.PocPath); p != "" {
				read, err := os.ReadFile(p)
				if err != nil {
					return nil, fmt.Errorf("poc_path not readable: %w", err)
				}
				data, source = read, p
			}
			if len(bytes.TrimSpace(data)) == 0 {
				return nil, fmt.Errorf("yaml or poc_path is required")
			}

			var draft poc.Poc
			parseErr := yaml.Unmarshal(data, &draft)

			problems := make([]string, 0, 4)
			warnings := make([]string, 0, 4)
			if parseErr != nil {
				problems = append(problems, "yaml: "+parseErr.Error())
				return map[string]any{
					"valid":    false,
					"errors":   problems,
					"warnings": warnings,
					"source":   source,
				}, nil
			}

			if strings.TrimSpace(draft.Id) == "" {
				problems = append(problems, "id is required")
			} else if !draftIDRe.MatchString(draft.Id) {
				problems = append(problems, "id must be 1-128 chars of [A-Za-z0-9._-] and start with a letter or digit")
			}
			if len(draft.Rules) == 0 {
				problems = append(problems, "rules is required")
			}
			if strings.TrimSpace(draft.Info.Name) == "" {
				warnings = append(warnings, "info.name is empty")
			}
			switch severity := strings.ToLower(strings.TrimSpace(draft.Info.Severity)); severity {
			case "info", "low", "medium", "high", "critical":
			case "":
				warnings = append(warnings, `info.severity is empty; it will be reported as "info"`)
			default:
				warnings = append(warnings, fmt.Sprintf("info.severity %q is not one of info/low/medium/high/critical", draft.Info.Severity))
			}
			if strings.TrimSpace(draft.Expression) == "" {
				warnings = append(warnings, "top-level expression is empty; the PoC may never match")
			}

			destructive := false
			for _, rm := range draft.Rules {
				if len(rm.Value.Brute) > 0 {
					destructive = true
				}
				req := rm.Value.Request
				switch strings.ToLower(strings.TrimSpace(req.Type)) {
				case poc.JS_Type, poc.GO_Type:
					// 脚本能力由 draft.Capability() 汇总。
				case poc.TCP_Type, poc.UDP_Type, poc.SSL_Type:
					if strings.TrimSpace(req.Host) == "" && strings.TrimSpace(req.Data) == "" {
						warnings = append(warnings, fmt.Sprintf("rule %q has no host/data for %s", rm.Key, req.Type))
					}
				default: // 空 type 即 http
					if strings.TrimSpace(req.Path) == "" && strings.TrimSpace(req.Raw) == "" {
						warnings = append(warnings, fmt.Sprintf("rule %q has no path/raw", rm.Key))
					}
				}
			}
			level := draft.Capability()
			if level == capability.Exec {
				destructive = true
			}

			est := analyzePoc(data)
			out := map[string]any{
				"valid":              len(problems) == 0,
				"errors":             problems,
				"warnings":           warnings,
				"source":             source,
				"id":                 draft.Id,
				"name":               draft.Info.Name,
				"severity":           draft.Info.Severity,
				"tags":               draft.Info.Tags,
				"author":             draft.Info.Author,
				"rules":              len(draft.Rules),
				"capability":         level.String(),
				"destructive":        destructive,
				"estimated_requests": est.Requests,
				"uncountable":        est.Uncountable,
				"script":             est.Script,
			}

			if a.Save {
				if len(problems) > 0 {
					return nil, fmt.Errorf("draft is invalid: %s", strings.Join(problems, "; "))
				}
				path, err := saveDraft(draft.Id, data)
				if err != nil {
					return nil, err
				}
				out["poc_path"] = path
			}
			return out, nil
		},
	}
}

// draftDir 是模型草稿的落盘目录，与用户配置同源，便于 verify.replay 按 poc_id 回查。
func draftDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "afrog", "drafts"), nil
}

// draftPath 返回草稿的规范路径；id 不合法（含路径穿越）时返回空串。
func draftPath(id string) string {
	if !draftIDRe.MatchString(id) {
		return ""
	}
	dir, err := draftDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, id+".yaml")
}

// saveDraft 把草稿写到用户配置目录，权限 0600：草稿里可能有目标专用凭据。
func saveDraft(id string, data []byte) (string, error) {
	path := draftPath(id)
	if path == "" {
		return "", fmt.Errorf("invalid draft id %q", id)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create draft dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("write draft: %w", err)
	}
	return path, nil
}

// --- poc.submit ---

// pocSubmitTool 把一份草稿推进「待人工终审」队列。
//
// 与 poc.draft 的分工：draft 只校验结构与成本，submit 必须先在一台真实目标上受限
// 实跑一次（沙箱实跑）并拿到证据，才允许进入队列——「拿不到证据的候选」不配进终审。
// 判定权仍不在这里：提交只代表「可复现」，是否入库由人工 `afrog poc approve` 决定。
func (s *Server) pocSubmitTool() *Tool {
	type args struct {
		PocPath    string `json:"poc_path"`
		Target     string `json:"target"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	return &Tool{
		Name:        "poc.submit",
		Title:       "提交 PoC 候选",
		Description: "在一台真实目标上受限实跑一份草稿并取证据，通过后放入待人工终审队列（afrog poc approve/reject）。实跑会发包。草稿需先经 poc.draft 校验落盘；入库只能由人在 CLI 决定，模型没有直接写入 PoC 目录的路径。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"poc_path":    map[string]any{"type": "string", "description": "草稿 YAML 路径（通常来自 poc.draft 的 poc_path）"},
				"target":      map[string]any{"type": "string", "description": "实跑目标 URL 或 host:port"},
				"timeout_sec": map[string]any{"type": "integer", "minimum": 5, "maximum": 300, "description": "整体超时，默认 60 秒"},
			},
			"required": []string{"poc_path", "target"},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			target := strings.TrimSpace(a.Target)
			if target == "" {
				return nil, fmt.Errorf("target is required")
			}
			pocPath := strings.TrimSpace(a.PocPath)
			if pocPath == "" {
				return nil, fmt.Errorf("poc_path is required (run poc.draft with save=true to persist this draft and get a poc_path)")
			}

			pocPath, pocData, cleanup, err := resolvePoc("", pocPath)
			if err != nil {
				return nil, err
			}
			defer cleanup()

			var draft poc.Poc
			if err := yaml.Unmarshal(pocData, &draft); err != nil {
				return nil, fmt.Errorf("draft is not valid yaml: %w", err)
			}

			// 按草稿自身的能力等级门控：exec 级候选在未开启 destructive 时直接拒绝。
			est := analyzePoc(pocData)
			reserve := est.Requests
			if est.Uncountable {
				reserve = maxVerifyReserve
			}
			if err := s.gate.Take(policy.Action{
				Name:        "poc.submit",
				Target:      target,
				Capability:  draft.Capability(),
				Destructive: draft.Capability() == capability.Exec,
			}, reserve); err != nil {
				return nil, err
			}

			timeout := time.Duration(a.TimeoutSec) * time.Second
			if timeout <= 0 {
				timeout = 60 * time.Second
			}
			run, err := s.runPocScan(ctx, "poc.submit", target, pocPath, pocData, 0, est.NeedsOOB, timeout)
			if err != nil {
				return nil, err
			}
			ev := firstEvidence(run.Results)
			if ev == nil {
				return map[string]any{
					"submitted": false,
					"reason":    "sandbox run produced no evidence; the candidate did not reproduce on the target",
					"target":    target,
					"status":    run.Status,
					"results":   run.Results,
				}, nil
			}

			rec, err := drafter.Submit(drafter.SubmitOptions{
				ID:             draft.Id,
				Path:           pocPath,
				Target:         target,
				EvidenceID:     ev.ID,
				EvidenceDigest: ev.Digest,
				Requests:       est.Requests,
			})
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"submitted": true,
				"draft":     rec,
				"evidence":  evidenceRef(ev),
				"next":      "run `afrog poc approve " + rec.ID + "` after human review",
			}, nil
		},
	}
}

// --- probe.http ---
func (s *Server) probeHTTPTool() *Tool {
	type args struct {
		Method          string            `json:"method"`
		URL             string            `json:"url"`
		Headers         map[string]string `json:"headers"`
		Body            string            `json:"body"`
		TimeoutSec      int               `json:"timeout_sec"`
		FollowRedirects bool              `json:"follow_redirects"`
	}
	return &Tool{
		Name:        "probe.http",
		Title:       "发单次 HTTP 请求",
		Description: "发起一次受限的 HTTP 请求（单次、可重放），用于确认端点行为。适合核对状态码/响应特征；这次往返会写进观测流，供 observe.observations 复查。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"method":           map[string]any{"type": "string", "description": "默认 GET"},
				"url":              map[string]any{"type": "string", "description": "绝对 URL"},
				"headers":          map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
				"body":             map[string]any{"type": "string"},
				"timeout_sec":      map[string]any{"type": "integer", "minimum": 1, "maximum": 60},
				"follow_redirects": map[string]any{"type": "boolean"},
			},
			"required": []string{"url"},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}

			method := strings.ToUpper(strings.TrimSpace(a.Method))
			if method == "" {
				method = http.MethodGet
			}
			target := strings.TrimSpace(a.URL)
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				return nil, fmt.Errorf("url must be absolute http(s)")
			}
			if err := s.gate.Take(policy.Action{Name: "probe.http", Target: target}, 1); err != nil {
				return nil, err
			}

			timeout := time.Duration(a.TimeoutSec) * time.Second
			if timeout <= 0 {
				timeout = 15 * time.Second
			}
			reqCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			var body io.Reader
			if a.Body != "" {
				body = strings.NewReader(a.Body)
			}
			req, err := http.NewRequestWithContext(reqCtx, method, target, body)
			if err != nil {
				return nil, err
			}
			for k, v := range a.Headers {
				req.Header.Set(k, v)
			}

			client := &http.Client{Timeout: timeout}
			if !a.FollowRedirects {
				client.CheckRedirect = func(*http.Request, []*http.Request) error {
					return http.ErrUseLastResponse
				}
			}

			start := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			data, err := io.ReadAll(io.LimitReader(resp.Body, toolBodyLimit))
			if err != nil {
				return nil, err
			}

			headers := make(map[string]string, len(resp.Header))
			for k, vs := range resp.Header {
				headers[k] = strings.Join(vs, ", ")
			}

			latency := time.Since(start).Milliseconds()
			recordHTTPObservation("", method, resp.Request.URL.String(), resp.StatusCode, true, latency,
				describeRequest(method, target, a.Headers), describeResponse(resp, data))

			return map[string]any{
				"status":     resp.StatusCode,
				"headers":    headers,
				"body":       clampText(string(data), toolBodyLimit),
				"latency_ms": latency,
				"url":        resp.Request.URL.String(),
			}, nil
		},
	}
}

// --- probe.port ---

// maxProbePorts 是单次端口探测的端口数上限：工具调用应当短小，全端口扫描
// 走 CLI / 扫描任务，不要从一次 MCP 调用里发起。
const maxProbePorts = 1000

func (s *Server) probePortTool() *Tool {
	type args struct {
		Host       string `json:"host"`
		Ports      string `json:"ports"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	return &Tool{
		Name:        "probe.port",
		Title:       "端口探测",
		Description: "对单个主机做受限端口探测，返回开放端口与服务指纹。ports 支持 top100/top1000、单端口、区间（如 8000-8100），留空为 top100；单次最多 1000 个端口，按端口数扣预算。目标没有 Web 面，或想先看有哪些服务时用它。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"host":        map[string]any{"type": "string", "description": "主机、host:port 或 URL"},
				"ports":       map[string]any{"type": "string", "description": "端口表达式，默认 top100"},
				"timeout_sec": map[string]any{"type": "integer", "minimum": 5, "maximum": 600, "description": "整体超时，默认 120 秒"},
			},
			"required": []string{"host"},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			host, err := probeHost(a.Host)
			if err != nil {
				return nil, err
			}

			spec := strings.TrimSpace(a.Ports)
			if spec == "" {
				spec = "top100"
			}
			count, err := countProbePorts(spec)
			if err != nil {
				return nil, err
			}
			if count > maxProbePorts {
				return nil, fmt.Errorf("ports %q needs %d probes, above the %d limit for one call", spec, count, maxProbePorts)
			}
			if err := s.gate.Take(policy.Action{Name: "probe.port", Target: host}, count); err != nil {
				return nil, err
			}

			timeout := time.Duration(a.TimeoutSec) * time.Second
			if timeout <= 0 {
				timeout = 120 * time.Second
			}
			runCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			// 收敛速率：一次工具调用没有理由打满链路，也不做主动服务探针
			// （被动 banner 足够支撑「这个端口是什么」的判断，且请求数可数）。
			var (
				mu    sync.Mutex
				found []portscan.ScanResult
			)
			scanner, err := portscan.NewScanner(&portscan.Options{
				Targets:                 []string{host},
				Ports:                   spec,
				RateLimit:               50,
				ConnectRateLimit:        50,
				ConnectRateLimitPerHost: 20,
				MaxHostConcurrency:      4,
				Timeout:                 time.Second,
				Retries:                 0,
				ScanMode:                portscan.ScanModeConnect,
				SkipDiscovery:           true,
				// 关掉「疑似代答设备」的哨兵预探测：它会在预算之外额外发包，
				// 而一次工具调用只需要「这些端口开没开」这一个结论。
				SkipSpoofCheck: true,
				Quiet:          true,
				OnResult: func(r *portscan.ScanResult) {
					if r == nil || r.State != portscan.PortStateOpen {
						return
					}
					mu.Lock()
					found = append(found, *r)
					mu.Unlock()
				},
			})
			if err != nil {
				return nil, err
			}
			if err := scanner.Scan(runCtx); err != nil {
				return nil, err
			}

			sort.Slice(found, func(i, j int) bool { return found[i].Port < found[j].Port })
			open := make([]map[string]any, 0, len(found))
			for _, r := range found {
				open = append(open, map[string]any{
					"port":       r.Port,
					"state":      r.State.String(),
					"service":    r.Service,
					"product":    r.Product,
					"version":    r.Version,
					"device":     r.Device,
					"os":         r.OS,
					"cpe":        r.CPE,
					"tls":        r.TLS,
					"confidence": r.Confidence.String(),
					"banner":     clampText(r.Banner, toolHeaderLimit),
				})
			}
			return map[string]any{
				"host":    host,
				"ports":   spec,
				"scanned": count,
				"open":    open,
			}, nil
		},
	}
}

// probeHost 从主机、host:port 或 URL 中提取主机名。
func probeHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("host is required")
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return "", fmt.Errorf("invalid host %q", raw)
		}
		return u.Hostname(), nil
	}
	if h, _, err := net.SplitHostPort(raw); err == nil && h != "" {
		return h, nil
	}
	return strings.Trim(raw, "[]"), nil
}

// countProbePorts 静态数出一次探测会发起多少个连接，用于预算预留。
func countProbePorts(spec string) (int, error) {
	spec = strings.ToLower(strings.TrimSpace(spec))
	switch spec {
	case "", "top", "top100":
		return 100, nil
	case "full", "all":
		return 65535, nil
	}

	total := 0
	for _, tok := range strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.HasPrefix(tok, "top") {
			n, err := strconv.Atoi(strings.TrimPrefix(tok, "top"))
			if err != nil || n <= 0 {
				return 0, fmt.Errorf("invalid port token %q", tok)
			}
			total += n
			continue
		}
		if i := strings.IndexByte(tok, '-'); i > 0 {
			lo, errLo := strconv.Atoi(tok[:i])
			hi, errHi := strconv.Atoi(tok[i+1:])
			if errLo != nil || errHi != nil || lo <= 0 || hi > 65535 || lo > hi {
				return 0, fmt.Errorf("invalid port range %q", tok)
			}
			total += hi - lo + 1
			continue
		}
		n, err := strconv.Atoi(tok)
		if err != nil || n <= 0 || n > 65535 {
			return 0, fmt.Errorf("invalid port %q", tok)
		}
		total++
	}
	if total == 0 {
		return 0, fmt.Errorf("ports is empty")
	}
	return total, nil
}

// --- probe.fingerprint ---

// probeFingerprintAccept 是与浏览器一致的 Accept，减少被 WAF 简单规则拦下的概率。
const probeFingerprintAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

func (s *Server) probeFingerprintTool() *Tool {
	type args struct {
		URL        string `json:"url"`
		Favicon    bool   `json:"favicon"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	return &Tool{
		Name:        "probe.fingerprint",
		Title:       "识别 Web 指纹",
		Description: "对单个 URL 做一次 Web 指纹识别：技术栈、WAF/CDN、跳转链与 TLS 摘要。**返回里的 suggested_search 就是可直接透传的关键词串**（由识别出的技术栈的规则 id、名称等标识词拼成）：先用它调 poc.search(keyword=suggested_search) 预检（等价 afrog -pl -s），有结果再把同一串交给 scan.start(search=…) 并发扫描——这是「先识别指纹、再找漏洞」的主路径，别自己另编关键词。首页识别不出任何技术栈时，会自动补抓一次 /favicon.ico 再匹配（多一次请求与预算，返回里的 favicon_fetched 标明是否真的抓了）；favicon=true 则无论首页是否有结果都抓。若 technologies 为空（suggested_search 也是空），说明没识别出任何技术栈：不要凭空编关键词，改走 plan.next，或征得用户同意后用空 search 让 afrog 跑全部 PoC（见 scan.start）。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url":         map[string]any{"type": "string", "description": "绝对 URL，缺省协议时按 http 处理"},
				"favicon":     map[string]any{"type": "boolean", "description": "强制抓取 /favicon.ico（多一次请求与预算）；默认关闭，但首页没识别出任何技术栈时会自动补抓一次"},
				"timeout_sec": map[string]any{"type": "integer", "minimum": 1, "maximum": 60, "description": "整体超时，默认 15 秒"},
			},
			"required": []string{"url"},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			target := strings.TrimSpace(a.URL)
			if target == "" {
				return nil, fmt.Errorf("url is required")
			}
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				target = "http://" + target
			}
			if u, err := url.Parse(target); err != nil || u.Host == "" {
				return nil, fmt.Errorf("invalid url %q", a.URL)
			}

			requests := 1
			if a.Favicon {
				requests++
			}
			if err := s.gate.Take(policy.Action{Name: "probe.fingerprint", Target: target}, requests); err != nil {
				return nil, err
			}

			timeout := time.Duration(a.TimeoutSec) * time.Second
			if timeout <= 0 {
				timeout = 15 * time.Second
			}
			runCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			// 抓取与指纹素材组装统一在 pkg/webscan.Prober（与 afrog CLI 同一实现）：
			// 这里只做 MCP 参数到探测参数的映射。
			prober := webscan.NewProber(webscan.ProbeOptions{
				Timeout: timeout,
				Headers: []string{"Accept: " + probeFingerprintAccept},
			})

			start := time.Now()
			probe, err := prober.Probe(runCtx, target)
			if err != nil {
				return nil, err
			}
			latency := time.Since(start).Milliseconds()
			headers := probe.Headers

			matcher, err := s.webMatcher()
			if err != nil {
				return nil, err
			}
			// 先用首页素材匹配一次（不含 favicon）。
			matched := matcher.Match(probe.Response())

			// 抓 favicon 的时机：显式要求，或首页什么技术栈都没识别出来。favicon 的 mmh3
			// 是最稳定、最便宜的兜底指纹维度——首页没命中时补抓一次，往往能把「识别不出」
			// 变成「识别得出」。显式要求已在上面按 2 次请求计过费；自动补抓的这一次在此单独
			// 计费，预算不足就放弃补抓、不影响主结果。
			faviconFetched := false
			if a.Favicon || len(matched.Technologies) == 0 {
				allowed := true
				if !a.Favicon {
					if err := s.gate.Take(policy.Action{Name: "probe.fingerprint", Target: target}, 1); err != nil {
						allowed = false
					}
				}
				if allowed {
					if fav := prober.FetchFavicon(runCtx, probe.FinalURL); len(fav) > 0 {
						faviconFetched = true
						withFav := probe.Response()
						withFav.Favicon = fav
						matched = matcher.Match(withFav)
					}
				}
			}

			techs := make([]map[string]any, 0, len(matched.Technologies))
			waf := make([]string, 0, 2)
			cdn := make([]string, 0, 2)
			// suggested_search 是本工具交给模型的关键词：把每条技术栈的 requires 标识词
			// （规则 id、技术名及其连字符写法）拼成逗号串，可原样透传给 poc.search(keyword=)
			// 与 scan.start(search=)。用 MatchTokens 而不是只用名称，是为了让「检索口径」与
			// afrog 自身的 requires 门控一致——模型不必再猜关键词（那一步最容易乱编：
			// 识别出 jQuery 却去搜 wordpress、nginx 之类根本没识别到的产品）。
			//
			// 有意去掉 category：它是 requires 门控用的粗粒度语义，拿它做检索会一搜一大片
			// （实测 afrog -s "cms" 命中 83 条 PoC），把一次按需扫描放大成长列表扫描，
			// 违背本工具面「按需、可解释」的定位。规则 id 才是 PoC requires 里真正书写的词。
			searchTokens := make([]string, 0, len(matched.Technologies)*2)
			seenToken := make(map[string]struct{}, len(matched.Technologies)*2)
			for _, t := range matched.Technologies {
				techs = append(techs, map[string]any{
					"name":       t.Name,
					"version":    t.Version,
					"category":   t.Category,
					"cpe":        t.CPE,
					"confidence": t.Confidence.String(),
					"evidence":   t.Evidence,
				})
				category := strings.ToLower(strings.TrimSpace(t.Category))
				for _, tok := range t.MatchTokens() {
					if tok == category {
						continue
					}
					if _, ok := seenToken[tok]; ok {
						continue
					}
					seenToken[tok] = struct{}{}
					searchTokens = append(searchTokens, tok)
				}
				switch strings.ToLower(t.Category) {
				case "waf":
					waf = append(waf, t.Name)
				case "cdn":
					cdn = append(cdn, t.Name)
				}
			}

			out := map[string]any{
				"url":              probe.FinalURL,
				"status":           probe.Status,
				"title":            probe.Title,
				"server":           headers["server"],
				"powered_by":       headers["x-powered-by"],
				"technologies":     techs,
				"suggested_search": strings.Join(searchTokens, ","),
				"confidence":       matched.Confidence.String(),
				"waf":              waf,
				"cdn":              cdn,
				"redirects":        probe.Redirects,
				"favicon_hash":     matched.FaviconHash,
				"favicon_fetched":  faviconFetched,
				"latency_ms":       latency,
			}
			if probe.TLS != nil {
				out["tls"] = map[string]any{
					"subject":   probe.TLS.Subject,
					"issuer":    probe.TLS.Issuer,
					"not_after": probe.TLS.NotAfter,
					"dns_names": probe.TLS.DNSNames,
				}
			}

			recordHTTPObservation("", http.MethodGet, probe.FinalURL, probe.Status,
				len(matched.Technologies) > 0, latency,
				describeRequest(http.MethodGet, probe.FinalURL, map[string]string{"Accept": probeFingerprintAccept}),
				describeProbeResponse(probe))
			recordTechObservation(probe.FinalURL, probe.Status,
				probe.Title, headers["server"], headers["x-powered-by"], matched)

			return out, nil
		},
	}
}

// webMatcher 懒加载内置指纹规则；规则集只读，整个进程复用一份。
func (s *Server) webMatcher() (*webscan.Matcher, error) {
	s.webscanOnce.Do(func() {
		s.webscanMatcher, s.webscanErr = webscan.LoadMatcher("")
	})
	return s.webscanMatcher, s.webscanErr
}

// describeProbeResponse 从探测素材生成响应片段（状态行 + 头 + 正文），供观测流留存。
//
// 抓取由 pkg/webscan.Prober 完成，这里只有 MCP 观测流的展示格式。
func describeProbeResponse(p *webscan.ProbeResult) string {
	if p == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(p.Proto)
	sb.WriteByte(' ')
	sb.WriteString(strconv.Itoa(p.Status))
	sb.WriteByte(' ')
	sb.WriteString(http.StatusText(p.Status))

	keys := make([]string, 0, len(p.Headers))
	for k := range p.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sb.WriteByte('\n')
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(p.Headers[k])
	}
	sb.WriteString("\n\n")
	sb.Write(p.Body)
	return sb.String()
}

// --- scan.start ---

// scanStartTool 用一次子进程并发跑完「某技术栈（关键词）下的全部 PoC」。
//
// 这是取代「逐个 verify」的主入口。选择权交回 afrog 的 -s：关键词命中 id/名称/标签；
// 关键词为空时不加过滤、跑全库；带关键词时，命中该关键词的指纹 PoC 不受 severity 限制
// 也会被保留（见 config.filterPocSeveritySearchWithFingerprint）。于是指纹阶段照常运行、
// requires 按真实指纹放行，既避免「单跑一个漏洞 PoC 被指纹门控跳过」的假阴性，也把
// N 次串行验证压成一次并发扫描。整批扫描交给独立子进程，规避 sdk 的进程级全局状态串扰。
func (s *Server) scanStartTool() *Tool {
	type args struct {
		Target      string `json:"target"`
		Search      string `json:"search"`
		Severity    string `json:"severity"`
		Concurrency int    `json:"concurrency"`
		RateLimit   int    `json:"rate_limit"`
		TimeoutSec  int    `json:"timeout_sec"`
	}
	return &Tool{
		Name:  "scan.start",
		Title: "按技术栈并发扫描",
		Description: "用一次子进程并发跑完某个技术栈（关键词）下的全部 PoC，返回可重放证据——这是取代逐个验证的主入口。search 传技术栈/产品关键词（thinkphp、jquery、shiro…，逗号分隔可多个）：afrog 按 -s 选 PoC（命中 id/名称/标签）。**search 留空表示不加关键词、跑全库所有 PoC**——这是「没有任何指纹线索」时的兜底，请求量与耗时都大得多，只在 plan.next 也给不出关键词、且已征得用户同意「用 afrog 扫描全部漏洞」时才用。带关键词时，命中该关键词的指纹 PoC 不受 severity 限制也会被保留（关键词是硬前提：关键词不命中的指纹 PoC 同样会被滤掉），于是指纹阶段照常运行、requires 按真实指纹放行——既不会出现「单跑一个漏洞 PoC 被指纹门控跳过」的假阴性，也不为 N 个候选发 N 次串行请求。执行前先用 poc.search(keyword=…) 预检「本机有没有该技术栈的 PoC」（等价 afrog -pl -s；probe.fingerprint 返回的 suggested_search 可直接透传），结果为空就别扫。severity 只是按级别粗筛的兜底：用户没有指定等级时留空（即扫描所有等级），不要无理由默认塞 high,critical。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target":      map[string]any{"type": "string", "description": "目标 URL 或 host:port"},
				"search":      map[string]any{"type": "string", "description": "技术栈/产品关键词（如 thinkphp,jquery,nacos）；命中 PoC 的 id/名称/标签。留空 = 不加关键词、跑全库所有 PoC（量大，需先征得用户同意）"},
				"severity":    map[string]any{"type": "string", "description": "可选的级别粗筛（逗号分隔，如 high,critical）；用户没指定等级时留空，即扫描所有等级"},
				"concurrency": map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "description": "并发数，默认由引擎决定"},
				"rate_limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": 1000, "description": "每秒请求上限，0 表示不限"},
				"timeout_sec": map[string]any{"type": "integer", "minimum": 5, "maximum": 1800, "description": "整批扫描的整体超时，默认 300 秒"},
			},
			"required": []string{"target"},
		},
		OutputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target": map[string]any{"type": "string"},
				"search": map[string]any{"type": "string"},
				"status": map[string]any{"type": "string", "description": "completed / timeout / failed / cancelled"},
				"found":  map[string]any{"type": "boolean", "description": "是否有命中"},
				"results": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"poc_id":     map[string]any{"type": "string"},
							"poc_name":   map[string]any{"type": "string"},
							"severity":   map[string]any{"type": "string"},
							"target":     map[string]any{"type": "string"},
							"extractors": map[string]any{"type": "object"},
							"evidence":   map[string]any{"type": "object", "description": "原生证据（id/digest/steps/replay）"},
						},
					},
				},
				"summary": map[string]any{"type": "object", "description": "子进程汇总：executed / found / by_severity / elapsed_ms"},
				"library": map[string]any{
					"type":        "object",
					"description": "本机 PoC 库对该关键词的覆盖：matched_pocs（库中匹配数）/ executed_pocs（实际执行数）",
					"properties": map[string]any{
						"matched_pocs":  map[string]any{"type": "integer"},
						"executed_pocs": map[string]any{"type": "integer"},
					},
				},
				"conclusion": map[string]any{"type": "string", "description": "hit / no_finding / no_poc_for_keyword"},
				"guidance":   map[string]any{"type": "string", "description": "未命中时的说明，用来分清「本机没 PoC」与「有 PoC 没命中」"},
				"error":      map[string]any{"type": "string"},
			},
			"required": []string{"target", "search", "status", "found", "results", "library", "conclusion"},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			target := strings.TrimSpace(a.Target)
			if target == "" {
				return nil, fmt.Errorf("target is required")
			}
			// search 允许为空：空关键词 = 不加过滤、跑全库，用在「没有任何指纹线索」的兜底
			// （描述里要求模型先征得用户同意再这么做）。此时 -s 不会下发，afrog 加载全部 PoC。
			search := strings.TrimSpace(a.Search)

			if err := s.gate.Take(policy.Action{
				Name:   "scan.start",
				Target: target,
			}, estimateKeywordReserve(search)); err != nil {
				return nil, err
			}

			timeout := time.Duration(a.TimeoutSec) * time.Second
			if timeout <= 0 {
				timeout = 300 * time.Second
			}

			spec := baseScanSpec(target, search)
			spec.Severity = strings.TrimSpace(a.Severity)
			spec.Concurrency = a.Concurrency
			spec.RateLimit = a.RateLimit
			if s.oob != nil {
				spec.EnableOOB = true
				spec.OOBAdapter = s.oob.Adapter()
			}

			run, err := s.runScanSpec(ctx, mcpTaskID("scan.start"), spec, timeout)
			if err != nil {
				return nil, err
			}
			return scanRunResult(target, search, run, pocsrepo.CountMatched(search)), nil
		},
	}
}

// scanRunResult 把一次扫描的产物整理成工具返回，并显式区分三种结论——否则模型会把
// 「本机没有该技术栈的 PoC」读成「目标没有漏洞」：
//
//	hit                  有命中；
//	no_finding           本机有匹配 PoC 且已执行，但均未命中（只能说明这些 PoC 未在目标上成立）；
//	no_poc_for_keyword   关键词在本机 PoC 库里根本没有匹配（afrog 暂无该产品的检测能力）。
func scanRunResult(target, search string, run *scanRun, matched int) map[string]any {
	executed := 0
	if run.Summary != nil {
		executed = int(run.Summary.Executed)
	}
	out := map[string]any{
		"target":  target,
		"search":  search,
		"status":  run.Status,
		"found":   len(run.Results) > 0,
		"results": run.Results,
		// library 是「本机 PoC 库对这个关键词的覆盖」：matched_pocs 为库中匹配数，
		// executed_pocs 为实际执行数。两者一起看，才能分清「没 PoC」与「有 PoC 没命中」。
		"library": map[string]any{
			"matched_pocs": matched,
			"executed_pocs": executed,
		},
	}
	if run.Summary != nil {
		out["summary"] = run.Summary
	}
	if run.Error != "" {
		out["error"] = run.Error
	}
	switch {
	case len(run.Results) > 0:
		out["conclusion"] = "hit"
	case matched == 0:
		out["conclusion"] = "no_poc_for_keyword"
		out["guidance"] = fmt.Sprintf("本机 PoC 库中没有与关键词 %q 匹配的 PoC——这只说明 afrog 暂无该产品的检测能力，**不能据此判定目标无漏洞**。可换更通用的关键词，或征得用户同意后用空 search 跑全库。", search)
	case executed == 0:
		out["conclusion"] = "no_finding"
		out["guidance"] = fmt.Sprintf("本机有 %d 条匹配 PoC，但没有一条被执行（多半被 severity 过滤挡下）——这不构成「无漏洞」结论，去掉 severity 限制或用空 severity 重扫。", matched)
	default:
		out["conclusion"] = "no_finding"
		out["guidance"] = fmt.Sprintf("本机有 %d 条匹配 PoC、已执行 %d 条，均未命中——只能说明这些 PoC 未在目标上成立，**不等于目标无漏洞**。", matched, executed)
	}
	return out
}

// --- verify.replay ---

// verifyReplayTool 重放一条已有证据，并用内容寻址 id/digest 判断是否仍然成立。
//
// 这是「证据可重放」从口号变成动作的地方：重放成功但 digest 变了，说明目标行为或
// PoC 已经变了，调用方不该继续把旧结论当成事实。
func (s *Server) verifyReplayTool() *Tool {
	type args struct {
		ID         string `json:"id"`
		Target     string `json:"target"`
		PocPath    string `json:"poc_path"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	return &Tool{
		Name:        "verify.replay",
		Title:       "重放证据",
		Description: "按证据 id（evd_ 前缀）或 result id 重放一次，返回新证据并比对 digest 是否一致。target 留空沿用证据里的目标。用来复核旧结论是否仍然成立：重放成功但 digest 变了，说明目标行为或 PoC 已经变化。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":          map[string]any{"type": "string", "description": "证据 id 或 result id"},
				"target":      map[string]any{"type": "string", "description": "重放目标；留空沿用证据里的 target"},
				"poc_path":    map[string]any{"type": "string", "description": "本地 PoC 路径；留空按证据的 poc_id 从仓库或 drafts 解析"},
				"timeout_sec": map[string]any{"type": "integer", "minimum": 5, "maximum": 300},
			},
			"required": []string{"id"},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			id := strings.TrimSpace(a.ID)
			if id == "" {
				return nil, fmt.Errorf("id is required")
			}

			expected, err := agentapi.Evidence(id)
			if err != nil {
				return nil, err
			}
			if expected == nil {
				return nil, fmt.Errorf("evidence not found for %q (ids come from observe.findings evidence[] or a result id; evidence is only stored for PoCs that actually fired)", id)
			}

			pocPath, pocData, cleanup, err := resolveEvidencePoc(expected.PocID, a.PocPath)
			if err != nil {
				return nil, err
			}
			defer cleanup()

			target := strings.TrimSpace(a.Target)
			if target == "" {
				target = expected.Target
			}
			if target == "" {
				return nil, fmt.Errorf("target is required: this evidence has no target, pass one explicitly")
			}

			est := analyzePoc(pocData)
			reserve := est.Requests
			if est.Uncountable {
				reserve = maxVerifyReserve
			}
			if err := s.gate.Take(policy.Action{
				Name:       "verify.replay",
				Target:     target,
				Capability: capability.Declarative,
			}, reserve); err != nil {
				return nil, err
			}

			timeout := time.Duration(a.TimeoutSec) * time.Second
			if timeout <= 0 {
				timeout = 60 * time.Second
			}
			run, err := s.runPocScan(ctx, "verify.replay", target, pocPath, pocData, 0, est.NeedsOOB, timeout)
			if err != nil {
				return nil, err
			}

			actual := firstEvidence(run.Results)
			consistent := replayMatches(expected, actual)
			res := map[string]any{
				"poc_id":     expected.PocID,
				"target":     target,
				"replayed":   actual != nil,
				"consistent": consistent,
				"expected":   evidenceRef(expected),
			}
			if actual != nil {
				res["actual"] = evidenceRef(actual)
				res["evidence"] = actual
			}
			if reason := replayReason(actual != nil, consistent); reason != "" {
				res["reason"] = reason
			}
			return res, nil
		},
	}
}

// resolveEvidencePoc 按证据的 poc_id 找本地 PoC：先查仓库，再查模型草稿目录。
// 草稿路径让「模型写、poc.submit 实跑、verify.replay 复核」这条链路真正闭环。
func resolveEvidencePoc(pocID, pocPath string) (string, []byte, func(), error) {
	if strings.TrimSpace(pocPath) != "" {
		return resolvePoc("", pocPath)
	}
	path, data, cleanup, err := resolvePoc(pocID, "")
	if err == nil {
		return path, data, cleanup, nil
	}
	if draft := draftPath(pocID); draft != "" {
		if data, rerr := os.ReadFile(draft); rerr == nil {
			return draft, data, func() {}, nil
		}
	}
	return "", nil, func() {}, fmt.Errorf("poc %q is not available locally: %w", pocID, err)
}

func firstEvidence(out []map[string]any) *evidence.Evidence {
	for _, item := range out {
		if ev, ok := item["evidence"].(*evidence.Evidence); ok && ev != nil {
			return ev
		}
	}
	return nil
}

// replayMatches 用内容寻址 id 与 digest 双重比对：两者都由内容算出，任一不等都说明
// 这次重放观察到的不是同一条事实。
func replayMatches(expected, actual *evidence.Evidence) bool {
	if expected == nil || actual == nil {
		return false
	}
	return expected.ID == actual.ID && expected.Digest == actual.Digest
}

func replayReason(replayed, consistent bool) string {
	switch {
	case !replayed:
		return "replay did not reproduce the finding"
	case !consistent:
		return "replay produced different evidence: the target or the PoC changed"
	default:
		return ""
	}
}

func evidenceRef(ev *evidence.Evidence) map[string]any {
	if ev == nil {
		return nil
	}
	return map[string]any{
		"id":         ev.ID,
		"digest":     ev.Digest,
		"poc_id":     ev.PocID,
		"target":     ev.Target,
		"steps":      len(ev.Steps),
		"confidence": ev.Confidence,
		"created":    ev.Created,
	}
}

// --- act.brute ---

func (s *Server) actBruteTool() *Tool {
	type args struct {
		PocID       string `json:"poc_id"`
		PocPath     string `json:"poc_path"`
		Target      string `json:"target"`
		TimeoutSec  int    `json:"timeout_sec"`
		MaxRequests int    `json:"max_requests"`
	}
	return &Tool{
		Name:        "act.brute",
		Title:       "弱口令爆破",
		Description: "【破坏性】用带 brute 字典的 PoC 对目标做弱口令/字典尝试。默认策略拒绝，需先授予 full 模式且 destructive=true。只在授权目标上、且确认需要爆破时使用；普通漏洞验证用 scan.start 即可。",
		// 目录里显式标出「破坏性 + exec 级」：它是唯一默认即被拒的写工具。
		Capability:  capability.Exec,
		Destructive: true,
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"poc_id":       map[string]any{"type": "string"},
				"poc_path":     map[string]any{"type": "string", "description": "本地 PoC YAML 路径，优先于 poc_id"},
				"target":       map[string]any{"type": "string", "description": "目标 URL 或 host:port"},
				"timeout_sec":  map[string]any{"type": "integer", "minimum": 5, "maximum": 600},
				"max_requests": map[string]any{"type": "integer", "minimum": 1, "maximum": 1000, "description": "请求上限，默认 100。仅约束 YAML brute 字典；JS/Go PoC 内部循环无法由外部限流，只受 timeout 与预算约束"},
			},
			"required": []string{"target"},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			target := strings.TrimSpace(a.Target)
			if target == "" {
				return nil, fmt.Errorf("target is required")
			}
			if strings.TrimSpace(a.PocID) == "" && strings.TrimSpace(a.PocPath) == "" {
				return nil, fmt.Errorf("poc_id or poc_path is required (pass a poc_id from poc.search, or a poc_path from poc.draft with save=true)")
			}

			pocPath, pocData, cleanup, err := resolvePoc(a.PocID, a.PocPath)
			if err != nil {
				return nil, err
			}
			defer cleanup()

			maxReq := a.MaxRequests
			if maxReq <= 0 {
				maxReq = 100
			}
			if maxReq > 1000 {
				maxReq = 1000
			}

			// 预留预算取「PoC 潜在请求数」与「本次请求上限」的较小值；
			// 字典来自 CEL 表达式时无法静态计数，直接按上限预留。
			if err := s.gate.Take(policy.Action{
				Name:        "act.brute",
				Target:      target,
				Capability:  capability.Exec,
				Destructive: true,
			}, reserveForBrute(pocData, maxReq)); err != nil {
				return nil, err
			}

			timeout := time.Duration(a.TimeoutSec) * time.Second
			if timeout <= 0 {
				timeout = 120 * time.Second
			}
			run, err := s.runPocScan(ctx, "act.brute", target, pocPath, pocData, maxReq, analyzePoc(pocData).NeedsOOB, timeout)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"found":        len(run.Results) > 0,
				"results":      run.Results,
				"target":       target,
				"status":       run.Status,
				"max_requests": maxReq,
			}, nil
		},
	}
}

// --- judge.brief / judge.record ---

// judgeBriefTool 把一条命中的研判材料（证据 + 周边观测 + 子图 + 既有意见）打包给模型。
//
// 只读、零预算：它只读本机库，不发包、不改任何状态。模型据此给出的「结论」是意见，
// 不改漏洞台账——台账归确定性引擎与人工。
func (s *Server) judgeBriefTool() *Tool {
	type args struct {
		ID               string `json:"id"`
		ObservationLimit int    `json:"observation_limit"`
	}
	return &Tool{
		Name:        "judge.brief",
		Title:       "取研判材料",
		Description: "按 result id 或 evd_ 证据 id 取一条命中的研判材料：证据链、同目标周边观测、攻击面子图与已有研判意见。只读、零预算。要给出「这条命中到底靠不靠谱」的判断前，先取它。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":                map[string]any{"type": "string", "description": "result id 或 evd_ 开头的证据 id"},
				"observation_limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 200, "description": "周边观测条数，默认 50"},
			},
			"required": []string{"id"},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			if err := s.gate.Take(policy.Action{Name: "judge.brief"}, 0); err != nil {
				return nil, err
			}
			return judge.Build(judge.BriefOptions{ID: a.ID, ObservationLimit: a.ObservationLimit})
		},
	}
}

// judgeRecordTool 存下模型给出的研判意见（advisory）。
//
// 明确不写 vuln_ledger：意见进 judgement 表，与台账分表隔离，供人工复核时参考。
func (s *Server) judgeRecordTool() *Tool {
	type args struct {
		ID          string   `json:"id"`
		Conclusion  string   `json:"conclusion"`
		Reasoning   string   `json:"reasoning"`
		ReviewSteps []string `json:"review_steps"`
		Actor       string   `json:"actor"`
	}
	return &Tool{
		Name:        "judge.record",
		Title:       "记录研判意见",
		Description: "记录一条研判意见（likely_true/likely_false/uncertain）到 judgement 表，作为 advisory 供人工复核；不修改漏洞台账。结论来自研判材料，不要凭空写死。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":           map[string]any{"type": "string", "description": "被研判对象的 id（result id 或证据 id）"},
				"conclusion":   map[string]any{"type": "string", "enum": []string{"likely_true", "likely_false", "uncertain"}},
				"reasoning":    map[string]any{"type": "string", "description": "判断依据"},
				"review_steps": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "给人工的复核步骤"},
				"actor":        map[string]any{"type": "string", "description": "给出意见的主体，例如 agent:artex"},
			},
			"required": []string{"id", "conclusion"},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			if err := s.gate.Take(policy.Action{Name: "judge.record"}, 0); err != nil {
				return nil, err
			}
			rec, err := judge.Record(judge.RecordOptions{
				SubjectID:   a.ID,
				Conclusion:  a.Conclusion,
				Reasoning:   a.Reasoning,
				ReviewSteps: a.ReviewSteps,
				Actor:       a.Actor,
			})
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"recorded":  true,
				"judgement": rec,
				"note":      "advisory only: this does not change the vulnerability ledger",
			}, nil
		},
	}
}

// --- learn.brief / learn.record ---

// learnBriefTool 给模型喂终审结果与流水线指标，作为调优素材。
//
// 只读、零预算：素材来自本机 poc_draft / poc_review 与聚合指标，不发包。
func (s *Server) learnBriefTool() *Tool {
	type args struct {
		Limit int `json:"limit"`
	}
	return &Tool{
		Name:        "learn.brief",
		Title:       "取调优素材",
		Description: "取调优素材：流水线指标（含自动入库率）、最近终审决议（含驳回原因）与待审调优建议。只读、零预算。要给流水线提改进建议前，先取它。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 200, "description": "每类样本条数，默认 50"},
			},
			"required": []string{},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			if err := s.gate.Take(policy.Action{Name: "learn.brief"}, 0); err != nil {
				return nil, err
			}
			return learner.Build(learner.BriefOptions{Limit: a.Limit})
		},
	}
}

// learnRecordTool 存下模型给出的调优建议（一段 diff），供人审。
//
// 明确不自动应用：afrog 不解析、不改任何规则/阈值；采纳与否由 `afrog learn accept` 记录。
func (s *Server) learnRecordTool() *Tool {
	type args struct {
		Kind    string `json:"kind"`
		Summary string `json:"summary"`
		Diff    string `json:"diff"`
		Source  string `json:"source"`
		Actor   string `json:"actor"`
	}
	return &Tool{
		Name:        "learn.record",
		Title:       "记录调优建议",
		Description: "记录一条调优建议（rule/threshold/other）到 learn_suggestion 表，供人工审阅；不自动应用任何 diff。建议要基于 learn.brief 的素材，不要空谈。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"kind":    map[string]any{"type": "string", "enum": []string{"rule", "threshold", "other"}},
				"summary": map[string]any{"type": "string", "description": "一句话说明这条建议要改什么"},
				"diff":    map[string]any{"type": "string", "description": "建议的变更内容（diff 文本），afrog 不解析"},
				"source":  map[string]any{"type": "string", "description": "建议依据，例如「近 20 次终审」"},
				"actor":   map[string]any{"type": "string", "description": "提出建议的主体"},
			},
			"required": []string{"summary", "diff"},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			if err := s.gate.Take(policy.Action{Name: "learn.record"}, 0); err != nil {
				return nil, err
			}
			rec, err := learner.Record(learner.RecordOptions{
				Kind:    a.Kind,
				Summary: a.Summary,
				Diff:    a.Diff,
				Source:  a.Source,
				Actor:   a.Actor,
			})
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"recorded":   true,
				"suggestion": rec,
				"next":       "review with `afrog learn show " + rec.ID + "`; `afrog learn accept` records the decision but never applies the diff",
			}, nil
		},
	}
}

// runPocScan 用一次子进程在单目标上跑「一个具体 PoC」，返回归一化命中。
//
// PoC 走 -ap（追加语义）挂在内置库之上、再用 -s 以 PoC id 作关键词选中它，而不是用
// -P（独占语义）：
//   - -ap + -s 不动内置库，选择权交回 afrog 的 -s；再叠加 -w（Web 指纹），requires
//     能用 Web 指纹命中的技术栈 tokens 作为准入来源；
//   - -P（独占）会屏蔽内置库、只加载这一个 PoC，指纹阶段没有可跑的内置指纹 PoC，
//     requires 的准入来源最少，最容易把这次验证整个跳过——那是一个说不清楚的假阴性。
//
// 这与 scan.start 的 -s 口径一致，也是 afrog 自己的推荐用法。SDK 的 HTTP 客户端、
// 限速器与探测缓存都是进程级全局状态，同进程并发 scanner 会互相污染，所以整批交给
// 独立子进程执行。
//
// needsOOB 为真时接上反连平台；缺 OOB 直接报错，绝不下空结论。bruteMax > 0 时下发
// -brute-max-requests，只约束 YAML brute 字典。
func (s *Server) runPocScan(ctx context.Context, tool, target, pocPath string, pocData []byte, bruteMax int, needsOOB bool, timeout time.Duration) (*scanRun, error) {
	spec := &executor.Spec{
		Targets:        []string{strings.TrimSpace(target)},
		AppendPocs:     []string{pocPath},
		Search:         pocSearchKeyword(pocPath, pocData),
		WebFingerprint: true,
	}
	if bruteMax > 0 {
		spec.BruteMaxRequests = bruteMax
	}
	if needsOOB {
		if s.oob == nil {
			return nil, fmt.Errorf("this PoC verifies out of band: %w", errOOBUnavailable)
		}
		// 只给适配器名：凭据由子进程自己从 afrog-config.yaml 的 reverse 段取，
		// 与 CLI 的 -oob 口径一致，这里不再复制一份凭据读取逻辑。
		spec.EnableOOB = true
		spec.OOBAdapter = s.oob.Adapter()
	}
	return s.runScanSpec(ctx, mcpTaskID(tool), spec, timeout)
}

// pocSearchKeyword 取 -s 用的关键词：优先用 PoC 自身的 id，退回文件名。
//
// 关键词为空会让 -s 失效、变成全库扫描，因此这里必须有非空兜底。
func pocSearchKeyword(pocPath string, pocData []byte) string {
	if len(pocData) > 0 {
		var meta poc.PocMeta
		if err := yaml.Unmarshal(pocData, &meta); err == nil {
			if id := strings.TrimSpace(meta.Id); id != "" {
				return id
			}
		}
	}
	name := filepath.Base(pocPath)
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
	return strings.TrimSpace(name)
}

// resolvePoc 优先使用显式路径；否则按 id 取出 YAML 落到临时文件。
//
// SDK 只接受文件路径，落临时文件同时覆盖了内嵌 PoC（embedded:）的情况。
// 返回的 data 用于估算本次验证的请求预算。
func resolvePoc(pocID, pocPath string) (string, []byte, func(), error) {
	if p := strings.TrimSpace(pocPath); p != "" {
		data, err := os.ReadFile(p)
		if err != nil {
			return "", nil, func() {}, fmt.Errorf("poc_path not readable: %w (need a readable local PoC file; your own PoCs should be saved first via poc.draft with save=true, which returns a poc_path)", err)
		}
		return p, data, func() {}, nil
	}

	id := strings.TrimSpace(pocID)
	data, err := pocsrepo.ReadYamlByID(id)
	if err != nil {
		return "", nil, func() {}, fmt.Errorf("poc %q not found: %w (poc_id must be a real id returned by poc.search; do not invent ids)", id, err)
	}
	f, err := os.CreateTemp("", "afrog-verify-*.yaml")
	if err != nil {
		return "", nil, func() {}, err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", nil, func() {}, err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", nil, func() {}, err
	}
	return f.Name(), data, func() { os.Remove(f.Name()) }, nil
}

// pocEstimate 是对一个 PoC 请求量的静态估算。
type pocEstimate struct {
	Requests int
	// HasBrute 表示存在 YAML 的 brute 块。
	HasBrute bool
	// Uncountable 表示 brute 负载无法静态枚举（例如 CEL 表达式引用字典）。
	Uncountable bool
	// Script 表示规则由 JS/Go 脚本执行：脚本内部可能自行循环发包，
	// 外部既数不出次数，也拦不住 —— 只能按调用方声明的上限预留。
	Script bool
	// NeedsOOB 表示该 PoC 依赖带外（反连）回连下结论：不接反连平台时它无法给出
	// 可信结果，只能 fail-closed，不能当成「没命中」。
	NeedsOOB bool
}

// analyzePoc 静态分析一个 PoC 单目标的潜在请求量。
func analyzePoc(data []byte) pocEstimate {
	est := pocEstimate{Requests: defaultVerifyReserve}
	if len(data) == 0 {
		return est
	}
	var p poc.Poc
	if err := yaml.Unmarshal(data, &p); err != nil {
		return est
	}
	est.NeedsOOB = p.NeedsOOB()

	n := 0
	for _, rm := range p.Rules {
		switch strings.ToLower(strings.TrimSpace(rm.Value.Request.Type)) {
		case "javascript", "go":
			est.Script = true
		}
		combos, brute, unknown := bruteCombinations(rm.Value.Brute)
		if brute {
			est.HasBrute = true
		}
		if unknown {
			est.Uncountable = true
		}
		if combos > 1 {
			n += combos
		} else {
			n++
		}
		if n >= maxVerifyReserve {
			est.Requests = maxVerifyReserve
			return est
		}
	}
	if n > 0 {
		est.Requests = n
	}
	return est
}

// estimatePocRequests 返回静态估算的请求数。
func estimatePocRequests(data []byte) int {
	return analyzePoc(data).Requests
}

// reserveForBrute 计算 act.brute 的预算预留。
//
// 字典能静态计数时按组合数预留；遇到 CEL 字典或 JS/Go 脚本 PoC 时，
// 直接按调用方给的 max_requests 预留——那是本次真正可能发出的上限。
func reserveForBrute(data []byte, maxReq int) int {
	if maxReq <= 0 {
		maxReq = 1
	}
	est := analyzePoc(data)
	if est.Uncountable || est.Script {
		return maxReq
	}
	if est.Requests > maxReq {
		return maxReq
	}
	return est.Requests
}

func bruteCombinations(brute yaml.MapSlice) (combos int, has bool, uncountable bool) {
	combos = 1
	for _, item := range brute {
		key, ok := item.Key.(string)
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "mode", "commit", "continue":
			continue
		}
		has = true
		switch v := item.Value.(type) {
		case []any:
			if len(v) > 0 {
				combos *= len(v)
			} else {
				uncountable = true
			}
		case []string:
			if len(v) > 0 {
				combos *= len(v)
			} else {
				uncountable = true
			}
		default:
			// 字符串形式的 CEL 表达式 / 函数引用，无法静态枚举。
			uncountable = true
		}
		if combos >= maxVerifyReserve {
			return maxVerifyReserve, has, uncountable
		}
	}
	return combos, has, uncountable
}

func decodeArgs(raw json.RawMessage, dst any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	return json.Unmarshal(raw, dst)
}

func clampText(s string, limit int) string {
	if limit <= 0 || len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\n...[truncated]"
}
