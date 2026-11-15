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
	"github.com/zan8in/afrog/v3/pkg/judge"
	"github.com/zan8in/afrog/v3/pkg/learner"
	"github.com/zan8in/afrog/v3/pkg/observation"
	"github.com/zan8in/afrog/v3/pkg/planner"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/policy"
	"github.com/zan8in/afrog/v3/pkg/portscan"
	"github.com/zan8in/afrog/v3/pkg/sdk"
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
		s.verifyPocTool(),
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
		Description: "按项目、状态、严重级别列出漏洞结论（Finding）：同一主体上的同一类漏洞聚合为一条，带内容寻址 id 与证据引用（evidence[]）。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"project_id": map[string]any{"type": "string", "description": "项目 ID；留空表示全局"},
				"status":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "pending/confirmed/false_positive/fixed"},
				"severity":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"keyword":    map[string]any{"type": "string"},
				"page":       map[string]any{"type": "integer", "minimum": 1},
				"limit":      map[string]any{"type": "integer", "minimum": 1, "maximum": 200},
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
		Description: "按 result 主键或证据内容寻址 ID（evd_ 前缀）取一条可重放证据。",
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
				return nil, fmt.Errorf("evidence not found for %q", id)
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
		Description: "以某个资产（id 或地址）为根，返回攻击面子图：上下游资产、端点与参数、技术栈与候选 PoC（tech:/poc: 派生节点）、被动覆盖与命中数。",
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
		Description: "按 seq 游标增量拉取观测流（开放端口 / Web 指纹 / HTTP 事务 / 被动代理流量 / TLS 证书 / 带外回连 / DNS 解析）。只读、零预算；next_seq 直接作为下次的 since_seq。",
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
		Description: "给出下一步的 Action 提议（verify.poc / probe.fingerprint），按确定性分数排序；候选与未知面都带依据。只读、零预算，执行仍需 verify.*/probe.* 过策略门控。",
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
		Description: "按关键词与严重级别检索 PoC，返回 id、名称、级别与本地路径。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"keyword":  map[string]any{"type": "string", "description": "匹配 id / 名称 / 标签 / 作者"},
				"severity": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"limit":    map[string]any{"type": "integer", "minimum": 1, "maximum": 200},
			},
			"required": []string{},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			if err := s.gate.Take(policy.Action{Name: "poc.search"}, 0); err != nil {
				return nil, err
			}

			return agentapi.SearchPocs(a.Keyword, a.Severity, a.Limit)
		},
	}
}

// --- poc.draft ---

// draftIDRe 限定草稿 id：id 会直接成为落盘文件名，必须挡住 ../ 之类的路径穿越。
var draftIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// pocDraftTool 校验模型产出的 PoC 草稿，不发包。
//
// 分工：草稿由模型写，afrog 只负责结构校验、能力等级与请求量估算，并可选落盘，
// 让 verify.poc 能直接拿着 poc_path 去验证。判定是否漏洞仍然只发生在 verify.poc。
func (s *Server) pocDraftTool() *Tool {
	type args struct {
		Yaml    string `json:"yaml"`
		PocPath string `json:"poc_path"`
		Save    bool   `json:"save"`
	}
	return &Tool{
		Name:        "poc.draft",
		Description: "校验一份 PoC 草稿（yaml 字符串或本地 poc_path），返回结构、能力等级与请求量估算；save=true 时落盘并给出可直接交给 verify.poc 的 poc_path。不发送任何请求。",
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
		Description: "在一台真实目标上受限实跑一份草稿并取证据，通过后放入待人工终审队列（afrog poc approve/reject）。实跑会发包。",
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
				return nil, fmt.Errorf("poc_path is required")
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
			out, err := s.runSinglePoc(ctx, target, pocPath, timeout, 0, est.NeedsOOB)
			if err != nil {
				return nil, err
			}
			ev := firstEvidence(out)
			if ev == nil {
				return map[string]any{
					"submitted": false,
					"reason":    "sandbox run produced no evidence; the candidate did not reproduce on the target",
					"target":    target,
					"results":   out,
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
		Description: "发起一次受限的 HTTP 请求（单次、可重放），用于确认端点行为。",
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
		Description: "对单个主机做受限端口探测，返回开放端口与服务指纹。ports 支持 top100/top1000、单端口、区间（如 8000-8100），留空为 top100；单次最多 1000 个端口，按端口数扣预算。",
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

const (
	fpBodyLimit    = 1024 * 1024
	fpMaxRedirects = 5
	fpFaviconLimit = 512 * 1024
	fpUserAgent    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

var fpTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func (s *Server) probeFingerprintTool() *Tool {
	type args struct {
		URL        string `json:"url"`
		Favicon    bool   `json:"favicon"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	return &Tool{
		Name:        "probe.fingerprint",
		Description: "对单个 URL 做一次 Web 指纹识别：技术栈、WAF/CDN、跳转链与 TLS 摘要。默认不发 favicon 请求。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url":         map[string]any{"type": "string", "description": "绝对 URL，缺省协议时按 http 处理"},
				"favicon":     map[string]any{"type": "boolean", "description": "额外抓取一次 /favicon.ico（多一次请求与预算）"},
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

			var redirects []string
			client := &http.Client{
				Timeout: timeout,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					if len(via) >= fpMaxRedirects {
						return http.ErrUseLastResponse
					}
					redirects = append(redirects, req.URL.String())
					return nil
				},
			}
			req, err := http.NewRequestWithContext(runCtx, http.MethodGet, target, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("User-Agent", fpUserAgent)
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			reqHeaders := make(map[string]string, len(req.Header))
			for k, vs := range req.Header {
				reqHeaders[k] = strings.Join(vs, ", ")
			}

			start := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(io.LimitReader(resp.Body, fpBodyLimit))
			if err != nil {
				return nil, err
			}
			latency := time.Since(start).Milliseconds()

			headers := make(map[string]string, len(resp.Header))
			for k, vs := range resp.Header {
				headers[strings.ToLower(k)] = strings.Join(vs, ", ")
			}

			matcher, err := s.webMatcher()
			if err != nil {
				return nil, err
			}
			var favicon []byte
			if a.Favicon {
				favicon = fetchFavicon(runCtx, resp.Request.URL)
			}
			matched := matcher.Match(webscan.Response{
				StatusCode: resp.StatusCode,
				Headers:    headers,
				Body:       body,
				Favicon:    favicon,
				RequestURL: resp.Request.URL.String(),
				Cookies:    resp.Header.Values("Set-Cookie"),
			})

			techs := make([]map[string]any, 0, len(matched.Technologies))
			waf := make([]string, 0, 2)
			cdn := make([]string, 0, 2)
			for _, t := range matched.Technologies {
				techs = append(techs, map[string]any{
					"name":       t.Name,
					"version":    t.Version,
					"category":   t.Category,
					"cpe":        t.CPE,
					"confidence": t.Confidence.String(),
				})
				switch strings.ToLower(t.Category) {
				case "waf":
					waf = append(waf, t.Name)
				case "cdn":
					cdn = append(cdn, t.Name)
				}
			}

			out := map[string]any{
				"url":          resp.Request.URL.String(),
				"status":       resp.StatusCode,
				"title":        extractHTMLTitle(body),
				"server":       headers["server"],
				"powered_by":   headers["x-powered-by"],
				"technologies": techs,
				"confidence":   matched.Confidence.String(),
				"waf":          waf,
				"cdn":          cdn,
				"redirects":    redirects,
				"favicon_hash": matched.FaviconHash,
				"latency_ms":   latency,
			}
			if tls := tlsSummary(resp); tls != nil {
				out["tls"] = tls
			}

			recordHTTPObservation("", http.MethodGet, resp.Request.URL.String(), resp.StatusCode,
				len(matched.Technologies) > 0, latency,
				describeRequest(http.MethodGet, resp.Request.URL.String(), reqHeaders),
				describeResponse(resp, body))
			recordTechObservation(resp.Request.URL.String(), resp.StatusCode,
				extractHTMLTitle(body), headers["server"], headers["x-powered-by"], matched)

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

func extractHTMLTitle(body []byte) string {
	m := fpTitleRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return clampText(strings.TrimSpace(string(m[1])), 200)
}

func tlsSummary(resp *http.Response) map[string]any {
	if resp == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil
	}
	leaf := resp.TLS.PeerCertificates[0]
	return map[string]any{
		"subject":   leaf.Subject.String(),
		"issuer":    leaf.Issuer.String(),
		"not_after": leaf.NotAfter.Format("2006-01-02"),
		"dns_names": leaf.DNSNames,
	}
}

// fetchFavicon 抓一次 /favicon.ico；失败只影响 favicon 规则，不影响主结果。
func fetchFavicon(ctx context.Context, base *url.URL) []byte {
	if base == nil {
		return nil
	}
	u := *base
	u.Path = "/favicon.ico"
	u.RawQuery = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, fpFaviconLimit))
	if err != nil {
		return nil
	}
	return data
}

// --- verify.poc ---

func (s *Server) verifyPocTool() *Tool {
	type args struct {
		PocID      string `json:"poc_id"`
		PocPath    string `json:"poc_path"`
		Target     string `json:"target"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	return &Tool{
		Name:        "verify.poc",
		Description: "用单个 PoC 验证单个目标，返回可重放证据。可按 poc_id 或本地 yaml 路径指定。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"poc_id":      map[string]any{"type": "string"},
				"poc_path":    map[string]any{"type": "string", "description": "本地 PoC YAML 路径，优先于 poc_id"},
				"target":      map[string]any{"type": "string", "description": "目标 URL 或 host:port"},
				"timeout_sec": map[string]any{"type": "integer", "minimum": 5, "maximum": 300},
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
				return nil, fmt.Errorf("poc_id or poc_path is required")
			}

			pocPath, pocData, cleanup, err := resolvePoc(a.PocID, a.PocPath)
			if err != nil {
				return nil, err
			}
			defer cleanup()

			// 预算按 PoC 实际可能发出的请求数预留，而不是固定拍一个数。
			// 含无法静态计数的 brute 时按上限保守预留：爆破应走 act.brute。
			est := analyzePoc(pocData)
			reserve := est.Requests
			if est.Uncountable {
				reserve = maxVerifyReserve
			}
			if err := s.gate.Take(policy.Action{
				Name:       "verify.poc",
				Target:     target,
				Capability: capability.Declarative,
			}, reserve); err != nil {
				return nil, err
			}

			timeout := time.Duration(a.TimeoutSec) * time.Second
			if timeout <= 0 {
				timeout = 60 * time.Second
			}
			out, err := s.runSinglePoc(ctx, target, pocPath, timeout, 0, est.NeedsOOB)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"found":   len(out) > 0,
				"results": out,
				"target":  target,
			}, nil
		},
	}
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
		Description: "按证据 id（evd_ 前缀）或 result id 重放一次，返回新证据并比对 digest 是否一致。target 留空沿用证据里的目标。",
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
				return nil, fmt.Errorf("evidence not found for %q", id)
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
				return nil, fmt.Errorf("target is required: evidence has none")
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
			out, err := s.runSinglePoc(ctx, target, pocPath, timeout, 0, est.NeedsOOB)
			if err != nil {
				return nil, err
			}

			actual := firstEvidence(out)
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
// 草稿路径让「模型写、verify.poc 验证、verify.replay 复核」这条链路真正闭环。
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
		Description: "【破坏性】用带 brute 字典的 PoC 对目标做弱口令/字典尝试。默认策略拒绝，需先授予 full 模式且 destructive=true。",
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
				return nil, fmt.Errorf("poc_id or poc_path is required")
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
			out, err := s.runSinglePoc(ctx, target, pocPath, timeout, maxReq, analyzePoc(pocData).NeedsOOB)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"found":        len(out) > 0,
				"results":      out,
				"target":       target,
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
		Description: "按 result id 或 evd_ 证据 id 取一条命中的研判材料：证据链、同目标周边观测、攻击面子图与已有研判意见。只读、零预算。",
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
		Description: "记录一条研判意见（likely_true/likely_false/uncertain）到 judgement 表，作为 advisory 供人工复核；不修改漏洞台账。",
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
		Description: "取调优素材：流水线指标（含自动入库率）、最近终审决议（含驳回原因）与待审调优建议。只读、零预算。",
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
		Description: "记录一条调优建议（rule/threshold/other）到 learn_suggestion 表，供人工审阅；不自动应用任何 diff。",
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

// runSinglePoc 串行执行一个 PoC 对单个目标，返回归一化结果。
//
// SDK 内部有进程级全局状态，不支持并行扫描，因此这里用 verifyMu 串行化。
//
// needsOOB 由调用方从 analyzePoc 得到：反向 PoC 的回连判定依赖反连平台，SDK 的
// SDKMode 会在缺 OOB 时把这些 PoC 直接记成「未命中」。那是一个说不清楚的假阴性，
// 所以这里改成两条明确路径：有 OOB 就真的接上，没有就报错，绝不下空结论。
func (s *Server) runSinglePoc(ctx context.Context, target, pocPath string, timeout time.Duration, maxRequests int, needsOOB bool) ([]map[string]any, error) {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	s.verifyMu.Lock()
	defer s.verifyMu.Unlock()

	opts := []sdk.Option{
		sdk.WithTargets(target),
		sdk.WithPocPaths(pocPath),
		sdk.WithPocPathsOnly(),
		sdk.WithConcurrency(1),
		sdk.WithRateLimit(10),
		sdk.WithTimeout(int(timeout.Seconds())),
		sdk.WithFingerprintDisabled(),
		// 单 PoC 验证不需要 Web 探测：它会产生预算之外的额外请求，
		// 还会把 webprobe 汇总写进 result 表，污染「只跑一个 PoC」的语义。
		sdk.WithWebProbe(false),
		sdk.WithStopOnFirstMatch(),
	}
	if needsOOB {
		if s.oob == nil {
			return nil, fmt.Errorf("this PoC verifies out of band: %w", errOOBUnavailable)
		}
		// 只给适配器名：凭据由 SDK 自己从 afrog-config.yaml 的 reverse 段取，
		// 与 CLI 的 -oob 口径一致，这里不再复制一份凭据读取逻辑。
		opts = append(opts, sdk.WithOOB(sdk.OOBOptions{Adapter: s.oob.Adapter()}))
	}
	if maxRequests > 0 {
		opts = append(opts, sdk.WithBruteMaxRequests(maxRequests))
	}

	scanner, err := sdk.New(runCtx, opts...)
	if err != nil {
		return nil, err
	}
	defer scanner.Close()

	if err := scanner.Execute(runCtx); err != nil && runCtx.Err() == nil {
		return nil, err
	}

	results := scanner.Results()
	out := make([]map[string]any, 0, len(results))
	for _, r := range results {
		// verify.* 是 Agent 主动触发的动作，按设计稿只在这里记 http_transaction，
		// 与引擎侧「扫描阶段的事实」不重复。
		for _, ex := range r.Exchanges {
			request := ex.Request
			if strings.TrimSpace(request) == "" {
				request = describeRequest(ex.Method, ex.URL, ex.RequestHeaders)
			}
			response := ex.Response
			if strings.TrimSpace(response) == "" {
				response = ex.ResponseBody
			}
			recordHTTPObservation(r.PocID, ex.Method, ex.URL, ex.StatusCode, ex.Matched, ex.LatencyMs, request, response)
		}
		out = append(out, map[string]any{
			"poc_id":     r.PocID,
			"poc_name":   r.PocName,
			"severity":   r.Severity,
			"target":     r.FullTarget,
			"evidence":   r.Evidence,
			"exchanges":  sanitizeExchanges(r.Exchanges),
			"extractors": r.Extractors,
		})
	}
	return out, nil
}

func sanitizeExchanges(in []sdk.Exchange) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, ex := range in {
		out = append(out, map[string]any{
			"method":        ex.Method,
			"url":           ex.URL,
			"status_code":   ex.StatusCode,
			"matched":       ex.Matched,
			"latency_ms":    ex.LatencyMs,
			"request":       clampText(ex.Request, toolBodyLimit),
			"response":      clampText(ex.Response, toolBodyLimit),
			"response_body": clampText(ex.ResponseBody, toolBodyLimit),
		})
	}
	return out
}

// resolvePoc 优先使用显式路径；否则按 id 取出 YAML 落到临时文件。
//
// SDK 只接受文件路径，落临时文件同时覆盖了内嵌 PoC（embedded:）的情况。
// 返回的 data 用于估算本次验证的请求预算。
func resolvePoc(pocID, pocPath string) (string, []byte, func(), error) {
	if p := strings.TrimSpace(pocPath); p != "" {
		data, err := os.ReadFile(p)
		if err != nil {
			return "", nil, func() {}, fmt.Errorf("poc_path not readable: %w", err)
		}
		return p, data, func() {}, nil
	}

	id := strings.TrimSpace(pocID)
	data, err := pocsrepo.ReadYamlByID(id)
	if err != nil {
		return "", nil, func() {}, fmt.Errorf("poc %q not found: %w", id, err)
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
