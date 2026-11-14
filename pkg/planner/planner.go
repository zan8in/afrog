// Package planner 是确定性的「下一步试什么」提议器。
//
// 定位：不发包、不做策略判定、不推断漏洞状态。输入是攻击面图与既有结论，输出是
// 一份有依据、可排序的 Action 提议列表；执行与否由调用方的策略与预算门控决定。
//
// 与决策面的关系：模型可以提议，但提议本身不该依赖模型——同样的图必然得到同样的
// 顺序，否则「为什么先打这条」无法复盘。这里给出的是不依赖模型的确定性基线。
package planner

import (
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/ref"
)

const (
	// DefaultLimit 是单次规划默认返回的提议数。
	DefaultLimit = 20
	// MaxLimit 是提议数上限：列表会被 Agent 整段读进上下文，不适合无界返回。
	MaxLimit = 200
)

// 打分只服务于排序，绝对值没有含义；同一份图必然得到同一个顺序。
const (
	scoreCandidateBase = 100
	scoreVerifiedBonus = 3
	scoreUnknownTech   = 50
)

// 提议类别，说明这条提议「为什么会出现」。
const (
	// CategoryCandidatePoc 表示端点上的技术栈有现成 PoC 值得验证。
	CategoryCandidatePoc = "candidate_poc"
	// CategoryUnknownTech 表示端点所在的 origin 还没识别过技术栈。
	CategoryUnknownTech = "unknown_tech"
)

// Action 是一条待执行的原子动作，与 MCP 工具同名同参。
type Action struct {
	Name   string `json:"name"`
	Target string `json:"target"`
	PocID  string `json:"poc_id,omitempty"`
}

// Proposal 是一条提议，带依据与解释。
type Proposal struct {
	Action Action `json:"action"`
	// Category 说明提议来源，便于调用方按类过滤。
	Category string `json:"category"`
	// Score 只用于排序。
	Score int `json:"score"`
	// Severity 是候选 PoC 的等级；未知时为空。
	Severity string `json:"severity,omitempty"`
	// Rationale 是一句人话结论，直接可以展示给使用者。
	Rationale string `json:"rationale"`
	// Evidence 是得出这条提议的依据（图上的端点 / 技术栈节点）。
	Evidence []string `json:"evidence"`
}

// Options 是规划输入。
type Options struct {
	// ProjectID 只用于「不要重复提议已经确认过的组合」：项目归属与台账同口径。
	ProjectID string
	// Subject 限定规划范围（一个端点 URL，或配合 Under 当作前缀）。
	Subject string
	// Under 为 true 时按 URL 前缀展开 Subject。
	Under bool
	// Limit 是返回的提议数上限。
	Limit int
}

// Plan 是一次规划结果。
type Plan struct {
	ProjectID string     `json:"project_id"`
	Subject   string     `json:"subject,omitempty"`
	Proposals []Proposal `json:"proposals"`
	// Truncated 表示提议数超过 Limit 被截断。
	Truncated bool `json:"truncated"`
	// Excluded 是「已有结论、不再提议」的数量，用来解释候选为何变少。
	Excluded int `json:"excluded"`
}

// Build 生成提议列表。命名与 assetgraph.Build 一致：同样的输入必然得到同样的输出。
func Build(opts Options) (*Plan, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}

	subject := strings.TrimSpace(opts.Subject)
	if subject != "" {
		if normalized, err := ref.NormalizeEndpoint(subject); err == nil {
			subject = normalized
		}
	}

	out := &Plan{ProjectID: strings.TrimSpace(opts.ProjectID), Subject: subject}

	proposals, excluded, err := candidateProposals(out.ProjectID, subject, opts.Under)
	if err != nil {
		return nil, err
	}
	out.Excluded = excluded

	unknown, err := unknownTechProposals(subject, opts.Under)
	if err != nil {
		return nil, err
	}
	proposals = append(proposals, unknown...)

	sortProposals(proposals)
	if len(proposals) > limit {
		proposals = proposals[:limit]
		out.Truncated = true
	}
	out.Proposals = proposals
	return out, nil
}

// candidateProposals 把「端点 → 技术栈 → 候选 PoC」压成 verify.poc 提议。
//
// 归并口径是「PoC + origin」：同一个 PoC 在同一个 origin 上不该被提议多次——
// PoC 自己会拼路径，按端点逐条提议只会把同一件事重复 N 遍。返回的 excluded 是
// 历史上已经出过结果行、被跳过的组合数。
func candidateProposals(projectID, subject string, under bool) ([]Proposal, int, error) {
	rows, err := sqlite.SelectTechCandidates(subject, under)
	if err != nil {
		return nil, 0, err
	}
	if len(rows) == 0 {
		return nil, 0, nil
	}

	pocIDs := make([]string, 0, len(rows))
	seenPoc := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		if pocID := sqlite.TrimPocAssetID(r.PocID); pocID != "" {
			if _, ok := seenPoc[pocID]; !ok {
				seenPoc[pocID] = struct{}{}
				pocIDs = append(pocIDs, pocID)
			}
		}
	}

	overlaps, err := sqlite.SelectFindingOverlaps(pocIDs, projectID)
	if err != nil {
		return nil, 0, err
	}
	concluded := make(map[string]struct{}, len(overlaps))
	for _, o := range overlaps {
		if key := proposalKey(o.PocID, originOf(o.FullTarget)); key != "" {
			concluded[key] = struct{}{}
		}
	}

	meta := pocMetadata
	type group struct {
		origin   string
		pocID    string
		score    int
		severity string
		techs    map[string]struct{}
		points   map[string]struct{}
	}
	groups := make(map[string]*group, len(rows))
	excluded := 0
	for _, r := range rows {
		pocID := sqlite.TrimPocAssetID(r.PocID)
		origin := originOf(r.Endpoint)
		tech := sqlite.TrimTechAssetID(r.Tech)
		if pocID == "" || origin == "" {
			continue
		}
		key := proposalKey(pocID, origin)
		if _, ok := concluded[key]; ok {
			excluded++
			continue
		}
		g := groups[key]
		if g == nil {
			item, _ := meta(pocID)
			severity := strings.ToLower(strings.TrimSpace(item.Severity))
			score := scoreCandidateBase + severityWeight(severity)*10
			if item.Verified {
				score += scoreVerifiedBonus
			}
			g = &group{
				origin: origin, pocID: pocID, score: score, severity: severity,
				techs:  make(map[string]struct{}, 2),
				points: make(map[string]struct{}, 2),
			}
			groups[key] = g
		}
		if tech != "" {
			g.techs[tech] = struct{}{}
		}
		g.points[r.Endpoint] = struct{}{}
	}

	out := make([]Proposal, 0, len(groups))
	for _, g := range groups {
		techs := sortedKeys(g.techs)
		out = append(out, Proposal{
			Action:    Action{Name: "verify.poc", Target: g.origin, PocID: g.pocID},
			Category:  CategoryCandidatePoc,
			Score:     g.score,
			Severity:  g.severity,
			Rationale: candidateRationale(techs),
			Evidence:  append(sortedKeys(g.points), techNodes(techs)...),
		})
	}
	return out, excluded, nil
}

// unknownTechProposals 提议对「还没识别过技术栈」的 origin 做一次指纹。
//
// 先收敛到 origin 再判断：只要该 origin 下任何一个端点识别出了技术栈，整个 origin
// 就算指纹过，避免为一台主机上的每个端点各发一次请求。
func unknownTechProposals(subject string, under bool) ([]Proposal, error) {
	unknown, err := sqlite.SelectEndpointsWithoutTech(subject, under)
	if err != nil {
		return nil, err
	}
	if len(unknown) == 0 {
		return nil, nil
	}
	known, err := sqlite.SelectTechEndpoints(subject, under)
	if err != nil {
		return nil, err
	}
	fingerprinted := make(map[string]struct{}, len(known))
	for _, endpoint := range known {
		if origin := originOf(endpoint); origin != "" {
			fingerprinted[origin] = struct{}{}
		}
	}

	points := make(map[string]map[string]struct{}, len(unknown))
	for _, endpoint := range unknown {
		origin := originOf(endpoint)
		if origin == "" {
			continue
		}
		if _, ok := fingerprinted[origin]; ok {
			continue
		}
		if points[origin] == nil {
			points[origin] = make(map[string]struct{}, 2)
		}
		points[origin][endpoint] = struct{}{}
	}

	out := make([]Proposal, 0, len(points))
	for origin, seen := range points {
		endpoints := sortedKeys(seen)
		out = append(out, Proposal{
			Action:    Action{Name: "probe.fingerprint", Target: origin},
			Category:  CategoryUnknownTech,
			Score:     scoreUnknownTech,
			Rationale: "该源站还没有识别出任何技术栈，指纹后才能判断有哪些现成 PoC 值得验证。",
			Evidence:  endpoints,
		})
	}
	return out, nil
}

// sortProposals 固定排序：分数降序 → 动作名 → 目标 → PoC id。
// 后面的字段保证任何输入都得到唯一顺序，重跑不会抖动。
func sortProposals(items []Proposal) {
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Action.Name != b.Action.Name {
			return a.Action.Name < b.Action.Name
		}
		if a.Action.Target != b.Action.Target {
			return a.Action.Target < b.Action.Target
		}
		return a.Action.PocID < b.Action.PocID
	})
}

// proposalKey 是归并键：同一 PoC 在同一 origin 上算一条。
func proposalKey(pocID, origin string) string {
	pocID = strings.TrimSpace(pocID)
	if pocID == "" || origin == "" {
		return ""
	}
	return pocID + "|" + origin
}

// originOf 把 URL 压成「协议 + 主机」，默认端口按 ref 的归一化口径去掉。
//
// 归一化复用 ref.NormalizeEndpoint：否则 http://h 与 http://h:80 会被当成两个目标。
func originOf(raw string) string {
	normalized, err := ref.NormalizeEndpoint(raw)
	if err != nil {
		return ""
	}
	u, err := url.Parse(normalized)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// severityWeight 是等级的排序权重，与漏洞库展示等级一致。
func severityWeight(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

func candidateRationale(techs []string) string {
	if len(techs) == 0 {
		return "该端点识别出的技术栈有现成 PoC，按同一套 requires 准入语义成为候选。"
	}
	return "端点使用 " + strings.Join(techs, "、") + "，其 requires 声明的 PoC 是候选；候选不是结论，需 verify 确认。"
}

func techNodes(techs []string) []string {
	out := make([]string, 0, len(techs))
	for _, t := range techs {
		out = append(out, sqlite.TechAssetID(t))
	}
	return out
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pocMetadata 是规划器唯一依赖的 PoC 元信息入口。
//
// 抽成变量而不是直接调用 pocsrepo：一是全库元信息（几千个 YAML）在进程内只解析
// 一次，二是排序逻辑的测试不必依赖真实 PoC 库的内容。
var pocMetadata = defaultPocMetadata

var (
	pocMetaOnce sync.Once
	pocMetaByID map[string]pocsrepo.Item
)

func defaultPocMetadata(id string) (pocsrepo.Item, bool) {
	pocMetaOnce.Do(func() {
		items, err := pocsrepo.ListMeta(pocsrepo.ListOptions{Source: "all"})
		if err != nil {
			pocMetaByID = map[string]pocsrepo.Item{}
			return
		}
		idx := make(map[string]pocsrepo.Item, len(items))
		for _, it := range items {
			if it.ID == "" {
				continue
			}
			idx[it.ID] = it
		}
		pocMetaByID = idx
	})
	item, ok := pocMetaByID[id]
	return item, ok
}
