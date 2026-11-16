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
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/ref"
	"gopkg.in/yaml.v2"
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
	// Search 是 scan.start 的技术栈关键词（逗号分隔），即 afrog 的 -s 入参。
	// probe.fingerprint 等无参动作留空。
	Search string `json:"search,omitempty"`
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
	// RequiresOOB 表示这条提议靠带外（反连）回连下结论：执行它需要反连平台，
	// 否则 scan.start 会 fail-closed。调用方据此先补配置，或改选别的提议。
	RequiresOOB bool `json:"requires_oob,omitempty"`
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

// candidateProposals 把「端点 → 技术栈 → 候选 PoC」压成按源站合并的 scan.start 提议。
//
// 归并口径是 origin：同一个源站上的候选不再逐个 PoC 提一条，而是合成一条「按该源站
// 识别出的技术栈关键词、一次并发跑完整批 PoC」的 scan.start——这正是 afrog -s 的用法。
// 逐个 PoC 串行验证既慢，又会让「单跑一个漏洞 PoC 被指纹门控跳过」，与 afrog 的两阶段
// 扫描相悖。Search 因此取技术栈名而非 PoC id：-s 命中 id/名称/标签，且指纹 PoC 一律
// 被保留，于是指纹阶段照常运行、requires 按真实指纹放行。
//
// 返回的 excluded 是「已有结论、不再提议」的候选组合数（PoC + 源站）：同一个源站上若
// 还有未出结论的候选 PoC，该源站仍会提议——-s 会把它们一起跑。
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
		origin      string
		score       int
		severity    string
		requiresOOB bool
		techs       map[string]struct{}
		points      map[string]struct{}
		pocs        map[string]struct{}
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
		if _, ok := concluded[proposalKey(pocID, origin)]; ok {
			excluded++
			continue
		}
		g := groups[origin]
		if g == nil {
			g = &group{
				origin: origin,
				techs:  make(map[string]struct{}, 2),
				points: make(map[string]struct{}, 2),
				pocs:   make(map[string]struct{}, 4),
			}
			groups[origin] = g
		}
		item, _ := meta(pocID)
		severity := strings.ToLower(strings.TrimSpace(item.Severity))
		score := scoreCandidateBase + severityWeight(severity)*10
		if item.Verified {
			score += scoreVerifiedBonus
		}
		if score > g.score {
			g.score = score
		}
		if severityWeight(severity) > severityWeight(g.severity) {
			g.severity = severity
		}
		if pocNeedsOOB(pocID) {
			g.requiresOOB = true
		}
		g.pocs[pocID] = struct{}{}
		if tech != "" {
			g.techs[tech] = struct{}{}
		}
		g.points[r.Endpoint] = struct{}{}
	}

	out := make([]Proposal, 0, len(groups))
	for _, g := range groups {
		techs := sortedKeys(g.techs)
		search := strings.Join(techs, ",")
		if search == "" {
			// 没有技术栈名可做关键词时退回候选 PoC id：-s 同样命中 PoC id，
			// 且不能为空——空关键词会退化成全库扫描。
			search = strings.Join(sortedKeys(g.pocs), ",")
		}
		out = append(out, Proposal{
			Action:      Action{Name: "scan.start", Target: g.origin, Search: search},
			Category:    CategoryCandidatePoc,
			Score:       g.score,
			Severity:    g.severity,
			RequiresOOB: g.requiresOOB,
			Rationale:   candidateRationale(techs),
			Evidence:    append(sortedKeys(g.points), techNodes(techs)...),
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

// sortProposals 固定排序：分数降序 → 动作名 → 目标 → 关键词。
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
		return a.Action.Search < b.Action.Search
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
		return "该源站识别出的技术栈有现成 PoC，按同一套 requires 准入语义成为候选。"
	}
	return "源站使用 " + strings.Join(techs, "、") + "，其 requires 声明的 PoC 是候选；用 scan.start 按这批关键词一次并发跑完，候选不是结论。"
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

// pocNeedsOOB 判断一个 PoC 是否依赖带外（反连）验证。
//
// 与 pocMetadata 分开而不是塞进 Item：元信息来自 ListMeta，只解析 info 段；是否需要
// 反连写在 rules 段里，只有读全文才知道。全库读一遍代价太大，所以这里按需读取并缓存，
// 不因此拖慢列表。抽成变量同样是为了让提议逻辑的测试不必依赖真实 PoC 库的内容。
var pocNeedsOOB = defaultPocNeedsOOB

var (
	pocOOBCacheMu sync.Mutex
	pocOOBCache   = map[string]bool{}
)

func defaultPocNeedsOOB(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}

	pocOOBCacheMu.Lock()
	cached, ok := pocOOBCache[id]
	pocOOBCacheMu.Unlock()
	if ok {
		return cached
	}

	needs := false
	if data, err := pocsrepo.ReadYamlByID(id); err == nil && len(data) > 0 {
		var p poc.Poc
		if yaml.Unmarshal(data, &p) == nil {
			needs = p.NeedsOOB()
		}
	}

	pocOOBCacheMu.Lock()
	pocOOBCache[id] = needs
	pocOOBCacheMu.Unlock()
	return needs
}
