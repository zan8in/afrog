// Package agentapi 是 Agent 的只读数据面：MCP 工具与 REST（/api/v1）共用同一份语义。
//
// 这里只放「读模型」：不涉及策略、预算、审计与网络动作。把查询口径收在一处，
// 避免 MCP 与 REST 各写一遍、慢慢漂移。
package agentapi

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/assetgraph"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/evidence"
	"github.com/zan8in/afrog/v3/pkg/planner"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
)

// Findings 返回由 result / vuln_ledger / task_project / evidence 四表投影出的漏洞
// 结论（Finding）分页：聚合口径为类目级（project_id + subject + vuln_class）。
func Findings(f sqlite.LedgerFilter) (*sqlite.FindingPage, error) {
	page, err := sqlite.SelectFindings(f)
	if err != nil {
		return nil, err
	}
	// DB 聚合层把 severity 统一成大写（pkg/db/sqlite/finding.go 的 groupFindings 用它
	// 做组间取高比较），但 agent 面的输入 enum 与 scan.start 的 severity 都是小写。
	// 在只读投影的出口归一到小写，让 MCP observe.findings 与 REST /api/v1/findings
	// （二者同源）与 scan.start 同口径；DB 层的 ToUpper 不动。
	for i := range page.Items {
		page.Items[i].Severity = strings.ToLower(strings.TrimSpace(page.Items[i].Severity))
	}
	return page, nil
}

// Evidence 按证据 id（evd_ 前缀）或 result 主键取证据。
func Evidence(id string) (*evidence.Evidence, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("id is required")
	}
	if strings.HasPrefix(id, "evd_") {
		return sqlite.SelectEvidenceByID(id)
	}
	resultID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid id %q", id)
	}
	return sqlite.SelectEvidenceByResultID(resultID)
}

// StateResult 是攻击面子图查询结果。
//
// Known 区分「库里真实存在的资产」与「仅按地址合成的根节点」，避免调用方把
// 一个从未扫描过的地址误当成已有资产。
type StateResult struct {
	Known bool                 `json:"known"`
	Graph *assetgraph.Response `json:"graph"`
}

// State 以某个资产（id 或地址）为根返回子图。
func State(subject, projectID string, depth int, direction string) (*StateResult, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, fmt.Errorf("subject is required")
	}
	if depth <= 0 {
		depth = assetgraph.DefaultDepth
	}
	if depth > assetgraph.MaxDepth {
		depth = assetgraph.MaxDepth
	}
	direction = strings.ToLower(strings.TrimSpace(direction))
	switch direction {
	case "up", "down":
	default:
		direction = "both"
	}

	known := false
	if nodes, err := sqlite.SelectAssetNodes([]string{subject}); err == nil && len(nodes) > 0 {
		known = true
	}

	graph, err := assetgraph.Build(assetgraph.Options{
		Root:      subject,
		Depth:     depth,
		Direction: direction,
		ProjectID: projectID,
	})
	if err != nil {
		return nil, err
	}
	return &StateResult{Known: known, Graph: graph}, nil
}

// Observations 按 seq 游标增量拉取观测流。
func Observations(f sqlite.ObservationFilter) (*sqlite.ObservationPage, error) {
	return sqlite.SelectObservations(f)
}

// Plan 返回确定性的「下一步试什么」提议列表。
//
// 只读：提议不产生流量，也不改任何状态；执行与否由调用方再走一次策略门控。
func Plan(opts planner.Options) (*planner.Plan, error) {
	return planner.Build(opts)
}

// PocSearchResult 是 PoC 检索结果。
//
// Count 是本次返回的条数，Total 是命中总数，Truncated 表示命中数超过 limit 被截断。
// 三者都给出来，调用方才分得清「本地只有这么多」和「还有很多但被截断了」——后者应当
// 继续收窄条件，而不是把手里这批当成全集。
type PocSearchResult struct {
	Items     []map[string]any `json:"items"`
	Count     int              `json:"count"`
	Total     int              `json:"total"`
	Truncated bool             `json:"truncated"`
}

// SearchPocs 按关键词与级别检索 PoC。
func SearchPocs(keyword string, severity []string, limit int) (*PocSearchResult, error) {
	items, err := pocsrepo.ListMeta(pocsrepo.ListOptions{
		Source:   "all",
		Q:        keyword,
		Severity: severity,
	})
	if err != nil {
		return nil, err
	}

	total := len(items)

	// 相关性排序：poc.search 是用来「先预检本机有没有这个技术栈的 PoC」的，命中
	// 关键词越多、越靠近 id/名称的结果越该排前面。ListMeta 的 severity→name 排序
	// 会把一个只命中 tags 的低相关项排到精确命中 id 的项之前，模型据此容易选错 PoC。
	// 排序只在读取层做：afrog -pl -s 的输出顺序保持原样。
	if kws := poc.SplitSearchKeywords(keyword); len(kws) > 0 {
		sort.SliceStable(items, func(i, j int) bool {
			return searchRelevance(items[i], kws) > searchRelevance(items[j], kws)
		})
	}

	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	truncated := false
	if len(items) > limit {
		items = items[:limit]
		truncated = true
	}

	// tags/requires 为空时保持空切片而不是 nil：nil 会被序列化成 null，
	// 与 poc.search 的 outputSchema 里 "tags": array 冲突，客户端按 schema 校验会整批拒绝。
	nonNil := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return v
	}

	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		out = append(out, map[string]any{
			"id":       it.ID,
			"name":     it.Name,
			"severity": it.Severity,
			"tags":     nonNil(it.Tags),
			"requires": nonNil(it.Requires),
			"path":     it.Path,
			"source":   string(it.Source),
		})
	}
	return &PocSearchResult{Items: out, Count: len(out), Total: total, Truncated: truncated}, nil
}

// searchRelevance 给一条 PoC 算相对关键词的相关性：每个关键词只按它命中的最靠前
// 字段计一次分（id > name > tags > requires），再对所有关键词求和。
//
// 只用「命中几个关键词、命中最靠前的哪个字段」两个稳定维度：不去猜语义、也不做
// 分词模糊匹配，保证与 poc.search / afrog -s 的硬子串口径一致，同一输入结果确定。
func searchRelevance(it pocsrepo.Item, keywords []string) int {
	score := 0
	for _, k := range keywords {
		switch {
		case strings.Contains(strings.ToLower(it.ID), k):
			score += 4
		case strings.Contains(strings.ToLower(it.Name), k):
			score += 3
		case containsAnyFold(it.Tags, k):
			score += 2
		case containsAnyFold(it.Requires, k):
			score += 1
		}
	}
	return score
}

// containsAnyFold 判断 values 里是否有任一项（小写后）包含关键词 k。
func containsAnyFold(values []string, k string) bool {
	for _, v := range values {
		if strings.Contains(strings.ToLower(v), k) {
			return true
		}
	}
	return false
}
