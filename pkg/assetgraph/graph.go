// Package assetgraph 在资产表与 asset_edge 之上做子图遍历。
//
// 它只消费程序化推导出的父子关系（URL → authority → IP → 网段），不引入 DNS、
// 公共后缀等需要人工纠错的一层；节点缺失时按地址合成，避免为了图完整污染资产库。
package assetgraph

import (
	"sort"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/ref"
	"github.com/zan8in/gologger"
)

// 图的遍历上限：防止异常数据把一次查看放大成全表扫描。
//
// MaxDepth 取 4 是为了覆盖最长的一条推理链：hostport → endpoint → tech → poc
// （「这台机器的 8080 上跑着 X，X 有哪些现成 PoC」）。
const (
	MaxDepth     = 4
	DefaultDepth = 2
	MaxNodes     = 500
)

// Node 是图上的一个节点，附带它在本图中的位置与聚合信息。
type Node struct {
	sqlite.AssetNodeRow
	// Depth 是到根节点的最短距离；Relation 说明它相对根的位置。
	Depth    int    `json:"depth"`
	Relation string `json:"relation"`
	// Coverage 只对可作为被动覆盖口径的节点（domain / hostport / ip）有值。
	Coverage *sqlite.AssetCoverageSummary `json:"coverage,omitempty"`
	// Findings 是该资产上已锚定的被动命中数。
	Findings    int64 `json:"findings"`
	ParentCount int   `json:"parent_count"`
	ChildCount  int   `json:"child_count"`
}

// Rollup 是整棵子树的汇总。
type Rollup struct {
	Nodes        int            `json:"nodes"`
	ByType       map[string]int `json:"by_type"`
	Hosts        int            `json:"hosts"`
	CoveredHosts int            `json:"covered_hosts"`
	HitHosts     int            `json:"hit_hosts"`
	Findings     int64          `json:"findings"`
}

// Response 是一次子图查询的结果。
type Response struct {
	Root      Node               `json:"root"`
	Nodes     []Node             `json:"nodes"`
	Edges     []sqlite.AssetEdge `json:"edges"`
	Rollup    Rollup             `json:"rollup"`
	Truncated bool               `json:"truncated"`
}

// Options 控制遍历范围。
type Options struct {
	// Root 是起点，可以是资产 id，也可以是一个地址（不存在时按地址合成节点）。
	Root string
	// Depth 为 1..MaxDepth；<=0 时取 DefaultDepth。
	Depth int
	// Direction 取 down（更细的资产）/ up（归属）/ both，其它值按 both 处理。
	Direction string
	// ProjectID 非空时，命中与覆盖度按项目口径统计。
	ProjectID string
}

type trace struct {
	depth    int
	relation string
}

// Build 以 opts.Root 为根，按方向与深度收集子图。
func Build(opts Options) (*Response, error) {
	rootID := strings.TrimSpace(opts.Root)
	if rootID == "" {
		return nil, nil
	}

	depth := opts.Depth
	if depth <= 0 {
		depth = DefaultDepth
	}
	if depth > MaxDepth {
		depth = MaxDepth
	}

	direction := strings.ToLower(strings.TrimSpace(opts.Direction))
	switch direction {
	case "down", "up":
	default:
		direction = "both"
	}

	traces := map[string]*trace{rootID: {depth: 0, relation: "root"}}
	order := []string{rootID}
	edgeMap := make(map[string]sqlite.AssetEdge)
	frontier := []string{rootID}
	truncated := false

	for d := 1; d <= depth && len(frontier) > 0 && !truncated; d++ {
		edges, err := sqlite.SelectAssetEdges(frontier)
		if err != nil {
			return nil, err
		}
		frontierSet := make(map[string]struct{}, len(frontier))
		for _, id := range frontier {
			frontierSet[id] = struct{}{}
		}

		nextSet := make(map[string]struct{})
		for _, e := range edges {
			rel := ""
			if _, ok := frontierSet[e.ParentID]; ok {
				rel = "down"
			} else if _, ok := frontierSet[e.ChildID]; ok {
				rel = "up"
			}
			if rel == "" {
				continue
			}
			if direction == "down" && rel == "up" {
				continue
			}
			if direction == "up" && rel == "down" {
				continue
			}

			edgeMap[e.ParentID+"|"+e.ChildID+"|"+e.Kind] = e

			other := e.ChildID
			if rel == "up" {
				other = e.ParentID
			}
			if cur, ok := traces[other]; ok {
				// 同一节点可能同时被上下游发现：合并成 both，深度取最近的一次。
				if cur.relation != "root" && cur.relation != rel {
					cur.relation = "both"
				}
				if d < cur.depth {
					cur.depth = d
				}
				continue
			}
			traces[other] = &trace{depth: d, relation: rel}
			order = append(order, other)
			nextSet[other] = struct{}{}
			if len(order) >= MaxNodes {
				truncated = true
				break
			}
		}

		frontier = frontier[:0]
		for id := range nextSet {
			frontier = append(frontier, id)
		}
		sort.Strings(frontier)
	}

	rows, err := sqlite.SelectAssetNodes(order)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]sqlite.AssetNodeRow, len(order))
	for _, r := range rows {
		byID[r.ID] = r
	}
	// 只在边里出现的上级节点（authority / IP / 网段）由地址本身即可完整描述，
	// 读取时按需合成。
	for _, id := range order {
		if _, ok := byID[id]; ok {
			continue
		}
		byID[id] = sqlite.AssetNodeRow{
			ID:      id,
			Address: id,
			Type:    sqlite.ClassifyAssetAddress(id),
			Source:  "derived",
		}
	}

	hosts := make([]string, 0, len(order))
	for _, id := range order {
		if r, ok := byID[id]; ok && isCoverageHostType(r.Type) {
			hosts = append(hosts, r.Address)
		}
	}
	coverage, err := sqlite.SelectAssetCoverageByHostsScoped(hosts, opts.ProjectID)
	if err != nil {
		gologger.Debug().Msgf("资产图覆盖度读取失败: %v", err)
		coverage = map[string]sqlite.AssetCoverageSummary{}
	}
	findings, err := sqlite.SelectPassiveFindingCountsByAssetScoped(order, opts.ProjectID)
	if err != nil {
		gologger.Debug().Msgf("资产图命中数读取失败: %v", err)
		findings = map[string]int64{}
	}
	// 端点/参数不是资产行，命中数只能按 target/location 归集，再折算到节点 id。
	endpointFindings, paramFindings := passiveTargetFindings(order, opts.ProjectID)

	parentCount := make(map[string]int)
	childCount := make(map[string]int)
	edges := make([]sqlite.AssetEdge, 0, len(edgeMap))
	for _, e := range edgeMap {
		edges = append(edges, e)
		parentCount[e.ParentID]++
		childCount[e.ChildID]++
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].ParentID == edges[j].ParentID {
			return edges[i].ChildID < edges[j].ChildID
		}
		return edges[i].ParentID < edges[j].ParentID
	})

	resp := &Response{
		Nodes:     make([]Node, 0, len(order)),
		Edges:     edges,
		Truncated: truncated,
		Rollup:    Rollup{ByType: make(map[string]int)},
	}

	for _, id := range order {
		r, ok := byID[id]
		if !ok {
			continue
		}
		t := traces[id]
		if t == nil {
			continue
		}
		node := Node{
			AssetNodeRow: r,
			Depth:        t.depth,
			Relation:     t.relation,
			Findings:     nodeFindings(id, r.Type, findings, endpointFindings, paramFindings),
			ParentCount:  parentCount[id],
			ChildCount:   childCount[id],
		}
		if isCoverageHostType(r.Type) {
			if cov, ok := coverage[r.Address]; ok {
				c := cov
				node.Coverage = &c
			}
		}

		if id == rootID {
			resp.Root = node
			continue
		}
		resp.Nodes = append(resp.Nodes, node)

		resp.Rollup.Nodes++
		resp.Rollup.ByType[r.Type]++
		resp.Rollup.Findings += node.Findings
		if isCoverageHostType(r.Type) {
			resp.Rollup.Hosts++
			if node.Coverage != nil {
				resp.Rollup.CoveredHosts++
				if node.Coverage.State == "hit" {
					resp.Rollup.HitHosts++
				}
			}
		}
	}

	// 上游在前（先看归属），同一关系内按深度、地址排序，便于阅读。
	sort.SliceStable(resp.Nodes, func(i, j int) bool {
		a, b := resp.Nodes[i], resp.Nodes[j]
		if a.Relation != b.Relation {
			return a.Relation == "up"
		}
		if a.Depth != b.Depth {
			return a.Depth < b.Depth
		}
		return a.Address < b.Address
	})

	return resp, nil
}

// isCoverageHostType 判断该类型能否与被动覆盖度的 authority 口径对齐。
//
// url 的成本口径是它的 authority（另一个节点），cidr 则过粗，都不作为覆盖节点。
func isCoverageHostType(typ string) bool {
	switch typ {
	case "domain", "hostport", "ip":
		return true
	}
	return false
}

// passiveTargetFindings 把「按 target/location 聚合的命中」折算成端点/参数节点的计数。
//
// 端点先归一化再匹配：被动命中里的 target 可能带 query、大小写也不统一，直接按
// 原串比较会漏掉大量命中。
func passiveTargetFindings(assetIDs []string, projectID string) (endpoints, params map[string]int64) {
	endpoints = map[string]int64{}
	params = map[string]int64{}

	rows, err := sqlite.SelectPassiveTargetCountsScoped(assetIDs, projectID)
	if err != nil {
		gologger.Debug().Msgf("资产图端点命中数读取失败: %v", err)
		return endpoints, params
	}
	for _, r := range rows {
		endpoint, err := ref.NormalizeEndpoint(r.Target)
		if err != nil {
			continue
		}
		endpoints[endpoint] += r.Count
		if paramID, ok := sqlite.ParamAssetID(endpoint, r.Location); ok {
			params[paramID] += r.Count
		}
	}
	return endpoints, params
}

// nodeFindings 选择节点该用哪一套命中计数。
//
// 端点/参数是合成节点（没有 asset_id），用 target 口径；其余节点沿用资产口径。
func nodeFindings(id, typ string, byAsset, endpoints, params map[string]int64) int64 {
	switch typ {
	case "endpoint":
		return endpoints[id]
	case "param":
		return params[id]
	}
	return byAsset[id]
}
