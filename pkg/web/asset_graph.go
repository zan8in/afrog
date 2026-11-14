package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/gologger"
)

// 资产图的遍历上限。
//
// 图是人为推导出来的层级（URL → authority → IP → 网段），正常情况下每个节点
// 只有个位数邻居；限制深度与节点数是为了防止异常数据把一次查看放大成全表扫描。
const (
	assetGraphMaxDepth = 3
	assetGraphMaxNodes = 500
)

// assetGraphNode 是图上的一个节点，附带它在本图中的位置与聚合信息。
type assetGraphNode struct {
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

// assetGraphRollup 是整棵子树的汇总，用于「穿透视图的覆盖率」。
type assetGraphRollup struct {
	Nodes        int            `json:"nodes"`
	ByType       map[string]int `json:"by_type"`
	Hosts        int            `json:"hosts"`
	CoveredHosts int            `json:"covered_hosts"`
	HitHosts     int            `json:"hit_hosts"`
	Findings     int64          `json:"findings"`
}

type assetGraphResponse struct {
	Root      assetGraphNode     `json:"root"`
	Nodes     []assetGraphNode   `json:"nodes"`
	Edges     []sqlite.AssetEdge `json:"edges"`
	Rollup    assetGraphRollup   `json:"rollup"`
	Truncated bool               `json:"truncated"`
}

// assetGraphTrace 是遍历过程中的节点状态。
type assetGraphTrace struct {
	depth    int
	relation string
}

// buildAssetGraph 以某个资产为根，按方向与深度收集子图。
//
// direction:
//   - down：只看下游（更细的资产，穿透）
//   - up：只看上游（归属关系，反查）
//   - both：两个方向都看
func buildAssetGraph(rootID string, depth int, direction string) (*assetGraphResponse, error) {
	if depth <= 0 {
		depth = 2
	}
	if depth > assetGraphMaxDepth {
		depth = assetGraphMaxDepth
	}

	trace := map[string]*assetGraphTrace{rootID: {depth: 0, relation: "root"}}
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
			if cur, ok := trace[other]; ok {
				// 同一节点可能同时被上下游发现：合并成 both，深度取最近的一次。
				if cur.relation != "root" && cur.relation != rel {
					cur.relation = "both"
				}
				if d < cur.depth {
					cur.depth = d
				}
				continue
			}
			trace[other] = &assetGraphTrace{depth: d, relation: rel}
			order = append(order, other)
			nextSet[other] = struct{}{}
			if len(order) >= assetGraphMaxNodes {
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

	if len(order) == 0 {
		return nil, nil
	}

	rows, err := sqlite.SelectAssetNodes(order)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]sqlite.AssetNodeRow, len(order))
	for _, r := range rows {
		byID[r.ID] = r
	}
	// 图中可能存在「只在边里出现、没进资产表」的上级节点（authority / IP / 网段）。
	// 它们由地址本身即可完整描述，按需合成，避免为了让图完整而污染资产库。
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
	coverage, err := sqlite.SelectAssetCoverageByHosts(hosts)
	if err != nil {
		gologger.Debug().Msgf("资产图覆盖度读取失败: %v", err)
		coverage = map[string]sqlite.AssetCoverageSummary{}
	}
	findings, err := sqlite.SelectPassiveFindingCountsByAsset(order)
	if err != nil {
		gologger.Debug().Msgf("资产图命中数读取失败: %v", err)
		findings = map[string]int64{}
	}

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

	resp := &assetGraphResponse{
		Nodes:     make([]assetGraphNode, 0, len(order)),
		Edges:     edges,
		Truncated: truncated,
		Rollup: assetGraphRollup{
			ByType: make(map[string]int),
		},
	}

	for _, id := range order {
		r, ok := byID[id]
		if !ok {
			continue
		}
		t := trace[id]
		if t == nil {
			continue
		}
		node := assetGraphNode{
			AssetNodeRow: r,
			Depth:        t.depth,
			Relation:     t.relation,
			Findings:     findings[id],
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

// assetsGraphHandler 返回某个资产的子图：上游（归属）与下游（穿透），
// 附带给节点的被动覆盖与命中聚合。
func assetsGraphHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	q := r.URL.Query()
	rootID := strings.TrimSpace(q.Get("id"))
	if rootID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少资产 id"})
		return
	}

	depth := atoiDefault(q.Get("depth"), 2)
	if depth <= 0 {
		depth = 2
	}
	if depth > assetGraphMaxDepth {
		depth = assetGraphMaxDepth
	}

	direction := strings.ToLower(strings.TrimSpace(q.Get("direction")))
	switch direction {
	case "down", "up":
	default:
		direction = "both"
	}

	graph, err := buildAssetGraph(rootID, depth, direction)
	if err != nil {
		gologger.Warning().Msgf("读取资产图失败: id=%s err=%v", rootID, err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "读取资产关系失败"})
		return
	}
	if graph == nil || graph.Root.ID == "" {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "资产不存在"})
		return
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "OK", Data: graph})
}
