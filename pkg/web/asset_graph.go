package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/assetgraph"
	"github.com/zan8in/gologger"
)

// 资产图的遍历逻辑已下沉到 pkg/assetgraph，Web 与 MCP 共用同一实现。
const assetGraphMaxDepth = assetgraph.MaxDepth

type assetGraphNode = assetgraph.Node
type assetGraphRollup = assetgraph.Rollup
type assetGraphResponse = assetgraph.Response

// buildAssetGraph 以某个资产为根，按方向与深度收集子图。
//
// direction:
//   - down：只看下游（更细的资产，穿透）
//   - up：只看上游（归属关系，反查）
//   - both：两个方向都看
func buildAssetGraph(rootID string, depth int, direction string) (*assetGraphResponse, error) {
	return assetgraph.Build(assetgraph.Options{
		Root:      rootID,
		Depth:     depth,
		Direction: direction,
	})
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

	depth := atoiDefault(q.Get("depth"), assetgraph.DefaultDepth)
	if depth <= 0 {
		depth = assetgraph.DefaultDepth
	}
	if depth > assetgraph.MaxDepth {
		depth = assetgraph.MaxDepth
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
