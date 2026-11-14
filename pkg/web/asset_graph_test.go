package web

import (
	"testing"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
)

// seedAssetGraph 造一条完整链路：网段 → IP → 主机端口 → URL。
func seedAssetGraph(t *testing.T) {
	t.Helper()
	if _, err := sqlite.CreateAssets("manual", "", nil, []sqlite.AssetInput{
		{Address: "http://10.0.0.5:8080/api", Type: "url"},
	}); err != nil {
		t.Fatalf("CreateAssets: %v", err)
	}
	if err := sqlite.UpsertPassiveCoverage([]sqlite.PassiveCoverage{
		{ProjectID: "", Host: "10.0.0.5:8080", Detector: "sqli", State: "hit", Samples: 4, Hits: 1},
	}); err != nil {
		t.Fatalf("UpsertPassiveCoverage: %v", err)
	}
	if _, _, _, err := sqlite.UpsertPassiveFinding(sqlite.PassiveFinding{
		ProjectID:   "",
		AssetID:     "10.0.0.5:8080",
		Fingerprint: "sqli|http://10.0.0.5:8080/api|query:id",
		Detector:    "sqli",
		VulnType:    "sqli",
		Target:      "http://10.0.0.5:8080/api?id=1",
		Location:    "query:id",
	}); err != nil {
		t.Fatalf("UpsertPassiveFinding: %v", err)
	}
}

// TestBuildAssetGraphDownstream 锁定穿透视图：从网段一路看到具体 URL，并带上覆盖率。
func TestBuildAssetGraphDownstream(t *testing.T) {
	withProjectFixture(t)
	seedAssetGraph(t)

	graph, err := buildAssetGraph("10.0.0.0/24", 3, "down")
	if err != nil {
		t.Fatalf("buildAssetGraph: %v", err)
	}
	if graph.Root.ID != "10.0.0.0/24" {
		t.Fatalf("root = %q", graph.Root.ID)
	}

	depth := map[string]int{}
	relation := map[string]string{}
	for _, n := range graph.Nodes {
		depth[n.ID] = n.Depth
		relation[n.ID] = n.Relation
	}
	for id, want := range map[string]int{
		"10.0.0.5":                 1,
		"10.0.0.5:8080":            2,
		"http://10.0.0.5:8080/api": 3,
	} {
		if depth[id] != want {
			t.Fatalf("%s depth = %d, want %d（实际: %+v）", id, depth[id], want, depth)
		}
		if relation[id] != "down" {
			t.Fatalf("%s relation = %q, want down", id, relation[id])
		}
	}

	if graph.Rollup.Nodes != 3 {
		t.Fatalf("rollup.nodes = %d, want 3", graph.Rollup.Nodes)
	}
	if graph.Rollup.Hosts != 2 {
		t.Fatalf("rollup.hosts = %d, want 2（ip + hostport 可承载被动覆盖）", graph.Rollup.Hosts)
	}
	if graph.Rollup.CoveredHosts != 1 || graph.Rollup.HitHosts != 1 {
		t.Fatalf("覆盖汇总 = %+v, want covered=1 hit=1", graph.Rollup)
	}
	if graph.Rollup.Findings != 1 {
		t.Fatalf("rollup.findings = %d, want 1", graph.Rollup.Findings)
	}

	// 命中节点必须带上覆盖度快照，UI 才能直接渲染状态徽标。
	for _, n := range graph.Nodes {
		if n.ID == "10.0.0.5:8080" {
			if n.Coverage == nil || n.Coverage.State != "hit" {
				t.Fatalf("hostport 节点覆盖度 = %+v, want state=hit", n.Coverage)
			}
			if n.Findings != 1 {
				t.Fatalf("hostport 节点命中数 = %d, want 1", n.Findings)
			}
		}
	}
}

// TestBuildAssetGraphUpstream 锁定归属反查：从 URL 找到主机端口、IP 与网段。
func TestBuildAssetGraphUpstream(t *testing.T) {
	withProjectFixture(t)
	seedAssetGraph(t)

	graph, err := buildAssetGraph("http://10.0.0.5:8080/api", 3, "up")
	if err != nil {
		t.Fatalf("buildAssetGraph: %v", err)
	}
	got := map[string]string{}
	for _, n := range graph.Nodes {
		got[n.ID] = n.Relation
	}
	for _, id := range []string{"10.0.0.5:8080", "10.0.0.5", "10.0.0.0/24"} {
		if got[id] != "up" {
			t.Fatalf("%s relation = %q, want up（实际: %+v）", id, got[id], got)
		}
	}

	// down 方向不应反向带出上游节点。
	graph, err = buildAssetGraph("http://10.0.0.5:8080/api", 3, "down")
	if err != nil {
		t.Fatalf("buildAssetGraph(down): %v", err)
	}
	if len(graph.Nodes) != 0 {
		t.Fatalf("URL 的下游应为空，实际 = %+v", graph.Nodes)
	}
}
