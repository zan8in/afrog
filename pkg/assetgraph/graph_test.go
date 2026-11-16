package assetgraph

import (
	"testing"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/poc"
)

// 子图要能穿透到「端点 → 技术栈 → 候选 PoC」，且两类派生节点不落资产表。
func TestBuildIncludesTechAndCandidatePoc(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	if _, err := sqlite.CreateAssets("manual", "", nil, []sqlite.AssetInput{
		{Address: "https://a.example", Type: "url"},
	}); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	endpoint := "https://a.example/login"
	if err := sqlite.EnsureEndpointGraph(endpoint, ""); err != nil {
		t.Fatalf("ensure endpoint graph: %v", err)
	}
	if err := sqlite.EnsureTechGraph(endpoint, []string{"ThinkPHP"},
		map[string][]string{"ThinkPHP": {"CVE-2024-1", "CVE-2024-2"}}); err != nil {
		t.Fatalf("ensure tech graph: %v", err)
	}

	graph, err := Build(Options{Root: "a.example", Depth: 4, Direction: "down"})
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	nodes := map[string]Node{}
	for _, n := range graph.Nodes {
		nodes[n.ID] = n
	}
	if tech, ok := nodes["tech:thinkphp"]; !ok || tech.Type != "tech" {
		t.Fatalf("技术栈节点缺失或类型错误: %+v", nodes)
	}
	if poc, ok := nodes["poc:CVE-2024-1"]; !ok || poc.Type != "poc" {
		t.Fatalf("候选 PoC 节点缺失或类型错误: %+v", nodes)
	}
	if graph.Rollup.ByType["tech"] != 1 || graph.Rollup.ByType["poc"] != 2 {
		t.Fatalf("rollup.by_type = %+v, want tech 1 / poc 2", graph.Rollup.ByType)
	}

	// 从技术栈往回看，端点必须在上游；这是 Agent「为什么认为它有这个 PoC」的依据。
	up, err := Build(Options{Root: "tech:thinkphp", Depth: 2, Direction: "both"})
	if err != nil {
		t.Fatalf("build up: %v", err)
	}
	seen := map[string]string{}
	for _, n := range up.Nodes {
		seen[n.ID] = n.Relation
	}
	if seen[endpoint] != "up" {
		t.Fatalf("技术栈上游 = %+v, want 端点", seen)
	}
}

// requires 索引的匹配口径：规则 id、完整名字、首个词都能命中；WAF/CDN 不参与；
// 带版本约束的候选按识别到的版本过滤。
func TestCandidatesForUsesRequiresIndex(t *testing.T) {
	index := map[string][]techCandidate{
		"thinkphp":            {{ID: "CVE-2024-1"}},
		"thinkphp 6":          {{ID: "CVE-2024-2"}},
		"ajp-protocol-detect": {{ID: "ajp-file-read"}},
		"cloudflare":          {{ID: "not-a-real-poc"}},
		// jquery<3.5：只在识别到旧版本时才是候选。
		"jquery": {{ID: "jquery-xss", Version: &poc.RequireVersion{Tech: "jquery", Op: "<", Value: "3.5"}}},
	}
	cases := []struct {
		tech TechRef
		want []string
	}{
		{TechRef{Name: "ThinkPHP"}, []string{"CVE-2024-1"}},
		{TechRef{Name: "ThinkPHP 6"}, []string{"CVE-2024-1", "CVE-2024-2"}},
		{TechRef{Name: "Tomcat", RuleID: "ajp-protocol-detect"}, []string{"ajp-file-read"}},
		{TechRef{Name: "Cloudflare", Category: "waf"}, nil},
		{TechRef{Name: "UnknownTech"}, nil},
		// 旧版本满足 jquery<3.5，挂出候选。
		{TechRef{Name: "jQuery", Version: "3.4.1"}, []string{"jquery-xss"}},
		// 新版本不满足，剔除候选。
		{TechRef{Name: "jQuery", Version: "3.6.0"}, nil},
		// 版本未知：保留候选，避免因拿不到版本而漏报。
		{TechRef{Name: "jQuery"}, []string{"jquery-xss"}},
	}
	for _, tc := range cases {
		got := candidatesFor(index, tc.tech)
		if len(got) != len(tc.want) {
			t.Fatalf("candidatesFor(%+v) = %v, want %v", tc.tech, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("candidatesFor(%+v) = %v, want %v", tc.tech, got, tc.want)
			}
		}
	}
}

// requires 索引是 tech → candidate 边的唯一数据来源：它必须能从内置 PoC 建起来，
// 且任意一个键都能真的连出候选边。
func TestRequiresIndexDrivesCandidateEdges(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	index := requiresIndexByTech()
	if len(index) == 0 {
		t.Fatal("requires 索引为空：内置 PoC 的 info.requires 没有被读到")
	}
	var key string
	for k, ids := range index {
		if k != "" && len(ids) > 0 {
			key = k
			break
		}
	}
	if key == "" {
		t.Fatal("索引里没有合法的 requires 键")
	}

	endpoint := "https://a.example/app"
	if err := LinkTechCandidates(endpoint, []TechRef{{Name: key}}); err != nil {
		t.Fatalf("LinkTechCandidates: %v", err)
	}
	techID := sqlite.TechAssetID(key)
	edges, err := sqlite.SelectAssetEdges([]string{endpoint, techID})
	if err != nil {
		t.Fatalf("SelectAssetEdges: %v", err)
	}
	hasTech, hasCandidate := false, false
	for _, e := range edges {
		if e.ParentID == endpoint && e.ChildID == techID && e.Kind == "tech" {
			hasTech = true
		}
		if e.ParentID == techID && e.Kind == "candidate" {
			hasCandidate = true
		}
	}
	if !hasTech || !hasCandidate {
		t.Fatalf("候选边未落地: tech=%v candidate=%v edges=%+v", hasTech, hasCandidate, edges)
	}
}

// 子图必须能从主机穿透到「端点 → 参数」，且命中数落在端点/参数上而不是主机上。
func TestBuildIncludesEndpointsAndParams(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := sqlite.NewWebSqliteDB(); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(sqlite.CloseX)

	if _, err := sqlite.CreateAssets("manual", "", nil, []sqlite.AssetInput{
		{Address: "https://a.example", Type: "url"},
	}); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if err := sqlite.EnsureEndpointGraph("https://a.example/login?x=1", "query:user"); err != nil {
		t.Fatalf("ensure endpoint graph: %v", err)
	}
	if _, _, _, err := sqlite.UpsertPassiveFinding(sqlite.PassiveFinding{
		AssetID:     "https://a.example",
		Fingerprint: "sqli|https://a.example/login|query:user",
		Detector:    "sqli",
		VulnType:    "sqli",
		Severity:    "high",
		Confidence:  "certain",
		Title:       "SQLi",
		Target:      "https://a.example/login?x=1",
		Location:    "query:user",
	}); err != nil {
		t.Fatalf("upsert passive finding: %v", err)
	}

	graph, err := Build(Options{Root: "a.example", Depth: 2, Direction: "down"})
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	if graph == nil {
		t.Fatal("empty graph")
	}

	endpointID := "https://a.example/login"
	paramID := endpointID + "#query:user"
	nodes := map[string]Node{}
	for _, n := range graph.Nodes {
		nodes[n.ID] = n
	}

	endpoint, ok := nodes[endpointID]
	if !ok || endpoint.Type != "endpoint" {
		t.Fatalf("端点节点缺失或类型错误: %+v", nodes)
	}
	if endpoint.Findings != 1 {
		t.Fatalf("端点命中数 = %d, want 1", endpoint.Findings)
	}
	param, ok := nodes[paramID]
	if !ok || param.Type != "param" {
		t.Fatalf("参数节点缺失或类型错误: %+v", nodes)
	}
	if param.Findings != 1 {
		t.Fatalf("参数命中数 = %d, want 1", param.Findings)
	}

	if graph.Rollup.ByType["endpoint"] != 1 || graph.Rollup.ByType["param"] != 1 {
		t.Fatalf("rollup.by_type = %+v, want endpoint/param 各 1", graph.Rollup.ByType)
	}

	// 以参数节点为根时，上游必须能回到端点。
	up, err := Build(Options{Root: paramID, Depth: 1, Direction: "up"})
	if err != nil {
		t.Fatalf("build up: %v", err)
	}
	if up.Root.ID != paramID || up.Root.Type != "param" {
		t.Fatalf("参数根节点 = %+v", up.Root)
	}
	if len(up.Nodes) != 1 || up.Nodes[0].ID != endpointID {
		t.Fatalf("参数上游 = %+v, want 端点", up.Nodes)
	}
}
