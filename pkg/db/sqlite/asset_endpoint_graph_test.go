package sqlite

import "testing"

// 端点/参数的判定必须与读取时合成节点的口径一致，否则图里会同时出现两种类型。
func TestClassifyAssetAddressKinds(t *testing.T) {
	cases := map[string]string{
		"https://a.example":                     "url",
		"https://a.example/":                    "url",
		"https://a.example/login":               "endpoint",
		"http://a.example:8080/api?x=1":         "endpoint",
		"http://a.example/login#query:id":       "param",
		"http://a.example/login#json:user.name": "param",
		// 规则名不是参数：misconfig 的 cookie-secure:sid 不该被当成注入点。
		"http://a.example/login#cookie-secure:sid": "endpoint",
		"tech:thinkphp":  "tech",
		"poc:CVE-2024-1": "poc",
		"10.0.0.5":       "ip",
		"10.0.0.0/24":    "cidr",
		"a.example:443":  "hostport",
		"a.example":      "domain",
		"":               "",
	}
	for addr, want := range cases {
		if got := ClassifyAssetAddress(addr); got != want {
			t.Fatalf("ClassifyAssetAddress(%q) = %q, want %q", addr, got, want)
		}
	}
}

func TestParamAssetID(t *testing.T) {
	got, ok := ParamAssetID("http://a.example/login", "query:user")
	if !ok || got != "http://a.example/login#query:user" {
		t.Fatalf("ParamAssetID = %q, %v", got, ok)
	}
	for _, loc := range []string{"", "query", "response", "cookie-secure:sid", "query:"} {
		if _, ok := ParamAssetID("http://a.example/login", loc); ok {
			t.Fatalf("location %q 不该建参数节点", loc)
		}
	}
	if endpoint, location, ok := SplitParamAssetID(got); !ok ||
		endpoint != "http://a.example/login" || location != "query:user" {
		t.Fatalf("SplitParamAssetID = %q, %q, %v", endpoint, location, ok)
	}
}

// 端点/参数只写边、不写资产行：资产总数不能被扫描过程中看到的每个 URL 撑大。
func TestEnsureEndpointGraphWritesEdgesOnly(t *testing.T) {
	withAssetFixture(t)

	if err := EnsureEndpointGraph("HTTP://10.0.0.5:8080/Login?x=1#frag", "query:user"); err != nil {
		t.Fatalf("EnsureEndpointGraph: %v", err)
	}
	// 根路径与非法目标都不该产生节点。
	if err := EnsureEndpointGraph("http://10.0.0.5:8080/", ""); err != nil {
		t.Fatalf("EnsureEndpointGraph(root): %v", err)
	}
	if err := EnsureEndpointGraph("not a url", "query:id"); err != nil {
		t.Fatalf("EnsureEndpointGraph(invalid): %v", err)
	}

	endpoint := "http://10.0.0.5:8080/Login"
	param := endpoint + "#query:user"
	edges, err := SelectAssetEdges([]string{endpoint, param})
	if err != nil {
		t.Fatalf("SelectAssetEdges: %v", err)
	}
	kinds := map[string]string{}
	for _, e := range edges {
		kinds[e.ParentID+"→"+e.ChildID] = e.Kind
	}
	if kinds["10.0.0.5:8080→"+endpoint] != "service" {
		t.Fatalf("端点归属边缺失或类型错误: %+v", kinds)
	}
	if kinds[endpoint+"→"+param] != "param" {
		t.Fatalf("参数边缺失或类型错误: %+v", kinds)
	}
	if len(edges) != 2 {
		t.Fatalf("边数 = %d (%+v), want 2", len(edges), edges)
	}

	nodes, err := SelectAssetNodes([]string{endpoint, param, "10.0.0.5:8080"})
	if err != nil {
		t.Fatalf("SelectAssetNodes: %v", err)
	}
	if len(nodes) != 0 {
		t.Fatalf("端点/参数不应落资产表: %+v", nodes)
	}

	// 重复调用幂等。
	if err := EnsureEndpointGraph("http://10.0.0.5:8080/Login", "query:user"); err != nil {
		t.Fatalf("EnsureEndpointGraph again: %v", err)
	}
	if edges, err = SelectAssetEdges([]string{endpoint, param}); err != nil || len(edges) != 2 {
		t.Fatalf("幂等失败: %d 条边, err=%v", len(edges), err)
	}
}

// 技术栈/候选 PoC 同样只写边、不写资产行，且重复写入幂等。
func TestEnsureTechGraphWritesEdgesOnly(t *testing.T) {
	withAssetFixture(t)

	endpoint := "https://a.example/login"
	candidates := map[string][]string{"ThinkPHP": {"CVE-2024-1", "CVE-2024-2"}}
	if err := EnsureTechGraph(endpoint+"?x=1", []string{"ThinkPHP", "  "}, candidates); err != nil {
		t.Fatalf("EnsureTechGraph: %v", err)
	}
	// 非法目标静默跳过。
	if err := EnsureTechGraph("not a url", []string{"Nginx"}, nil); err != nil {
		t.Fatalf("EnsureTechGraph(invalid): %v", err)
	}

	techID := "tech:thinkphp"
	pocID := "poc:CVE-2024-1"
	edges, err := SelectAssetEdges([]string{endpoint, techID, pocID})
	if err != nil {
		t.Fatalf("SelectAssetEdges: %v", err)
	}
	kinds := map[string]string{}
	for _, e := range edges {
		kinds[e.ParentID+"→"+e.ChildID] = e.Kind
	}
	if kinds[endpoint+"→"+techID] != "tech" {
		t.Fatalf("端点→技术栈边缺失或类型错误: %+v", kinds)
	}
	if kinds[techID+"→"+pocID] != "candidate" {
		t.Fatalf("技术栈→候选 PoC 边缺失或类型错误: %+v", kinds)
	}
	if len(edges) != 3 {
		t.Fatalf("边数 = %d (%+v), want 3", len(edges), edges)
	}

	nodes, err := SelectAssetNodes([]string{techID, pocID})
	if err != nil {
		t.Fatalf("SelectAssetNodes: %v", err)
	}
	if len(nodes) != 0 {
		t.Fatalf("技术栈/PoC 不应落资产表: %+v", nodes)
	}

	if err := EnsureTechGraph(endpoint, []string{"ThinkPHP"}, candidates); err != nil {
		t.Fatalf("EnsureTechGraph again: %v", err)
	}
	if edges, err = SelectAssetEdges([]string{endpoint, techID, pocID}); err != nil || len(edges) != 3 {
		t.Fatalf("幂等失败: %d 条边, err=%v", len(edges), err)
	}
}

// 历史被动命中在升级后要能补出端点/参数边，且重复启动不新增行。
func TestBackfillEndpointGraph(t *testing.T) {
	withAssetFixture(t)

	if _, err := dbx.Exec(`INSERT INTO "passive_finding"
		("project_id","asset_id","fingerprint","target","location")
		VALUES ('','10.0.0.5:8080','fp1','http://10.0.0.5:8080/api?id=1','query:id'),
		       ('','10.0.0.5:8080','fp2','10.0.0.5','')`); err != nil {
		t.Fatalf("seed passive findings: %v", err)
	}

	n, err := BackfillEndpointGraph(10)
	if err != nil {
		t.Fatalf("BackfillEndpointGraph: %v", err)
	}
	if n != 1 {
		t.Fatalf("补建条数 = %d, want 1（非 URL 目标应跳过）", n)
	}

	endpoint := "http://10.0.0.5:8080/api"
	edges, err := SelectAssetEdges([]string{endpoint})
	if err != nil {
		t.Fatalf("SelectAssetEdges: %v", err)
	}
	if len(edges) != 2 {
		t.Fatalf("补建边 = %+v, want service + param 各一条", edges)
	}

	if _, err := BackfillEndpointGraph(10); err != nil {
		t.Fatalf("第二次补建: %v", err)
	}
	if edges, err = SelectAssetEdges([]string{endpoint}); err != nil || len(edges) != 2 {
		t.Fatalf("幂等失败: %d 条边, err=%v", len(edges), err)
	}
}

// 端点/参数的命中数按 target/location 归集，且受项目口径约束。
func TestSelectPassiveTargetCountsScoped(t *testing.T) {
	withAssetFixture(t)

	if _, err := dbx.Exec(`INSERT INTO "passive_finding"
		("project_id","asset_id","fingerprint","target","location")
		VALUES
		('p1','https://a.example','fp1','https://a.example/login?id=1','query:id'),
		('p1','https://a.example','fp2','https://a.example/login?id=2','query:id'),
		('p1','https://a.example','fp3','https://a.example/list','query:page'),
		('p2','https://a.example','fp4','https://a.example/login','query:id')`); err != nil {
		t.Fatalf("seed passive findings: %v", err)
	}

	rows, err := SelectPassiveTargetCountsScoped([]string{"https://a.example"}, "p1")
	if err != nil {
		t.Fatalf("SelectPassiveTargetCountsScoped: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("分组数 = %d (%+v), want 3（target 各自成组）", len(rows), rows)
	}
	got := map[string]int64{}
	for _, r := range rows {
		got[r.Target+"|"+r.Location] = r.Count
	}
	if got["https://a.example/login?id=1|query:id"] != 1 || got["https://a.example/login?id=2|query:id"] != 1 {
		t.Fatalf("错误的分组结果: %+v", got)
	}
	if got["https://a.example/list|query:page"] != 1 {
		t.Fatalf("错误的分组结果: %+v", got)
	}

	var total int64
	for _, r := range rows {
		total += r.Count
	}
	if total != 3 {
		t.Fatalf("p1 命中数 = %d, want 3（p2 不应计入）", total)
	}
}
