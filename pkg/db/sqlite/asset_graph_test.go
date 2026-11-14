package sqlite

import "testing"

// TestDeriveAssetChain 锁定程序化父链的口径：只做可计算的关系，不做猜测。
func TestDeriveAssetChain(t *testing.T) {
	cases := []struct {
		addr string
		typ  string
		want []assetParent
	}{
		{
			addr: "https://a.example/login",
			typ:  "url",
			want: []assetParent{{Address: "a.example", Type: "domain", Kind: "host"}},
		},
		{
			addr: "http://10.0.0.5:8080/api",
			typ:  "url",
			want: []assetParent{
				{Address: "10.0.0.5:8080", Type: "hostport", Kind: "host"},
				{Address: "10.0.0.5", Type: "ip", Kind: "ip"},
				{Address: "10.0.0.0/24", Type: "cidr", Kind: "cidr"},
			},
		},
		{
			addr: "a.example:8443",
			typ:  "hostport",
			want: []assetParent{{Address: "a.example", Type: "domain", Kind: "host"}},
		},
		{
			addr: "10.0.0.5",
			typ:  "ip",
			want: []assetParent{{Address: "10.0.0.0/24", Type: "cidr", Kind: "cidr"}},
		},
		{
			// IPv6 的网段默认值争议大，明确不推导。
			addr: "fd00::1",
			typ:  "ip",
			want: nil,
		},
		{
			// 主域推导需要公共后缀表，宁可不做，避免把 co.uk 这类后缀切错。
			addr: "a.example",
			typ:  "domain",
			want: nil,
		},
		{
			addr: "10.0.0.0/24",
			typ:  "cidr",
			want: nil,
		},
	}

	for _, c := range cases {
		got := deriveAssetChain(c.addr, c.typ)
		if len(got) != len(c.want) {
			t.Fatalf("%s (%s) 链长 = %d (%+v), want %d", c.addr, c.typ, len(got), got, len(c.want))
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s (%s)[%d] = %+v, want %+v", c.addr, c.typ, i, got[i], c.want[i])
			}
		}
	}
}

// TestBackfillAssetGraph 锁定历史资产的补建：幂等、只处理有上级的类型。
func TestBackfillAssetGraph(t *testing.T) {
	withAssetFixture(t)

	// 绕过 upsert 直接写行，模拟「图功能上线前」的老资产。
	if _, err := dbx.Exec(`INSERT INTO "asset"("id","address","type","archived") VALUES
		('https://old.example/login','https://old.example/login','url',0),
		('10.1.2.3','10.1.2.3','ip',0),
		('old.example','old.example','domain',0)`); err != nil {
		t.Fatalf("seed legacy assets: %v", err)
	}

	n, err := BackfillAssetGraph(100)
	if err != nil {
		t.Fatalf("BackfillAssetGraph: %v", err)
	}
	if n != 2 {
		t.Fatalf("补建条数 = %d, want 2（domain 无上级，不应被处理）", n)
	}

	edges, err := SelectAssetEdges([]string{"https://old.example/login", "10.1.2.3"})
	if err != nil {
		t.Fatalf("SelectAssetEdges: %v", err)
	}
	if len(edges) != 2 {
		t.Fatalf("补建边 = %+v, want url→host 与 ip→cidr 各一条", edges)
	}
	got := map[string]string{}
	for _, e := range edges {
		got[e.ParentID+"→"+e.ChildID] = e.Kind
	}
	if got["old.example→https://old.example/login"] != "host" {
		t.Fatalf("URL 的归属边缺失: %+v", got)
	}
	if got["10.1.2.0/24→10.1.2.3"] != "cidr" {
		t.Fatalf("IP 的网段边缺失: %+v", got)
	}

	// 幂等：第二次不应重复处理。
	if n, err = BackfillAssetGraph(100); err != nil || n != 0 {
		t.Fatalf("第二次补建 = %d, err=%v, want 0", n, err)
	}
}

// TestUpsertAssetsBuildsGraph 锁定资产入库时自动补齐父子边。
func TestUpsertAssetsBuildsGraph(t *testing.T) {
	withAssetFixture(t)

	if _, err := CreateAssets("manual", "", nil, []AssetInput{
		{Address: "http://10.0.0.5:8080/api", Type: "url"},
		{Address: "https://a.example/login", Type: "url"},
	}); err != nil {
		t.Fatalf("CreateAssets: %v", err)
	}

	// 推导只写边、不写节点：资产总数不应因为「多算了一个 host」而膨胀。
	nodes, err := SelectAssetNodes([]string{
		"http://10.0.0.5:8080/api", "https://a.example/login",
		"10.0.0.5:8080", "10.0.0.5", "10.0.0.0/24", "a.example",
	})
	if err != nil {
		t.Fatalf("SelectAssetNodes: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("资产表节点数 = %d (%+v), want 2（只含用户显式录入的资产）", len(nodes), nodes)
	}

	edges, err := SelectAssetEdges([]string{"10.0.0.5:8080", "10.0.0.5"})
	if err != nil {
		t.Fatalf("SelectAssetEdges: %v", err)
	}
	found := map[string]string{}
	for _, e := range edges {
		found[e.ParentID+"→"+e.ChildID] = e.Kind
	}
	want := map[string]string{
		"10.0.0.5:8080→http://10.0.0.5:8080/api": "host",
		"10.0.0.5→10.0.0.5:8080":                 "ip",
		"10.0.0.0/24→10.0.0.5":                   "cidr",
	}
	for k, kind := range want {
		if found[k] != kind {
			t.Fatalf("缺少边 %s (kind=%s)，实际 = %+v", k, kind, found)
		}
	}

	all, err := ListAssets(AssetFilter{View: "all"})
	if err != nil {
		t.Fatalf("ListAssets all: %v", err)
	}
	if all.Total != 2 {
		t.Fatalf("全部视图 = %d 条, want 2", all.Total)
	}
}
