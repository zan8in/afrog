package web

import (
	"testing"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/passive"
)

// TestCoverageHostOfAsset 锁定资产地址到覆盖度 authority 的归一化口径。
//
// 归一化错了会直接导致「未覆盖资产」出现大量假阳性：同名资产因为带不带默认端口、
// 有没有路径而各算一次。cidr 无法映射到单个 authority，必须显式排除。
func TestCoverageHostOfAsset(t *testing.T) {
	cases := []struct {
		addr string
		typ  string
		want string
	}{
		{"https://A.Example/path", "url", "a.example"},
		{"http://a.example:80/", "url", "a.example"},
		{"https://a.example:443/", "url", "a.example"},
		{"https://a.example:8443/", "url", "a.example:8443"},
		{"a.example", "domain", "a.example"},
		{"10.0.0.5:8080", "hostport", "10.0.0.5:8080"},
		{"10.0.0.0/24", "cidr", ""},
		{"", "url", ""},
	}
	for _, c := range cases {
		if got := coverageHostOfAsset(c.addr, c.typ); got != c.want {
			t.Errorf("coverageHostOfAsset(%q, %q) = %q, want %q", c.addr, c.typ, got, c.want)
		}
	}
}

func TestCoverageHostFromURL(t *testing.T) {
	if got := coverageHostFromURL("https://A.Example:8443/api?id=1"); got != "a.example:8443" {
		t.Fatalf("host = %q", got)
	}
	if got := coverageHostFromURL(""); got != "" {
		t.Fatalf("空 URL 必须返回空串，得到 %q", got)
	}
}

// TestCoverageStoreKeepsStrongestState 锁定内存聚合层与库层一致的优先级规则。
func TestCoverageStoreKeepsStrongestState(t *testing.T) {
	s := &passiveCoverageStore{}
	s.reset("p1", []string{"sqli"})

	s.mu.Lock()
	s.observeLocked(passive.CoverageSignal{
		Target: "a.example", Detector: "sqli", State: passive.CoverageSkipped, Reason: "静态资源",
	})
	s.observeLocked(passive.CoverageSignal{
		Target: "a.example", Detector: "sqli", State: passive.CoverageTested, Reason: "已执行，无结论",
	})
	s.observeLocked(passive.CoverageSignal{
		Target: "a.example", Detector: "sqli", State: passive.CoverageSkipped, Reason: "另一条静态资源",
	})
	b := s.buckets[coverageKey{projectID: "p1", host: "a.example", detector: "sqli"}]
	s.mu.Unlock()

	if b == nil {
		t.Fatal("聚合桶不存在")
	}
	if b.state != passive.CoverageTested {
		t.Fatalf("state = %q, want tested（跳过不得降级）", b.state)
	}
	if b.reason != "已执行，无结论" {
		t.Fatalf("reason = %q, want 保留 tested 的原因", b.reason)
	}
	if b.samples != 3 || b.skipped != 2 {
		t.Fatalf("计数 = samples:%d skipped:%d, want 3/2", b.samples, b.skipped)
	}
}

// TestPassiveFindingLineage 锁定详情页的血缘链：
// 资产锚点必须精确匹配、判定手法来自 Extra、覆盖度快照与命中同项目同资产。
func TestPassiveFindingLineage(t *testing.T) {
	withProjectFixture(t)

	// 故意放一个前缀相同的干扰资产，验证精确匹配不会误锚定。
	if _, err := sqlite.CreateAssets("manual", "", nil, []sqlite.AssetInput{
		{Address: "https://a.example", Type: "url"},
		{Address: "https://a.example.evil.com", Type: "url"},
	}); err != nil {
		t.Fatalf("CreateAssets: %v", err)
	}
	if err := sqlite.UpsertPassiveCoverage([]sqlite.PassiveCoverage{
		{ProjectID: "p1", Host: "a.example", Detector: "sqli", State: "hit", Samples: 2, Hits: 1},
		{ProjectID: "p1", Host: "a.example", Detector: "extract", State: "tested", Samples: 3},
	}); err != nil {
		t.Fatalf("UpsertPassiveCoverage: %v", err)
	}

	id, _, _, err := sqlite.UpsertPassiveFinding(sqlite.PassiveFinding{
		ProjectID:   "p1",
		Fingerprint: "sqli|boolean|https://a.example/list|query:id",
		Detector:    "sqli",
		VulnType:    "sqli",
		Severity:    "high",
		Confidence:  "certain",
		Title:       "SQL 注入",
		Target:      "https://a.example/list?id=1",
		Location:    "query:id",
		Payload:     "1' AND 1=1--",
		Evidence:    "布尔差分成立",
		Extra:       `{"technique":"boolean","dialect":"mysql","evasion":"","construct":"closed"}`,
		TracesRaw:   `[{"label":"基线 #1"},{"label":"恒真 #1"}]`,
	})
	if err != nil {
		t.Fatalf("UpsertPassiveFinding: %v", err)
	}

	detail, err := sqlite.GetPassiveFinding(id)
	if err != nil {
		t.Fatalf("GetPassiveFinding: %v", err)
	}
	view := newPassiveFindingDetailView(detail)

	if view.Lineage.Host != "a.example" {
		t.Fatalf("Host = %q, want a.example", view.Lineage.Host)
	}
	if view.Lineage.Asset == nil || view.Lineage.Asset.Address != "https://a.example" {
		t.Fatalf("资产锚点 = %+v, want https://a.example（不得误锚定到前缀相同的干扰资产）", view.Lineage.Asset)
	}
	if view.Lineage.Technique != "boolean" || view.Lineage.Dialect != "mysql" || view.Lineage.Construct != "closed" {
		t.Fatalf("判定手法未从 Extra 正确解析: %+v", view.Lineage)
	}
	if view.Lineage.TraceSteps != 2 {
		t.Fatalf("TraceSteps = %d, want 2", view.Lineage.TraceSteps)
	}
	if len(view.Coverage) != 2 {
		t.Fatalf("覆盖度快照 = %+v, want 2 个检测器", view.Coverage)
	}
	if view.Coverage[0].Detector != "sqli" {
		t.Fatalf("覆盖度应把命中排在最前，实际 = %+v", view.Coverage[0])
	}
}

// TestPassiveFindingAssetIDRoundTrip 锁定落库时写入的 asset_id 会被读取并优先使用。
func TestPassiveFindingAssetIDRoundTrip(t *testing.T) {
	withProjectFixture(t)

	if _, err := sqlite.CreateAssets("manual", "", nil, []sqlite.AssetInput{
		{Address: "https://b.example", Type: "url"},
	}); err != nil {
		t.Fatalf("CreateAssets: %v", err)
	}

	id, _, _, err := sqlite.UpsertPassiveFinding(sqlite.PassiveFinding{
		ProjectID:   "p1",
		AssetID:     "https://b.example",
		Fingerprint: "misconfig|b",
		Detector:    "misconfig",
		VulnType:    "misconfig",
		Target:      "https://b.example/",
	})
	if err != nil {
		t.Fatalf("UpsertPassiveFinding: %v", err)
	}
	detail, err := sqlite.GetPassiveFinding(id)
	if err != nil {
		t.Fatalf("GetPassiveFinding: %v", err)
	}
	if detail.AssetID != "https://b.example" {
		t.Fatalf("asset_id 未落库: %q", detail.AssetID)
	}
	if view := newPassiveFindingDetailView(detail); view.Lineage.Asset == nil {
		t.Fatalf("血缘资产缺失: %+v", view.Lineage)
	}
}

// TestSelectUncoveredAssetsSkipsDirtyTargets 锁定未覆盖清单与建议侧同口径：
// 不可执行地址不得出现在清单里，否则用户会反复点一个必定失败的目标。
func TestSelectUncoveredAssetsSkipsDirtyTargets(t *testing.T) {
	withProjectFixture(t)

	if _, err := sqlite.CreateAssets("manual", "", nil, []sqlite.AssetInput{
		{Address: "https://never.example", Type: "url"},
		{Address: "21", Type: "domain"},
	}); err != nil {
		t.Fatalf("CreateAssets: %v", err)
	}

	total, items := selectUncoveredAssets("", 10)
	if total != 1 || len(items) != 1 || items[0].Address != "https://never.example" {
		t.Fatalf("未覆盖资产 = %+v (total=%d), want 只含 never.example", items, total)
	}
}
