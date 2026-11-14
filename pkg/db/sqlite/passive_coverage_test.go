package sqlite

import "testing"

// withCoverageFixture 在隔离库里补建覆盖度表，避免影响其它用例的建表假设。
func withCoverageFixture(t *testing.T) {
	t.Helper()
	db := newExportFixture(t)
	if _, err := db.Exec(passiveCoverageDDL); err != nil {
		t.Fatalf("create coverage schema: %v", err)
	}
	prev := dbx
	dbx = db
	t.Cleanup(func() { dbx = prev })
}

// TestPassiveCoverageStateNeverDowngrades 锁定状态优先级：hit > tested > error > skipped。
//
// 这是覆盖度台账的核心不变量：一次跳过绝不能把「已执行过」擦掉，
// 否则使用者会看到「没测过」，从而重复补扫。
func TestPassiveCoverageStateNeverDowngrades(t *testing.T) {
	withCoverageFixture(t)

	upsert := func(state, reason string, samples, hits, skipped, errors int64) {
		t.Helper()
		err := UpsertPassiveCoverage([]PassiveCoverage{{
			ProjectID: "p1", Host: "a.example", Detector: "sqli",
			State: state, Reason: reason,
			Samples: samples, Hits: hits, Skipped: skipped, Errors: errors,
		}})
		if err != nil {
			t.Fatalf("upsert %s: %v", state, err)
		}
	}
	row := func() PassiveCoverage {
		t.Helper()
		items, total, err := SelectPassiveCoverage(PassiveCoverageFilter{ProjectID: "p1"})
		if err != nil || total != 1 || len(items) != 1 {
			t.Fatalf("select = %v, total=%d, err=%v", items, total, err)
		}
		return items[0]
	}

	upsert("skipped", "静态资源不参与注入检测", 1, 0, 1, 0)
	if r := row(); r.State != "skipped" || r.Skipped != 1 {
		t.Fatalf("首次跳过 = %+v", r)
	}

	upsert("tested", "已执行，无结论", 1, 0, 0, 0)
	if r := row(); r.State != "tested" || r.Samples != 2 {
		t.Fatalf("执行后 = %+v, want state=tested samples=2", r)
	}

	upsert("skipped", "另一条静态资源", 1, 0, 1, 0)
	r := row()
	if r.State != "tested" || r.Reason != "已执行，无结论" {
		t.Fatalf("跳过不得降级或覆盖原因: %+v", r)
	}
	if r.Samples != 3 || r.Skipped != 2 {
		t.Fatalf("计数必须无条件累加: %+v", r)
	}

	upsert("hit", "命中 1 条", 1, 1, 0, 0)
	if r := row(); r.State != "hit" || r.Hits != 1 || r.Reason != "命中 1 条" {
		t.Fatalf("命中后 = %+v", r)
	}

	upsert("tested", "已执行，无结论", 1, 0, 0, 0)
	upsert("error", "boom", 1, 0, 0, 1)
	r = row()
	if r.State != "hit" || r.Reason != "命中 1 条" {
		t.Fatalf("命中是最强结论，不得被覆盖: %+v", r)
	}
	if r.Errors != 1 || r.Samples != 6 {
		t.Fatalf("错误计数与样本数必须保留: %+v", r)
	}
}

// TestPassiveCoverageSummaryAndHosts 锁定汇总口径与已覆盖资产集合。
func TestPassiveCoverageSummaryAndHosts(t *testing.T) {
	withCoverageFixture(t)

	if err := UpsertPassiveCoverage([]PassiveCoverage{
		{ProjectID: "p1", Host: "a.example", Detector: "sqli", State: "hit", Samples: 3, Hits: 1},
		{ProjectID: "p1", Host: "a.example", Detector: "extract", State: "tested", Samples: 5},
		{ProjectID: "p1", Host: "b.example", Detector: "sqli", State: "error", Samples: 1, Errors: 1},
		{ProjectID: "p2", Host: "c.example", Detector: "sqli", State: "hit", Samples: 1, Hits: 1},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	sum, err := SelectPassiveCoverageSummary("p1")
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if sum.Total != 3 || sum.Hosts != 2 || sum.Hit != 1 || sum.Tested != 1 || sum.Error != 1 {
		t.Fatalf("summary = %+v", sum)
	}

	hosts, err := SelectCoverageHosts("p1")
	if err != nil {
		t.Fatalf("hosts: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("hosts = %v, want 2 项", hosts)
	}
	if _, ok := hosts["c.example"]; ok {
		t.Fatalf("项目隔离失效：p2 的资产出现在 p1 的覆盖度里")
	}

	items, total, err := SelectPassiveCoverage(PassiveCoverageFilter{ProjectID: "p1", State: []string{"hit"}})
	if err != nil || total != 1 || len(items) != 1 || items[0].Detector != "sqli" {
		t.Fatalf("state 过滤 = %v, total=%d, err=%v", items, total, err)
	}

	items, total, err = SelectPassiveCoverage(PassiveCoverageFilter{ProjectID: "p1", Keyword: "b.example"})
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("keyword 过滤 = %v, total=%d, err=%v", items, total, err)
	}
}

// TestSelectAssetsForCoverage 锁定只取能映射到 authority 的资产，且按项目过滤。
func TestSelectAssetsForCoverage(t *testing.T) {
	withCoverageFixture(t)

	if _, err := dbx.Exec(
		`INSERT INTO "asset"("id","address","type","archived") VALUES
			('1','https://a.example','url',0),
			('2','b.example','domain',1),
			('3','10.0.0.0/24','cidr',0),
			('4','10.0.0.5:8080','hostport',0)`,
	); err != nil {
		t.Fatalf("seed assets: %v", err)
	}
	if _, err := dbx.Exec(
		`INSERT INTO "project_asset"("project_id","asset_id") VALUES
			('p1','1'),('p1','3'),('p1','4'),('p2','2')`,
	); err != nil {
		t.Fatalf("seed project_asset: %v", err)
	}

	assets, err := SelectAssetsForCoverage("p1")
	if err != nil {
		t.Fatalf("select assets: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("assets = %+v, want 2 条（url + hostport，排除 cidr）", assets)
	}
	for _, a := range assets {
		if a.Type == "cidr" {
			t.Fatalf("cidr 不应参与被动覆盖度比对: %+v", a)
		}
	}
}
