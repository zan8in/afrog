package sqlite

import "testing"

// TestSuggestionSources 锁定三条建议数据源的口径与互斥关系。
func TestSuggestionSources(t *testing.T) {
	withCoverageFixture(t)

	// 三个资产：陈旧（扫过但很久以前）、刚扫过、从未扫过。
	if _, err := dbx.Exec(`INSERT INTO "asset"("id","address","type","archived","last_scan_at") VALUES
		('https://stale.example','https://stale.example','url',0,'2020-01-01 00:00:00'),
		('https://fresh.example','https://fresh.example','url',0,'2099-01-01 00:00:00'),
		('https://never.example','https://never.example','url',0,'')`); err != nil {
		t.Fatalf("seed assets: %v", err)
	}

	if err := UpsertPassiveCoverage([]PassiveCoverage{
		// 全部是 skipped：这是覆盖空洞。
		{ProjectID: "", Host: "gap.example", Detector: "sqli", State: "skipped", Samples: 2, Skipped: 2},
		{ProjectID: "", Host: "gap.example", Detector: "extract", State: "skipped", Samples: 2, Skipped: 2},
		// 有真实结论：不算空洞。
		{ProjectID: "", Host: "ok.example", Detector: "sqli", State: "tested", Samples: 1},
		{ProjectID: "", Host: "ok.example", Detector: "extract", State: "skipped", Samples: 1, Skipped: 1},
	}); err != nil {
		t.Fatalf("seed coverage: %v", err)
	}

	// 三条命中：一条待提升、一条已提升、一条已人工标记修复。
	for _, f := range []PassiveFinding{
		{Fingerprint: "f1", Detector: "sqli", Title: "待提升", Target: "https://never.example/a"},
		{Fingerprint: "f2", Detector: "sqli", Title: "已提升", Target: "https://never.example/b"},
		{Fingerprint: "f3", Detector: "sqli", Title: "已修复", Target: "https://never.example/c"},
	} {
		id, _, _, err := UpsertPassiveFinding(f)
		if err != nil {
			t.Fatalf("UpsertPassiveFinding: %v", err)
		}
		switch f.Fingerprint {
		case "f2":
			if err := MarkPassiveFindingPromoted(id, "r-1"); err != nil {
				t.Fatalf("mark promoted: %v", err)
			}
		case "f3":
			if err := SetPassiveFindingState(id, PassiveStateFixed); err != nil {
				t.Fatalf("mark fixed: %v", err)
			}
		}
	}

	hosts, total, err := SelectCoverageGapHosts(10)
	if err != nil {
		t.Fatalf("SelectCoverageGapHosts: %v", err)
	}
	if total != 1 || len(hosts) != 1 || hosts[0] != "gap.example" {
		t.Fatalf("覆盖空洞 = %v (total=%d), want [gap.example]", hosts, total)
	}

	stale, staleTotal, err := SelectStaleAssets(30, 10)
	if err != nil {
		t.Fatalf("SelectStaleAssets: %v", err)
	}
	if staleTotal != 1 || len(stale) != 1 || stale[0].Address != "https://stale.example" {
		t.Fatalf("陈旧资产 = %+v (total=%d), want stale.example 1 条", stale, staleTotal)
	}

	briefs, unpromoted, err := SelectUnpromotedPassiveFindings(10)
	if err != nil {
		t.Fatalf("SelectUnpromotedPassiveFindings: %v", err)
	}
	if unpromoted != 1 || len(briefs) != 1 || briefs[0].Title != "待提升" {
		t.Fatalf("未入台账命中 = %+v (total=%d), want 1 条「待提升」", briefs, unpromoted)
	}
}
