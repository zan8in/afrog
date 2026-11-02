package sqlite

import "testing"

func useFixtureDB(t *testing.T) {
	t.Helper()
	db := newExportFixture(t)
	old := dbx
	dbx = db
	t.Cleanup(func() { dbx = old })
}

func sampleFinding(projectID, fp string) PassiveFinding {
	return PassiveFinding{
		ProjectID:   projectID,
		Fingerprint: fp,
		Detector:    "sqli",
		VulnType:    "sqli",
		Severity:    "high",
		Confidence:  "certain",
		Title:       "SQL 注入",
		Target:      "http://example.com/list",
		Location:    "query:id",
		Payload:     "1 AND 1=1-- -",
		Evidence:    "布尔差分成立",
		Request:     "GET /list?id=1 HTTP/1.1",
		Response:    "HTTP/1.1 200 OK",
		Extra:       "{}",
	}
}

// 同一作用域内重复命中必须归并为一条：累加次数、状态转 present，而不是新增一行。
func TestUpsertPassiveFindingAggregates(t *testing.T) {
	useFixtureDB(t)

	const fp = "sqli|sqli|http://x/|query:id"
	id1, state1, hit1, err := UpsertPassiveFinding(sampleFinding("", fp))
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if id1 == 0 || state1 != PassiveStateNew || hit1 != 1 {
		t.Fatalf("first upsert = id:%d state:%s hit:%d, want non-zero/new/1", id1, state1, hit1)
	}

	id2, state2, hit2, err := UpsertPassiveFinding(sampleFinding("", fp))
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if id2 != id1 {
		t.Fatalf("second upsert id = %d, want %d (same row)", id2, id1)
	}
	if state2 != PassiveStatePresent || hit2 != 2 {
		t.Fatalf("second upsert = state:%s hit:%d, want present/2", state2, hit2)
	}

	n, err := CountPassiveFindings()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
}

// 去重的作用域是「项目」：同一漏洞在不同项目下必须是两条独立观察。
func TestUpsertPassiveFindingScopesByProject(t *testing.T) {
	useFixtureDB(t)

	const fp = "sqli|sqli|http://x/|query:id"
	idA, _, _, err := UpsertPassiveFinding(sampleFinding("p_a", fp))
	if err != nil {
		t.Fatalf("upsert project A: %v", err)
	}
	idB, stateB, hitB, err := UpsertPassiveFinding(sampleFinding("p_b", fp))
	if err != nil {
		t.Fatalf("upsert project B: %v", err)
	}
	if idB == idA {
		t.Fatalf("different projects must not share a row: %d", idB)
	}
	// 跨项目不算重复命中，仍应是「新增」且次数为 1。
	if stateB != PassiveStateNew || hitB != 1 {
		t.Fatalf("project B first upsert = state:%s hit:%d, want new/1", stateB, hitB)
	}

	// 未归属（空 project_id）同样自成一个作用域。
	idNone, stateNone, hitNone, err := UpsertPassiveFinding(sampleFinding("", fp))
	if err != nil {
		t.Fatalf("upsert unassigned: %v", err)
	}
	if idNone == idA || idNone == idB {
		t.Fatalf("unassigned scope must be independent: %d", idNone)
	}
	if stateNone != PassiveStateNew || hitNone != 1 {
		t.Fatalf("unassigned first upsert = state:%s hit:%d, want new/1", stateNone, hitNone)
	}

	n, _ := CountPassiveFindings()
	if n != 3 {
		t.Fatalf("count = %d, want 3", n)
	}
}

// 人工标记「已修复」后再次命中，必须转为「复发」——这是复测场景的核心语义。
func TestUpsertPassiveFindingRegressionAfterFixed(t *testing.T) {
	useFixtureDB(t)

	const fp = "sqli|sqli|http://x/|query:id"
	id, _, _, err := UpsertPassiveFinding(sampleFinding("p_a", fp))
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := SetPassiveFindingState(id, PassiveStateFixed); err != nil {
		t.Fatalf("mark fixed: %v", err)
	}

	_, state, hit, err := UpsertPassiveFinding(sampleFinding("p_a", fp))
	if err != nil {
		t.Fatalf("upsert after fixed: %v", err)
	}
	if state != PassiveStateRegression || hit != 2 {
		t.Fatalf("after fixed = state:%s hit:%d, want regression/2", state, hit)
	}
}

func TestSetPassiveFindingStateRejectsUnknown(t *testing.T) {
	useFixtureDB(t)

	id, _, _, err := UpsertPassiveFinding(sampleFinding("", "fp-state"))
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := SetPassiveFindingState(id, PassiveStateRegression); err == nil {
		t.Fatalf("regression must not be settable manually")
	}
}

func TestSelectPassiveFindingsFilters(t *testing.T) {
	useFixtureDB(t)

	_, _, _, _ = UpsertPassiveFinding(sampleFinding("p_a", "fp-1"))
	f2 := sampleFinding("p_a", "fp-2")
	f2.VulnType = "xss"
	f2.Severity = "medium"
	f2.Target = "http://example.com/search"
	_, _, _, _ = UpsertPassiveFinding(f2)
	_, _, _, _ = UpsertPassiveFinding(sampleFinding("p_b", "fp-3"))

	items, total, err := SelectPassiveFindings(PassiveFindingFilter{})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if total != 3 || len(items) != 3 {
		t.Fatalf("total = %d items = %d, want 3/3", total, len(items))
	}

	items, total, err = SelectPassiveFindings(PassiveFindingFilter{VulnType: "xss"})
	if err != nil {
		t.Fatalf("select by type: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].VulnType != "xss" {
		t.Fatalf("filter by vuln_type failed: total=%d items=%d", total, len(items))
	}

	items, total, err = SelectPassiveFindings(PassiveFindingFilter{Keyword: "search"})
	if err != nil {
		t.Fatalf("select by keyword: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("filter by keyword failed: total=%d", total)
	}

	// 项目作用域筛选：p_a 下 2 条，p_b 下 1 条。
	_, total, err = SelectPassiveFindings(PassiveFindingFilter{ProjectID: "p_a"})
	if err != nil {
		t.Fatalf("select by project: %v", err)
	}
	if total != 2 {
		t.Fatalf("project p_a total = %d, want 2", total)
	}

	// 状态筛选：全部是新增。
	_, total, err = SelectPassiveFindings(PassiveFindingFilter{State: []string{PassiveStateNew}})
	if err != nil {
		t.Fatalf("select by state: %v", err)
	}
	if total != 3 {
		t.Fatalf("state=new total = %d, want 3", total)
	}
	_, total, _ = SelectPassiveFindings(PassiveFindingFilter{State: []string{PassiveStateFixed}})
	if total != 0 {
		t.Fatalf("state=fixed total = %d, want 0", total)
	}
}

func TestGetPassiveFindingIncludesRaw(t *testing.T) {
	useFixtureDB(t)

	id, _, _, err := UpsertPassiveFinding(sampleFinding("p_a", "fp-raw"))
	if err != nil || id == 0 {
		t.Fatalf("upsert: %v", err)
	}

	detail, err := GetPassiveFinding(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if detail.Request == "" || detail.Response == "" {
		t.Fatalf("raw request/response must be present in detail view")
	}
	if detail.Promoted != 0 {
		t.Fatalf("Promoted = %d, want 0", detail.Promoted)
	}
	if detail.State != PassiveStateNew || detail.HitCount != 1 {
		t.Fatalf("state = %s hit = %d, want new/1", detail.State, detail.HitCount)
	}
	if detail.FirstSeen == "" || detail.LastSeen == "" {
		t.Fatalf("timeline must be populated on first insert")
	}
}

func TestMarkPassiveFindingPromoted(t *testing.T) {
	useFixtureDB(t)

	id, _, _, _ := UpsertPassiveFinding(sampleFinding("p_a", "fp-promote"))
	if err := MarkPassiveFindingPromoted(id, "result-1"); err != nil {
		t.Fatalf("mark: %v", err)
	}

	detail, err := GetPassiveFinding(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if detail.Promoted != 1 || detail.ResultID != "result-1" {
		t.Fatalf("promote state = %d/%q, want 1/result-1", detail.Promoted, detail.ResultID)
	}
}

func TestCountPassiveFindingsByProject(t *testing.T) {
	useFixtureDB(t)

	_, _, _, _ = UpsertPassiveFinding(sampleFinding("p_a", "fp-1"))
	_, _, _, _ = UpsertPassiveFinding(sampleFinding("p_a", "fp-2"))
	_, _, _, _ = UpsertPassiveFinding(sampleFinding("p_b", "fp-3"))

	n, err := CountPassiveFindingsByProject("p_a")
	if err != nil {
		t.Fatalf("count by project: %v", err)
	}
	if n != 2 {
		t.Fatalf("count p_a = %d, want 2", n)
	}
}
