package sqlite

import "testing"

func useFixtureDB(t *testing.T) {
	t.Helper()
	db := newExportFixture(t)
	old := dbx
	dbx = db
	t.Cleanup(func() { dbx = old })
}

func sampleFinding(fp string) PassiveFinding {
	return PassiveFinding{
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

func TestInsertPassiveFindingDeduplicates(t *testing.T) {
	useFixtureDB(t)

	id1, err := InsertPassiveFinding(sampleFinding("sqli|sqli|http://x/|query:id"))
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if id1 == 0 {
		t.Fatalf("first insert must return a non-zero id")
	}

	id2, err := InsertPassiveFinding(sampleFinding("sqli|sqli|http://x/|query:id"))
	if err != nil {
		t.Fatalf("insert duplicate: %v", err)
	}
	if id2 != 0 {
		t.Fatalf("duplicate insert id = %d, want 0 (ignored)", id2)
	}

	n, err := CountPassiveFindings()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
}

func TestSelectPassiveFindingsFilters(t *testing.T) {
	useFixtureDB(t)

	_, _ = InsertPassiveFinding(sampleFinding("fp-1"))
	f2 := sampleFinding("fp-2")
	f2.VulnType = "xss"
	f2.Severity = "medium"
	f2.Target = "http://example.com/search"
	_, _ = InsertPassiveFinding(f2)

	items, total, err := SelectPassiveFindings(PassiveFindingFilter{})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("total = %d items = %d, want 2/2", total, len(items))
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
}

func TestGetPassiveFindingIncludesRaw(t *testing.T) {
	useFixtureDB(t)

	id, err := InsertPassiveFinding(sampleFinding("fp-raw"))
	if err != nil || id == 0 {
		t.Fatalf("insert: %v", err)
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
}

func TestMarkPassiveFindingPromoted(t *testing.T) {
	useFixtureDB(t)

	id, _ := InsertPassiveFinding(sampleFinding("fp-promote"))
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
