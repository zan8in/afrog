package sqlite

import "testing"

func sampleExtraction(projectID, fp string) PassiveExtraction {
	return PassiveExtraction{
		ProjectID:   projectID,
		Fingerprint: fp,
		Detector:    "extract",
		Rule:        "aws-access-key-id",
		Category:    "cloud-key",
		Title:       "AWS 访问密钥",
		Severity:    "high",
		Confidence:  "probable",
		Value:       "AKIAIOSFODNN7EXAMPLE",
		Target:      "https://example.com",
		Location:    "response-body",
		Evidence:    "…const key = \"AKIA…\"…",
		Request:     "GET /app.js HTTP/1.1",
		Response:    "HTTP/1.1 200 OK",
		Extra:       `{"status":200}`,
	}
}

// 同一作用域内重复提取必须归并为一条：累加次数，而不是新增一行。
func TestUpsertPassiveExtractionAggregates(t *testing.T) {
	useFixtureDB(t)

	const fp = "aws-access-key-id|AKIAIOSFODNN7EXAMPLE|https://example.com"
	id1, hit1, err := UpsertPassiveExtraction(sampleExtraction("", fp))
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if id1 == 0 || hit1 != 1 {
		t.Fatalf("first upsert = id:%d hit:%d, want non-zero/1", id1, hit1)
	}

	id2, hit2, err := UpsertPassiveExtraction(sampleExtraction("", fp))
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if id2 != id1 {
		t.Fatalf("second upsert id = %d, want %d (same row)", id2, id1)
	}
	if hit2 != 2 {
		t.Fatalf("second upsert hit = %d, want 2", hit2)
	}

	n, err := CountPassiveExtractions()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
}

// 去重作用域是「项目」：同一个密钥在不同项目下必须是两条独立观察。
func TestUpsertPassiveExtractionScopesByProject(t *testing.T) {
	useFixtureDB(t)

	const fp = "aws-access-key-id|AKIAIOSFODNN7EXAMPLE|https://example.com"
	idA, _, err := UpsertPassiveExtraction(sampleExtraction("p_a", fp))
	if err != nil {
		t.Fatalf("upsert project A: %v", err)
	}
	idB, hitB, err := UpsertPassiveExtraction(sampleExtraction("p_b", fp))
	if err != nil {
		t.Fatalf("upsert project B: %v", err)
	}
	if idB == idA {
		t.Fatalf("different projects must not share a row: %d", idB)
	}
	if hitB != 1 {
		t.Fatalf("project B first upsert hit = %d, want 1", hitB)
	}

	nA, err := CountPassiveExtractionsByProject("p_a")
	if err != nil {
		t.Fatalf("count project A: %v", err)
	}
	if nA != 1 {
		t.Fatalf("project A count = %d, want 1", nA)
	}

	n, _ := CountPassiveExtractions()
	if n != 2 {
		t.Fatalf("total count = %d, want 2", n)
	}
}

// 缺少 fingerprint 的观察无法参与聚合，必须被拒绝而不是落一条脏数据。
func TestUpsertPassiveExtractionRejectsEmptyFingerprint(t *testing.T) {
	useFixtureDB(t)

	if _, _, err := UpsertPassiveExtraction(sampleExtraction("", "  ")); err == nil {
		t.Fatalf("empty fingerprint must be rejected")
	}
}

func TestSelectPassiveExtractionsFilters(t *testing.T) {
	useFixtureDB(t)

	_, _, _ = UpsertPassiveExtraction(sampleExtraction("p_a", "fp-1"))
	e2 := sampleExtraction("p_a", "fp-2")
	e2.Rule = "jwt"
	e2.Category = "token"
	e2.Severity = "medium"
	e2.Target = "https://api.example.com/token"
	e2.Value = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
	_, _, _ = UpsertPassiveExtraction(e2)
	_, _, _ = UpsertPassiveExtraction(sampleExtraction("p_b", "fp-3"))

	items, total, err := SelectPassiveExtractions(PassiveExtractionFilter{})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if total != 3 || len(items) != 3 {
		t.Fatalf("total = %d items = %d, want 3/3", total, len(items))
	}

	_, total, err = SelectPassiveExtractions(PassiveExtractionFilter{Category: "token"})
	if err != nil {
		t.Fatalf("select by category: %v", err)
	}
	if total != 1 {
		t.Fatalf("category=token total = %d, want 1", total)
	}

	_, total, err = SelectPassiveExtractions(PassiveExtractionFilter{Rule: "aws-access-key-id"})
	if err != nil {
		t.Fatalf("select by rule: %v", err)
	}
	if total != 2 {
		t.Fatalf("rule=aws total = %d, want 2", total)
	}

	_, total, err = SelectPassiveExtractions(PassiveExtractionFilter{Keyword: "api.example.com"})
	if err != nil {
		t.Fatalf("select by keyword: %v", err)
	}
	if total != 1 {
		t.Fatalf("keyword total = %d, want 1", total)
	}

	_, total, err = SelectPassiveExtractions(PassiveExtractionFilter{ProjectID: "p_a"})
	if err != nil {
		t.Fatalf("select by project: %v", err)
	}
	if total != 2 {
		t.Fatalf("project p_a total = %d, want 2", total)
	}

	_, total, err = SelectPassiveExtractions(PassiveExtractionFilter{Severity: "high"})
	if err != nil {
		t.Fatalf("select by severity: %v", err)
	}
	if total != 2 {
		t.Fatalf("severity=high total = %d, want 2", total)
	}
}

// 列表查询不能把原始请求/响应带出来（响应会随记录数线性膨胀），详情接口才需要。
func TestGetPassiveExtractionIncludesRaw(t *testing.T) {
	useFixtureDB(t)

	id, _, err := UpsertPassiveExtraction(sampleExtraction("p_a", "fp-raw"))
	if err != nil || id == 0 {
		t.Fatalf("upsert: %v", err)
	}

	items, _, err := SelectPassiveExtractions(PassiveExtractionFilter{})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if len(items) != 1 || items[0].Request != "" || items[0].Response != "" {
		t.Fatalf("list rows must not carry raw request/response")
	}

	detail, err := GetPassiveExtraction(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if detail.Request == "" || detail.Response == "" {
		t.Fatalf("raw request/response must be present in detail view")
	}
	if detail.HitCount != 1 {
		t.Fatalf("hit_count = %d, want 1", detail.HitCount)
	}
	if detail.FirstSeen == "" || detail.LastSeen == "" {
		t.Fatalf("timeline must be populated on first insert")
	}
}
