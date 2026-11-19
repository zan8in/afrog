package sqlite

import (
	"fmt"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/zan8in/afrog/v3/pkg/evidence"
	"github.com/zan8in/afrog/v3/pkg/finding"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/ref"
	"github.com/zan8in/afrog/v3/pkg/result"
)

// useFindingFixture 复用整库夹具并切换全局 dbx，供 Finding 投影查询使用。
func useFindingFixture(t *testing.T) *sqlx.DB {
	t.Helper()
	db := newExportFixture(t)
	prev := dbx
	dbx = db
	t.Cleanup(func() { dbx = prev })
	return db
}

// insertFindingResult 插入一条命中，poc 列写入可解析的 JSON，供类目推导使用。
func insertFindingResult(t *testing.T, db *sqlx.DB, id int, taskID, vulid, target, fulltarget, created, cweID string) {
	t.Helper()
	pocJSON := fmt.Sprintf(`{"Id":%q,"Info":{"Author":"afrog","Classification":{"CweId":%q}}}`, vulid, cweID)
	_, err := db.Exec(
		`INSERT INTO result(id, taskid, vulid, vulname, target, fulltarget, severity, poc, result, created, fingerprint, extractor)
		 VALUES(?, ?, ?, ?, ?, ?, 'high', ?, '', ?, '', '')`,
		id, taskID, vulid, "name-"+vulid, target, fulltarget, pocJSON, created)
	if err != nil {
		t.Fatalf("insert result: %v", err)
	}
}

// linkFindingProject 把任务归属到项目，Finding 的 (项目, 主体, 类目) 口径依赖它。
func linkFindingProject(t *testing.T, db *sqlx.DB, taskID, projectID, createdAt string) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO task_project(taskid, project_id, created_at) VALUES(?, ?, ?)`,
		taskID, projectID, createdAt); err != nil {
		t.Fatalf("insert task_project: %v", err)
	}
}

func findFindingByID(items []finding.Finding, id string) *finding.Finding {
	for i := range items {
		if items[i].ID == id {
			return &items[i]
		}
	}
	return nil
}

// 类目级聚合：同一主体上映射到同一 CWE 的不同 PoC 归为一条结论，
// 重复命中累加 hit_count 与 last_seen，代表值取确定性的极值。
func TestSelectFindingsAggregatesBySubjectAndClass(t *testing.T) {
	db := useFindingFixture(t)

	linkFindingProject(t, db, "t-1", "p-alpha", "2026-09-28 10:00:00")
	linkFindingProject(t, db, "t-2", "p-alpha", "2026-09-28 10:00:00")

	// 同一主体、同一 CWE，来自两个任务的两次命中。
	insertFindingResult(t, db, 1, "t-1", "poc-a", "http://a.example", "http://a.example/1", "2026-09-28 10:00:00", "CWE-89")
	insertFindingResult(t, db, 2, "t-2", "poc-b", "http://a.example", "http://a.example/1", "2026-09-28 11:00:00", "CWE-89")
	// 同一主机、不同端点：主体不同，必须是另一条结论。
	insertFindingResult(t, db, 3, "t-1", "poc-c", "http://a.example", "http://a.example/2", "2026-09-28 12:00:00", "CWE-79")

	page, err := SelectFindings(LedgerFilter{Project: "p-alpha"})
	if err != nil {
		t.Fatalf("SelectFindings: %v", err)
	}
	if page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("total/items = %d/%d, want 2/2", page.Total, len(page.Items))
	}

	wantID := finding.IDFor("p-alpha", ref.Endpoint("http://a.example/1"), "cwe-89")
	got := findFindingByID(page.Items, wantID)
	if got == nil {
		t.Fatalf("finding %s not found: %+v", wantID, page.Items)
	}
	if got.HitCount != 2 {
		t.Fatalf("hit_count = %d, want 2", got.HitCount)
	}
	if got.Severity != "HIGH" || got.VulnClass != "cwe-89" {
		t.Fatalf("severity/class = %s/%s, want HIGH/cwe-89", got.Severity, got.VulnClass)
	}
	if got.FirstSeen != "2026-09-28 10:00:00" || got.LastSeen != "2026-09-28 11:00:00" {
		t.Fatalf("first/last = %s/%s, want 10:00/11:00", got.FirstSeen, got.LastSeen)
	}
	if got.Source != finding.SourceActive {
		t.Fatalf("source = %s, want active", got.Source)
	}
	// 可读目标与来源 PoC：subject 是不透明的 ep_ id，target 是可读 URL；同一类目下
	// 由两个 PoC 命中聚合而来，poc_ids 必须给全且去重升序。
	if got.Target != "http://a.example/1" {
		t.Fatalf("target = %q, want http://a.example/1", got.Target)
	}
	if len(got.PocIDs) != 2 || got.PocIDs[0] != "poc-a" || got.PocIDs[1] != "poc-b" {
		t.Fatalf("poc_ids = %v, want [poc-a poc-b]", got.PocIDs)
	}
}

// 同一个 (项目, 主体, 类目) 在任何路径下都必须算出同一个 id；项目参与 canonical，
// 因此不同项目下的同一漏洞是两条独立结论。
func TestSelectFindingsIDIsStableAndScopedByProject(t *testing.T) {
	db := useFindingFixture(t)

	linkFindingProject(t, db, "t-a", "p-a", "2026-09-28 10:00:00")
	linkFindingProject(t, db, "t-b", "p-b", "2026-09-28 10:00:00")

	insertFindingResult(t, db, 1, "t-a", "poc-a", "http://a.example", "http://a.example/1", "2026-09-28 10:00:00", "CWE-89")
	insertFindingResult(t, db, 2, "t-b", "poc-a", "http://a.example", "http://a.example/1", "2026-09-28 10:00:00", "CWE-89")

	page, err := SelectFindings(LedgerFilter{})
	if err != nil {
		t.Fatalf("SelectFindings: %v", err)
	}
	if page.Total != 2 {
		t.Fatalf("total = %d, want 2 (project-scoped)", page.Total)
	}

	idA := finding.IDFor("p-a", ref.Endpoint("http://a.example/1"), "cwe-89")
	idB := finding.IDFor("p-b", ref.Endpoint("http://a.example/1"), "cwe-89")
	if findFindingByID(page.Items, idA) == nil || findFindingByID(page.Items, idB) == nil {
		t.Fatalf("expected %s and %s, got %+v", idA, idB, page.Items)
	}
}

// 证据回填：finding.Evidence 收集组内各条命中的代表证据，confidence 取最高，
// 并且这些 id 能通过 evidence 查询回读。
func TestSelectFindingsBackfillsEvidence(t *testing.T) {
	db := useFindingFixture(t)

	linkFindingProject(t, db, "t-1", "p-alpha", "2026-09-28 10:00:00")
	insertFindingResult(t, db, 1, "t-1", "poc-a", "http://a.example", "http://a.example/1", "2026-09-28 10:00:00", "CWE-89")
	insertFindingResult(t, db, 2, "t-1", "poc-b", "http://a.example", "http://a.example/1", "2026-09-28 11:00:00", "CWE-89")

	for _, ev := range []*evidence.Evidence{
		{ID: "evd-one", PocID: "poc-a", Target: "http://a.example/1", Confidence: "probable", Created: "2026-09-28 10:00:00", Steps: []evidence.Step{}},
		{ID: "evd-two", PocID: "poc-b", Target: "http://a.example/1", Confidence: "certain", Created: "2026-09-28 11:00:00", Steps: []evidence.Step{}},
	} {
		if err := InsertEvidence(ev, 0, "t-1"); err != nil {
			t.Fatalf("insert evidence %s: %v", ev.ID, err)
		}
	}
	// InsertEvidence 不落 result_id，这里手工补上，让投影能按 result 取到证据。
	if _, err := db.Exec(`UPDATE evidence SET result_id = 1 WHERE id = 'evd-one'`); err != nil {
		t.Fatalf("update evidence result_id: %v", err)
	}
	if _, err := db.Exec(`UPDATE evidence SET result_id = 2 WHERE id = 'evd-two'`); err != nil {
		t.Fatalf("update evidence result_id: %v", err)
	}

	page, err := SelectFindings(LedgerFilter{Project: "p-alpha"})
	if err != nil {
		t.Fatalf("SelectFindings: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(page.Items))
	}
	got := page.Items[0]
	if len(got.Evidence) != 2 {
		t.Fatalf("evidence = %v, want 2 refs", got.Evidence)
	}
	seen := map[string]bool{}
	for _, id := range got.Evidence {
		seen[id] = true
		if ev, err := SelectEvidenceByID(id); err != nil || ev == nil {
			t.Fatalf("evidence %s not readable: ev=%+v err=%v", id, ev, err)
		}
	}
	if !seen["evd-one"] || !seen["evd-two"] {
		t.Fatalf("evidence = %v, want both evd-one and evd-two", got.Evidence)
	}
	if got.Confidence != "certain" {
		t.Fatalf("confidence = %s, want certain (highest of the group)", got.Confidence)
	}
}

// 状态由台账叠加：人工标记 fixed 后，投影出的 state 随之变成 fixed。
func TestSelectFindingsFollowsLedgerStatus(t *testing.T) {
	db := useFindingFixture(t)

	linkFindingProject(t, db, "t-1", "p-alpha", "2026-09-28 10:00:00")
	insertFindingResult(t, db, 1, "t-1", "poc-a", "http://a.example", "http://a.example/1", "2026-09-28 10:00:00", "CWE-89")
	insertFindingResult(t, db, 2, "t-1", "poc-c", "http://a.example", "http://a.example/2", "2026-09-28 12:00:00", "CWE-79")

	if _, err := db.Exec(
		`INSERT INTO vuln_ledger(vulid, target, fulltarget, status, note, updated_at)
		 VALUES('poc-c', 'http://a.example', 'http://a.example/2', 'fixed', '', '2026-09-28 13:00:00')`); err != nil {
		t.Fatalf("insert ledger: %v", err)
	}

	page, err := SelectFindings(LedgerFilter{Project: "p-alpha"})
	if err != nil {
		t.Fatalf("SelectFindings: %v", err)
	}
	fixed := findFindingByID(page.Items, finding.IDFor("p-alpha", ref.Endpoint("http://a.example/2"), "cwe-79"))
	if fixed == nil {
		t.Fatalf("fixed finding not found: %+v", page.Items)
	}
	if fixed.State != finding.StateFixed || fixed.Status != "fixed" {
		t.Fatalf("state/status = %s/%s, want fixed/fixed", fixed.State, fixed.Status)
	}

	pending := findFindingByID(page.Items, finding.IDFor("p-alpha", ref.Endpoint("http://a.example/1"), "cwe-89"))
	if pending == nil || pending.State != finding.StateNew {
		t.Fatalf("pending finding state = %+v, want new", pending)
	}
}

// 投影在 Go 侧分页：total 是聚合后的结论数，不是台账行数。
func TestSelectFindingsPaginates(t *testing.T) {
	db := useFindingFixture(t)

	linkFindingProject(t, db, "t-1", "p-alpha", "2026-09-28 10:00:00")
	insertFindingResult(t, db, 1, "t-1", "poc-a", "http://a.example", "http://a.example/1", "2026-09-28 10:00:00", "CWE-89")
	insertFindingResult(t, db, 2, "t-1", "poc-b", "http://a.example", "http://a.example/2", "2026-09-28 11:00:00", "CWE-89")
	insertFindingResult(t, db, 3, "t-1", "poc-c", "http://a.example", "http://a.example/3", "2026-09-28 12:00:00", "CWE-89")

	first, err := SelectFindings(LedgerFilter{Project: "p-alpha", Page: 1, PageSize: 1})
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if first.Total != 3 || len(first.Items) != 1 {
		t.Fatalf("page1 total/items = %d/%d, want 3/1", first.Total, len(first.Items))
	}
	// 按 last_seen 倒序：12:00 的端点排在最前。
	if first.Items[0].Subject != ref.Endpoint("http://a.example/3") {
		t.Fatalf("page1 subject = %s, want endpoint /3", first.Items[0].Subject)
	}

	second, err := SelectFindings(LedgerFilter{Project: "p-alpha", Page: 2, PageSize: 1})
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(second.Items) != 1 || second.Items[0].Subject != ref.Endpoint("http://a.example/2") {
		t.Fatalf("page2 items = %+v, want endpoint /2", second.Items)
	}
}

// 归组是纯函数：行顺序不影响结果，代表值都取确定性的极值。
func TestGroupFindingsIsOrderIndependent(t *testing.T) {
	rowA := findingRow{
		VulID: "poc-a", VulName: "n-a", Target: "http://a.example", FullTarget: "http://a.example/1",
		Severity: "high", FirstSeen: "2026-09-28 10:00:00", LastSeen: "2026-09-28 10:00:00",
		HitCount: 1, Status: "pending", ProjectID: "p-alpha",
		Poc: `{"Id":"poc-a","Info":{"Classification":{"CweId":"CWE-89"}}}`,
	}
	rowB := findingRow{
		VulID: "poc-b", VulName: "n-b", Target: "http://a.example", FullTarget: "http://a.example/1",
		Severity: "critical", FirstSeen: "2026-09-28 11:00:00", LastSeen: "2026-09-28 11:00:00",
		HitCount: 1, Status: "pending", ProjectID: "p-alpha",
		Poc: `{"Id":"poc-b","Info":{"Classification":{"CweId":"CWE-89"}}}`,
	}

	forward := groupFindings([]findingRow{rowA, rowB})
	reverse := groupFindings([]findingRow{rowB, rowA})
	if len(forward) != 1 || len(reverse) != 1 {
		t.Fatalf("groups = %d/%d, want 1/1", len(forward), len(reverse))
	}

	wantID := finding.IDFor("p-alpha", ref.Endpoint("http://a.example/1"), "cwe-89")
	for _, g := range []*findingGroup{forward[0], reverse[0]} {
		f := g.Finding
		if f.ID != wantID {
			t.Fatalf("id = %s, want %s", f.ID, wantID)
		}
		if f.HitCount != 2 || f.Severity != "CRITICAL" {
			t.Fatalf("hit/severity = %d/%s, want 2/CRITICAL", f.HitCount, f.Severity)
		}
		if f.FirstSeen != "2026-09-28 10:00:00" || f.LastSeen != "2026-09-28 11:00:00" {
			t.Fatalf("first/last = %s/%s, want 10:00/11:00", f.FirstSeen, f.LastSeen)
		}
	}
}

// 落库时写 finding → evidence 的判定边：D3 已定，证据可用后即可从图上反查。
func TestInsertEvidenceForResultLinksFindingEdge(t *testing.T) {
	db := useFindingFixture(t)
	linkFindingProject(t, db, "t-1", "p-alpha", "2026-09-28 10:00:00")

	r := &result.Result{
		Target:     "http://a.example",
		FullTarget: "http://a.example/1",
		PocInfo:    &poc.Poc{Id: "poc-a", Info: poc.Info{Classification: poc.Classification{CweId: "CWE-89"}}},
		Evidence:   &evidence.Evidence{ID: "evd-edge", PocID: "poc-a", Target: "http://a.example/1", Confidence: "certain", Created: "2026-09-28 10:00:00", Steps: []evidence.Step{}},
	}
	insertEvidenceForResult(r, 1, "t-1")

	wantFinding := finding.IDFor("p-alpha", ref.Endpoint("http://a.example/1"), "cwe-89")
	var edge AssetEdge
	if err := db.Get(&edge,
		`SELECT parent_id, child_id, kind, created_at FROM asset_edge WHERE parent_id = ? AND child_id = ?`,
		wantFinding, "evd-edge"); err != nil {
		t.Fatalf("finding→evidence edge not written: %v", err)
	}
	if edge.Kind != "justified_by" {
		t.Fatalf("edge kind = %s, want justified_by", edge.Kind)
	}
}

// fnd_ 前缀的地址是合成节点：只写边、不写资产行，读取时按前缀判型。
func TestClassifyAssetAddressFindingNode(t *testing.T) {
	id := finding.IDFor("p-alpha", ref.Endpoint("http://a.example/1"), "cwe-89")
	if !isFindingID(id) {
		t.Fatalf("id %s should carry the finding prefix", id)
	}
	if got := ClassifyAssetAddress(id); got != "finding" {
		t.Fatalf("classify = %s, want finding", got)
	}
}

// 前缀拼接发生在 finding 包，这里只断言它确实带上了 fnd_ 前缀。
func isFindingID(id string) bool {
	return len(id) > len(findingIDPrefix) && id[:len(findingIDPrefix)] == findingIDPrefix
}
