package sqlite

import (
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/observation"
)

func sampleObservation(t *testing.T, project, kind, subject string) *observation.Observation {
	t.Helper()
	var payload any
	switch kind {
	case observation.KindPortOpen:
		payload = observation.PortOpen{Port: 80, State: "open", Service: "http"}
	case observation.KindTech:
		payload = observation.Tech{URL: subject, Status: 200, Title: "t"}
	default:
		payload = observation.HTTPTransaction{Method: "GET", URL: subject, Status: 200}
	}
	obs, err := observation.New(project, observation.SourceHTTP, kind, subject, payload)
	if err != nil {
		t.Fatalf("new observation: %v", err)
	}
	return obs
}

// 去重键是 (project_id, id)：同一事实重扫不新增行，跨项目各存一份。
func TestInsertObservationDedupes(t *testing.T) {
	useFixtureDB(t)
	obs := sampleObservation(t, "p1", observation.KindTech, "http://a.example")

	for i := 0; i < 2; i++ {
		if err := InsertObservation(obs); err != nil {
			t.Fatalf("insert #%d: %v", i, err)
		}
	}
	var count int
	if err := dbx.Get(&count, `SELECT COUNT(*) FROM "observation" WHERE "project_id" = 'p1'`); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("dedupe failed: %d rows", count)
	}

	other := sampleObservation(t, "p2", observation.KindTech, "http://a.example")
	if other.ID == obs.ID {
		t.Fatalf("id must be project-scoped: %s", other.ID)
	}
	if err := InsertObservation(other); err != nil {
		t.Fatalf("insert other project: %v", err)
	}
	if err := dbx.Get(&count, `SELECT COUNT(*) FROM "observation"`); err != nil {
		t.Fatalf("count all: %v", err)
	}
	if count != 2 {
		t.Fatalf("cross-project rows = %d, want 2", count)
	}
}

func TestSelectObservationsCursorAndFilters(t *testing.T) {
	useFixtureDB(t)

	items := []*observation.Observation{
		sampleObservation(t, "", observation.KindPortOpen, "a.example:80"),
		sampleObservation(t, "", observation.KindTech, "http://a.example"),
		sampleObservation(t, "", observation.KindHTTPTransaction, "http://a.example/login"),
	}
	for _, it := range items {
		if err := InsertObservation(it); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	first, err := SelectObservations(ObservationFilter{Limit: 2})
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(first.Items) != 2 || !first.HasMore {
		t.Fatalf("page 1 = %d items, has_more=%v", len(first.Items), first.HasMore)
	}
	if first.Items[0].Seq >= first.Items[1].Seq {
		t.Fatalf("items are not ordered by seq: %d, %d", first.Items[0].Seq, first.Items[1].Seq)
	}
	if first.NextSeq != first.Items[1].Seq {
		t.Fatalf("next_seq = %d, want %d", first.NextSeq, first.Items[1].Seq)
	}

	second, err := SelectObservations(ObservationFilter{SinceSeq: first.NextSeq, Limit: 2})
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(second.Items) != 1 || second.HasMore {
		t.Fatalf("page 2 = %d items, has_more=%v", len(second.Items), second.HasMore)
	}
	if second.Items[0].ID != items[2].ID {
		t.Fatalf("cursor skipped/duplicated rows: %+v", second.Items[0])
	}

	byKind, err := SelectObservations(ObservationFilter{Kinds: []string{observation.KindTech}})
	if err != nil {
		t.Fatalf("filter kind: %v", err)
	}
	if len(byKind.Items) != 1 || byKind.Items[0].Kind != observation.KindTech {
		t.Fatalf("kind filter = %+v", byKind.Items)
	}
	if string(byKind.Items[0].Payload) == "" {
		t.Fatal("payload must round-trip")
	}

	bySubject, err := SelectObservations(ObservationFilter{Subject: "http://a.example/login"})
	if err != nil {
		t.Fatalf("filter subject: %v", err)
	}
	if len(bySubject.Items) != 1 || bySubject.Items[0].Kind != observation.KindHTTPTransaction {
		t.Fatalf("subject filter = %+v", bySubject.Items)
	}
}

// subject 子树只沿地址层级展开：host 命中端口，端点命中路径与参数，
// 但不会把 a.example 匹配到 a.example.evil.com。
func TestSelectObservationsSubjectSubtree(t *testing.T) {
	useFixtureDB(t)

	subjects := []string{
		"a.example:80",
		"a.example:8080",
		"a.example.evil.com:80",
		"http://a.example",
		"http://a.example/login",
		"http://a.example.evil.com/x",
	}
	for _, s := range subjects {
		if err := InsertObservation(sampleObservation(t, "", observation.KindTech, s)); err != nil {
			t.Fatalf("insert %s: %v", s, err)
		}
	}

	host, err := SelectObservations(ObservationFilter{Subject: "a.example", SubjectUnder: true})
	if err != nil {
		t.Fatalf("host subtree: %v", err)
	}
	if got := len(host.Items); got != 2 {
		t.Fatalf("host 子树命中 %d 条, want 2: %+v", got, subjectIDs(host.Items))
	}
	for _, it := range host.Items {
		if it.Subject == "a.example.evil.com:80" {
			t.Fatalf("子树误匹配了同前缀的其他域名: %+v", it)
		}
	}

	url, err := SelectObservations(ObservationFilter{Subject: "http://a.example/", SubjectUnder: true})
	if err != nil {
		t.Fatalf("url subtree: %v", err)
	}
	if got := len(url.Items); got != 2 {
		t.Fatalf("端点子树命中 %d 条, want 2: %+v", got, subjectIDs(url.Items))
	}

	exact, err := SelectObservations(ObservationFilter{Subject: "a.example"})
	if err != nil {
		t.Fatalf("exact subject: %v", err)
	}
	if len(exact.Items) != 0 {
		t.Fatalf("精确匹配不该命中子节点: %+v", subjectIDs(exact.Items))
	}
}

func subjectIDs(items []observation.Observation) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Subject)
	}
	return out
}

// 保留上限可配置：超限分批删最旧，0 表示不限制。
func TestPruneObservationsHonorsConfiguredLimit(t *testing.T) {
	useFixtureDB(t)
	oldLimit := atomic.LoadInt64(&observationMaxRows)
	t.Cleanup(func() { atomic.StoreInt64(&observationMaxRows, oldLimit) })

	for i := 0; i < 30; i++ {
		subject := "prune-" + strconv.Itoa(i) + ".example:80"
		if err := InsertObservation(sampleObservation(t, "", observation.KindPortOpen, subject)); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	SetObservationMaxRows(20)
	for i := 0; i < 50; i++ {
		var count int64
		if err := dbx.Get(&count, `SELECT COUNT(*) FROM "observation"`); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count <= 20 {
			break
		}
		pruneObservations()
	}
	var count int64
	if err := dbx.Get(&count, `SELECT COUNT(*) FROM "observation"`); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count > 20 {
		t.Fatalf("裁剪后仍有 %d 行, want <= 20", count)
	}

	SetObservationMaxRows(0)
	pruneObservations()
	var after int64
	if err := dbx.Get(&after, `SELECT COUNT(*) FROM "observation"`); err != nil {
		t.Fatalf("count: %v", err)
	}
	if after != count {
		t.Fatalf("0 应表示不限制: %d -> %d", count, after)
	}
}

// 异步写入路径：RecordObservation 入队后 FlushObservations 必须等到落库完成。
func TestRecordObservationFlushes(t *testing.T) {
	useFixtureDB(t)
	observeDropped = 0
	t.Cleanup(stopObservationWriter)

	obs := sampleObservation(t, "", observation.KindPortOpen, "a.example:443")
	RecordObservation(obs)
	FlushObservations()

	page, err := SelectObservations(ObservationFilter{})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != obs.ID {
		t.Fatalf("observation not flushed: %+v", page.Items)
	}
	if DroppedObservations() != 0 {
		t.Fatalf("unexpected drops: %d", DroppedObservations())
	}
}
