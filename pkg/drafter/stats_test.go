package drafter

import (
	"testing"
)

func TestGetStatsEmpty(t *testing.T) {
	withHome(t)

	st, err := GetStats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if st.Total != 0 || st.Reviewed != 0 || st.Reviews != 0 {
		t.Fatalf("empty stats = %+v", st)
	}
	// 没有任何决议时，入库率是未定义：分子分母都为 0，值应为 0 且由 CLI 渲染成 n/a。
	if st.IngestRate != 0 {
		t.Fatalf("ingest rate on empty = %v, want 0", st.IngestRate)
	}
}

func TestGetStatsIngestRateExcludesPending(t *testing.T) {
	withHome(t)

	submit := func(id string) {
		t.Helper()
		if _, err := Submit(SubmitOptions{
			Path:       writeDraft(t, id),
			Target:     "http://a.test",
			EvidenceID: "evd_" + id,
		}); err != nil {
			t.Fatalf("submit %s: %v", id, err)
		}
	}

	submit("cand-1")
	submit("cand-2")
	submit("cand-3")

	if _, err := Approve("cand-1"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := Reject("cand-2", "no repro"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	// cand-3 保持 pending：它不应进入入库率的分母。

	st, err := GetStats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if st.Total != 3 || st.Pending != 1 || st.Approved != 1 || st.Rejected != 1 {
		t.Fatalf("counts = %+v", st)
	}
	if st.Reviewed != 2 {
		t.Fatalf("reviewed = %d, want 2", st.Reviewed)
	}
	if st.IngestRate != 0.5 {
		t.Fatalf("ingest rate = %v, want 0.5 (approved/(approved+rejected))", st.IngestRate)
	}
	// 两条决议各写一条流水（Approve + Reject）。
	if st.Reviews != 2 {
		t.Fatalf("reviews = %d, want 2", st.Reviews)
	}

	if len(st.BySeverity) != 1 || st.BySeverity[0].Name != "high" ||
		st.BySeverity[0].Total != 3 || st.BySeverity[0].IngestRate != 0.5 {
		t.Fatalf("by_severity = %+v", st.BySeverity)
	}
}
