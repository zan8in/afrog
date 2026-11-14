package sqlite

import "testing"

// withPipelineFixture 在临时库上建表并接管 dbx，覆盖 P3 的三张 advisory/流水表。
func withPipelineFixture(t *testing.T) {
	t.Helper()
	db := newExportFixture(t)
	prev := dbx
	dbx = db
	t.Cleanup(func() { dbx = prev })
}

func TestPocReviewAppendOnlyAndValidate(t *testing.T) {
	withPipelineFixture(t)

	if err := InsertPocReview(PocReview{DraftID: "d-1", Decision: PocDecisionApproved, Severity: "high", Requests: 3}); err != nil {
		t.Fatalf("insert approved: %v", err)
	}
	if err := InsertPocReview(PocReview{DraftID: "d-1", Decision: PocDecisionRejected, Reason: "no repro", Created: "2026-11-01 10:00:00"}); err != nil {
		t.Fatalf("insert rejected: %v", err)
	}
	// 同一草稿可以有多条决议流水（被驳回 → 迭代 → 再批准），这是本表存在的前提。
	if err := InsertPocReview(PocReview{DraftID: "d-2", Decision: PocDecisionApproved}); err != nil {
		t.Fatalf("insert d-2: %v", err)
	}

	if n, err := CountPocReviews(); err != nil || n != 3 {
		t.Fatalf("count = %d, err = %v, want 3", n, err)
	}

	rows, err := SelectPocReviews("d-1", 0)
	if err != nil {
		t.Fatalf("select by draft: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("select by draft got %d rows, want 2", len(rows))
	}

	all, err := SelectPocReviews("", 0)
	if err != nil || len(all) != 3 {
		t.Fatalf("select all got %d rows, err = %v, want 3", len(all), err)
	}

	// 非法输入必须被拒绝：缺 draft_id、非法 decision。
	if err := InsertPocReview(PocReview{Decision: PocDecisionApproved}); err == nil {
		t.Fatal("empty draft_id must be rejected")
	}
	if err := InsertPocReview(PocReview{DraftID: "d-3", Decision: "maybe"}); err == nil {
		t.Fatal("invalid decision must be rejected")
	}
}

func TestJudgementUpsertAndReadBySubject(t *testing.T) {
	withPipelineFixture(t)

	first := Judgement{
		ID:         "jdg_1",
		SubjectID:  "42",
		EvidenceID: "evd_abc",
		Conclusion: JudgementLikelyFalse,
		Reasoning:  "response is a generic 404 page",
		Actor:      "agent:artex",
	}
	if err := UpsertJudgement(first); err != nil {
		t.Fatalf("upsert first: %v", err)
	}

	got, err := SelectJudgementByID("jdg_1")
	if err != nil {
		t.Fatalf("select by id: %v", err)
	}
	if got == nil || !got.FalsePositive || got.Conclusion != JudgementLikelyFalse {
		t.Fatalf("unexpected judgement: %+v", got)
	}

	// 同一 id 再来一次是更新而非新增（false_positive 跟随 conclusion 重算）。
	first.Conclusion = JudgementLikelyTrue
	if err := UpsertJudgement(first); err != nil {
		t.Fatalf("upsert update: %v", err)
	}
	got, err = SelectJudgementByID("jdg_1")
	if err != nil {
		t.Fatalf("select after update: %v", err)
	}
	if got.FalsePositive {
		t.Fatalf("false_positive must follow conclusion, got %+v", got)
	}

	// 另一个 actor 对同一对象给出不同意见：两条并存，供人对照。
	second := Judgement{ID: "jdg_2", SubjectID: "42", EvidenceID: "evd_abc", Conclusion: JudgementUncertain, Actor: "agent:other"}
	if err := UpsertJudgement(second); err != nil {
		t.Fatalf("upsert second: %v", err)
	}
	list, err := SelectJudgementsBySubject("42", "evd_abc")
	if err != nil {
		t.Fatalf("select by subject: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("subject query must dedupe ids and return 2, got %d", len(list))
	}

	if err := UpsertJudgement(Judgement{ID: "jdg_bad", SubjectID: "42", Conclusion: "definitely"}); err == nil {
		t.Fatal("invalid conclusion must be rejected")
	}
	if err := UpsertJudgement(Judgement{Conclusion: JudgementUncertain}); err == nil {
		t.Fatal("empty id must be rejected")
	}
}

func TestLearnSuggestionLifecycle(t *testing.T) {
	withPipelineFixture(t)

	rec := LearnSuggestion{
		ID:      "lsg_1",
		Kind:    LearnKindThreshold,
		Summary: "放宽 low 级 PoC 的入库门槛",
		Diff:    "--- a/policy.yaml\n+++ b/policy.yaml\n",
		Source:  "近 20 次终审",
	}
	if err := UpsertLearnSuggestion(rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := SelectLearnSuggestion("lsg_1")
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if got == nil || got.Status != LearnSuggestionPending || got.Source != "近 20 次终审" {
		t.Fatalf("unexpected suggestion: %+v", got)
	}

	pending, err := SelectLearnSuggestions(LearnSuggestionPending, 0)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending list got %d, err = %v, want 1", len(pending), err)
	}

	// accept 只记录决策：diff 原文保持不变。
	if err := SetLearnSuggestionStatus("lsg_1", LearnSuggestionAccepted, "人工确认"); err != nil {
		t.Fatalf("accept: %v", err)
	}
	got, err = SelectLearnSuggestion("lsg_1")
	if err != nil {
		t.Fatalf("select after accept: %v", err)
	}
	if got.Status != LearnSuggestionAccepted || got.Note != "人工确认" {
		t.Fatalf("status not advanced: %+v", got)
	}
	if got.Diff != rec.Diff {
		t.Fatalf("diff must be untouched by status change")
	}

	if err := SetLearnSuggestionStatus("missing", LearnSuggestionRejected, ""); err == nil {
		t.Fatal("unknown id must be rejected")
	}
	if v, err := SelectLearnSuggestion("missing"); err != nil || v != nil {
		t.Fatalf("missing suggestion should be (nil, nil), got %+v, %v", v, err)
	}
}
