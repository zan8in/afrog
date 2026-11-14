package sqlite

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// 终审决议流水：每次 `afrog poc approve|reject` 都追加一条不可变记录。
//
// 与 poc_draft 的分工：poc_draft 是「当前处于哪一步」的状态机（一份草稿只有一条），
// 本表是「历史上被怎么决议过」的流水——草稿可能被模型迭代后重新提交、再次终审，
// 只看状态机就丢掉了这段历史。Learner 消费的正是这条流水。
//
// 只追加：决议不修改、不删除，保证「自动入库率」这类指标可复算。
const pocReviewDDL = `CREATE TABLE IF NOT EXISTS "poc_review" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT,
	"draft_id" TEXT NOT NULL DEFAULT '',
	"decision" TEXT NOT NULL DEFAULT '',
	"severity" TEXT NOT NULL DEFAULT '',
	"capability" TEXT NOT NULL DEFAULT '',
	"requests" INTEGER NOT NULL DEFAULT 0,
	"target" TEXT NOT NULL DEFAULT '',
	"reason" TEXT NOT NULL DEFAULT '',
	"actor" TEXT NOT NULL DEFAULT '',
	"created" TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS "idx_poc_review_draft"
	ON "poc_review" ("draft_id", "created");
  CREATE INDEX IF NOT EXISTS "idx_poc_review_decision"
	ON "poc_review" ("decision", "created");`

const pocReviewTimeLayout = "2006-01-02 15:04:05"

// 终审决议取值。
const (
	PocDecisionApproved = "approved"
	PocDecisionRejected = "rejected"
)

// PocReview 是一条终审决议流水记录。
type PocReview struct {
	ID       int64  `db:"id" json:"id"`
	DraftID  string `db:"draft_id" json:"draft_id"`
	Decision string `db:"decision" json:"decision"`
	// Severity / Capability / Requests 从草稿快照下来，使指标不必回查可能已被迭代的草稿。
	Severity   string `db:"severity" json:"severity"`
	Capability string `db:"capability" json:"capability"`
	Requests   int    `db:"requests" json:"requests"`
	Target     string `db:"target" json:"target"`
	// Reason 是驳回原因或批准备注。
	Reason string `db:"reason" json:"reason"`
	// Actor 是决议发起者，当前只有人工 CLI（human:cli）。
	Actor   string `db:"actor" json:"actor"`
	Created string `db:"created" json:"created"`
}

func ensurePocReview() error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	if _, err := execBusyRetry(pocReviewDDL); err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	return nil
}

// InsertPocReview 追加一条终审决议。
func InsertPocReview(r PocReview) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	id := strings.TrimSpace(r.DraftID)
	if id == "" {
		return fmt.Errorf("poc review draft_id is required")
	}
	if r.Decision != PocDecisionApproved && r.Decision != PocDecisionRejected {
		return fmt.Errorf("invalid poc review decision %q", r.Decision)
	}
	if strings.TrimSpace(r.Created) == "" {
		r.Created = time.Now().Format(pocReviewTimeLayout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := dbx.ExecContext(ctx, `INSERT INTO "poc_review"
		("draft_id","decision","severity","capability","requests","target","reason","actor","created")
	 VALUES(?,?,?,?,?,?,?,?,?)`,
		id, r.Decision, r.Severity, r.Capability, r.Requests, r.Target, r.Reason, r.Actor, r.Created)
	return err
}

// SelectPocReviews 按 draft_id 取决议流水（为空表示全部），created 降序。
func SelectPocReviews(draftID string, limit int) ([]PocReview, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	query := `SELECT * FROM "poc_review"`
	args := []interface{}{}
	if id := strings.TrimSpace(draftID); id != "" {
		query += ` WHERE "draft_id" = ?`
		args = append(args, id)
	}
	query += ` ORDER BY "created" DESC, "id" DESC LIMIT ?`
	args = append(args, limit)

	out := make([]PocReview, 0, limit)
	if err := dbx.Select(&out, query, args...); err != nil {
		return nil, err
	}
	return out, nil
}

// CountPocReviews 返回终审决议总数。
func CountPocReviews() (int, error) {
	if dbx == nil {
		return 0, fmt.Errorf("sqlite not initialized")
	}
	var n int
	if err := dbx.Get(&n, `SELECT COUNT(*) FROM "poc_review"`); err != nil {
		return 0, err
	}
	return n, nil
}
