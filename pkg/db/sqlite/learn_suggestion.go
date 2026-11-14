package sqlite

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// learn_suggestion 是 Learner 角色的「调优建议」存储：advisory，供人审，不自动改任何规则。
//
// 与 poc_draft 的分工：poc_draft 是「候选 PoC 要不要入库」的终审队列，本表是
// 「规则/阈值要不要调」的建议队列——两者都是「模型提议、人拍板」，只是对象不同。
// 建议里的 diff 只是一段文本：afrog 不解析、不应用它，应用动作由人走正常代码变更流程。
const learnSuggestionDDL = `CREATE TABLE IF NOT EXISTS "learn_suggestion" (
	"id" TEXT PRIMARY KEY,
	"kind" TEXT NOT NULL DEFAULT '',
	"summary" TEXT NOT NULL DEFAULT '',
	"diff" TEXT NOT NULL DEFAULT '',
	"status" TEXT NOT NULL DEFAULT 'pending',
	"note" TEXT NOT NULL DEFAULT '',
	"actor" TEXT NOT NULL DEFAULT '',
	"source" TEXT NOT NULL DEFAULT '',
	"created" TEXT NOT NULL DEFAULT '',
	"updated" TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS "idx_learn_suggestion_status"
	ON "learn_suggestion" ("status", "updated");`

const learnSuggestionTimeLayout = "2006-01-02 15:04:05"

// 调优建议的三种状态。
const (
	LearnSuggestionPending  = "pending"
	LearnSuggestionAccepted = "accepted"
	LearnSuggestionRejected = "rejected"
)

// 建议类别。
const (
	LearnKindRule      = "rule"
	LearnKindThreshold = "threshold"
	LearnKindOther     = "other"
)

// LearnSuggestion 是一条规则/阈值调优建议。
type LearnSuggestion struct {
	ID string `db:"id" json:"id"`
	// Kind 取 rule / threshold / other。
	Kind    string `db:"kind" json:"kind"`
	Summary string `db:"summary" json:"summary"`
	// Diff 是建议的变更内容（文本/diff），不做解析。
	Diff string `db:"diff" json:"diff"`
	// Status 取 pending / accepted / rejected。
	Status string `db:"status" json:"status"`
	Note   string `db:"note" json:"note"`
	Actor  string `db:"actor" json:"actor"`
	// Source 记录这条建议是从哪批终审结果里学出来的（可选，便于复盘）。
	Source  string `db:"source" json:"source"`
	Created string `db:"created" json:"created"`
	Updated string `db:"updated" json:"updated"`
}

func ensureLearnSuggestion() error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	if _, err := execBusyRetry(learnSuggestionDDL); err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	return nil
}

// UpsertLearnSuggestion 写入或更新一条建议（按 id）。
func UpsertLearnSuggestion(s LearnSuggestion) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	if strings.TrimSpace(s.ID) == "" {
		return fmt.Errorf("learn suggestion id is required")
	}
	if strings.TrimSpace(s.Status) == "" {
		s.Status = LearnSuggestionPending
	}
	now := time.Now().Format(learnSuggestionTimeLayout)
	if strings.TrimSpace(s.Created) == "" {
		s.Created = now
	}
	s.Updated = now

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := dbx.ExecContext(ctx, `INSERT INTO "learn_suggestion"
		("id","kind","summary","diff","status","note","actor","source","created","updated")
	 VALUES(?,?,?,?,?,?,?,?,?,?)
	 ON CONFLICT("id") DO UPDATE SET
		"kind"=excluded."kind",
		"summary"=excluded."summary",
		"diff"=excluded."diff",
		"status"=excluded."status",
		"note"=excluded."note",
		"actor"=excluded."actor",
		"source"=excluded."source",
		"updated"=excluded."updated"`,
		s.ID, s.Kind, s.Summary, s.Diff, s.Status, s.Note, s.Actor, s.Source, s.Created, s.Updated)
	return err
}

// SelectLearnSuggestion 按 id 取一条建议；不存在时返回 (nil, nil)。
func SelectLearnSuggestion(id string) (*LearnSuggestion, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	var s LearnSuggestion
	err := dbx.Get(&s, `SELECT * FROM "learn_suggestion" WHERE "id" = ?`, strings.TrimSpace(id))
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return &s, nil
}

// SelectLearnSuggestions 按状态列出建议，updated 降序；status 为空表示全部。
func SelectLearnSuggestions(status string, limit int) ([]LearnSuggestion, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	query := `SELECT * FROM "learn_suggestion"`
	args := []interface{}{}
	if s := strings.TrimSpace(status); s != "" {
		query += ` WHERE "status" = ?`
		args = append(args, s)
	}
	query += ` ORDER BY "updated" DESC, "id" ASC LIMIT ?`
	args = append(args, limit)

	out := make([]LearnSuggestion, 0, limit)
	if err := dbx.Select(&out, query, args...); err != nil {
		return nil, err
	}
	return out, nil
}

// SetLearnSuggestionStatus 推进一条建议的状态并记录备注；id 不存在时返回错误。
func SetLearnSuggestionStatus(id, status, note string) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := dbx.ExecContext(ctx,
		`UPDATE "learn_suggestion" SET "status" = ?, "note" = ?, "updated" = ? WHERE "id" = ?`,
		strings.TrimSpace(status), note, time.Now().Format(learnSuggestionTimeLayout), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("learn suggestion %q not found", strings.TrimSpace(id))
	}
	return nil
}
