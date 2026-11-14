package sqlite

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// 候选 PoC 待审队列：模型产出的草稿在「通过沙箱实跑、拿到证据」后进入此表，
// 由人工终审决定是否入库（~/.config/afrog/pocs-my）。
//
// 与 drafts 目录的分工：目录里是 YAML 原文（谁都能看），本表是「这份草稿处于
// 流水线哪一步」的状态机——pending / approved / rejected。判定权不在模型手里，
// 因此状态只由 poc.submit 与 CLI `afrog poc approve|reject` 推进。

const pocDraftDDL = `CREATE TABLE IF NOT EXISTS "poc_draft" (
	"id" TEXT PRIMARY KEY,
	"status" TEXT NOT NULL DEFAULT 'pending',
	"name" TEXT NOT NULL DEFAULT '',
	"severity" TEXT NOT NULL DEFAULT '',
	"capability" TEXT NOT NULL DEFAULT '',
	"path" TEXT NOT NULL DEFAULT '',
	"target" TEXT NOT NULL DEFAULT '',
	"evidence_id" TEXT NOT NULL DEFAULT '',
	"evidence_digest" TEXT NOT NULL DEFAULT '',
	"requests" INTEGER NOT NULL DEFAULT 0,
	"note" TEXT NOT NULL DEFAULT '',
	"created" TEXT NOT NULL DEFAULT '',
	"updated" TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS "idx_poc_draft_status"
	ON "poc_draft" ("status", "updated");`

const pocDraftTimeLayout = "2006-01-02 15:04:05"

// 候选 PoC 的三种状态。
const (
	PocDraftPending  = "pending"
	PocDraftApproved = "approved"
	PocDraftRejected = "rejected"
)

// PocDraft 是待审队列里的一条候选 PoC。
type PocDraft struct {
	ID string `db:"id" json:"id"`
	// Status 取 pending / approved / rejected。
	Status string `db:"status" json:"status"`
	Name   string `db:"name" json:"name"`
	// Severity / Capability / Requests 来自 validator 的静态结论，供终审快速判断风险。
	Severity   string `db:"severity" json:"severity"`
	Capability string `db:"capability" json:"capability"`
	Requests   int    `db:"requests" json:"requests"`
	// Path 是草稿 YAML 的绝对路径；approve 时从它复制进 pocs-my。
	Path string `db:"path" json:"path"`
	// Target / EvidenceID / EvidenceDigest 记录「沙箱实跑」在哪台目标上拿到了哪条证据。
	Target         string `db:"target" json:"target"`
	EvidenceID     string `db:"evidence_id" json:"evidence_id"`
	EvidenceDigest string `db:"evidence_digest" json:"evidence_digest"`
	// Note 是驳回原因或终审备注。
	Note    string `db:"note" json:"note"`
	Created string `db:"created" json:"created"`
	Updated string `db:"updated" json:"updated"`
}

func ensurePocDraft() error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	if _, err := execBusyRetry(pocDraftDDL); err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	return nil
}

// UpsertPocDraft 写入或更新一条候选记录。重复提交同一 id 时刷新内容并回到 pending
// ——草稿可能被模型迭代过，旧的实跑证据不再代表当前这版 YAML。
func UpsertPocDraft(d PocDraft) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	id := strings.TrimSpace(d.ID)
	if id == "" {
		return fmt.Errorf("poc draft id is required")
	}
	if strings.TrimSpace(d.Status) == "" {
		d.Status = PocDraftPending
	}
	now := time.Now().Format(pocDraftTimeLayout)
	if strings.TrimSpace(d.Created) == "" {
		d.Created = now
	}
	d.Updated = now

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := dbx.ExecContext(ctx, `INSERT INTO "poc_draft"
		("id","status","name","severity","capability","path","target","evidence_id","evidence_digest","requests","note","created","updated")
	 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
	 ON CONFLICT("id") DO UPDATE SET
		"status"=excluded."status",
		"name"=excluded."name",
		"severity"=excluded."severity",
		"capability"=excluded."capability",
		"path"=excluded."path",
		"target"=excluded."target",
		"evidence_id"=excluded."evidence_id",
		"evidence_digest"=excluded."evidence_digest",
		"requests"=excluded."requests",
		"note"=excluded."note",
		"updated"=excluded."updated"`,
		id, d.Status, d.Name, d.Severity, d.Capability, d.Path, d.Target,
		d.EvidenceID, d.EvidenceDigest, d.Requests, d.Note, d.Created, d.Updated)
	return err
}

// SelectPocDraft 按 id 取一条候选记录；不存在时返回 (nil, nil)。
func SelectPocDraft(id string) (*PocDraft, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	var d PocDraft
	err := dbx.Get(&d, `SELECT * FROM "poc_draft" WHERE "id" = ?`, strings.TrimSpace(id))
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return &d, nil
}

// SelectPocDrafts 按状态列出候选记录，updated 降序；status 为空表示全部。
func SelectPocDrafts(status string) ([]PocDraft, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	query := `SELECT * FROM "poc_draft"`
	args := []interface{}{}
	if s := strings.TrimSpace(status); s != "" {
		query += ` WHERE "status" = ?`
		args = append(args, s)
	}
	query += ` ORDER BY "updated" DESC, "id" ASC`

	out := make([]PocDraft, 0, 16)
	if err := dbx.Select(&out, query, args...); err != nil {
		return nil, err
	}
	return out, nil
}

// SetPocDraftStatus 推进一条候选的状态并记录备注。id 不存在时返回错误，
// 避免 CLI 静默「批准了不存在的草稿」。
func SetPocDraftStatus(id, status, note string) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := dbx.ExecContext(ctx,
		`UPDATE "poc_draft" SET "status" = ?, "note" = ?, "updated" = ? WHERE "id" = ?`,
		strings.TrimSpace(status), note, time.Now().Format(pocDraftTimeLayout), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("poc draft %q not found", strings.TrimSpace(id))
	}
	return nil
}
