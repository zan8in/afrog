package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/zan8in/afrog/v3/pkg/evidence"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/gologger"
)

// 证据表：一条命中（result）对应一条可重放证据。
//
// 与 result 表的分工：result 回答「发现了什么」，evidence 回答「凭什么成立」。
// 主键用 (taskid, id)：id 由证据内容算出，同一条证据在不同任务里允许各存一份
// ——空分项目的口径要求「跨任务不去重」，但同一任务内的重复写入必须幂等
// （例如 Agent 重试、进程重放），因此用 INSERT OR IGNORE。
const evidenceDDL = `CREATE TABLE IF NOT EXISTS "evidence" (
	"id" TEXT NOT NULL DEFAULT '',
	"taskid" TEXT NOT NULL DEFAULT '',
	"result_id" INTEGER NOT NULL DEFAULT 0,
	"poc_id" TEXT NOT NULL DEFAULT '',
	"target" TEXT NOT NULL DEFAULT '',
	"digest" TEXT NOT NULL DEFAULT '',
	"confidence" TEXT NOT NULL DEFAULT '',
	"payload" TEXT NOT NULL DEFAULT '{}',
	"created" TEXT NOT NULL DEFAULT '',
	PRIMARY KEY ("taskid", "id")
  );
  CREATE INDEX IF NOT EXISTS "idx_evidence_result"
	ON "evidence" ("result_id");
  CREATE INDEX IF NOT EXISTS "idx_evidence_digest"
	ON "evidence" ("digest");`

// evidenceTimeLayout 与 result.created 一致，便于跨表按时间排序与比较。
const evidenceTimeLayout = "2006-01-02 15:04:05"

func ensureEvidence() error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	if _, err := execBusyRetry(evidenceDDL); err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	return nil
}

// insertEvidenceForResult 在结果落库后补写证据。失败只记录日志，不影响结果本身
// ——漏洞报告必须优先于证据的可用性。
func insertEvidenceForResult(r *result.Result, resultID int64, taskID string) {
	if r == nil || r.Evidence == nil || strings.TrimSpace(r.Evidence.ID) == "" {
		return
	}
	if err := InsertEvidence(r.Evidence, resultID, taskID); err != nil {
		gologger.Error().Msgf("insert evidence failed: %v", err)
	}
}

// InsertEvidence 写入一条证据；同一 (taskid, id) 重复写入时静默忽略。
func InsertEvidence(ev *evidence.Evidence, resultID int64, taskID string) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	if ev == nil || strings.TrimSpace(ev.ID) == "" {
		return nil
	}

	args, err := evidenceInsertArgs(ev, resultID, taskID)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = dbx.ExecContext(ctx, evidenceInsertSQL, args...)
	return err
}

const evidenceInsertSQL = `INSERT OR IGNORE INTO "evidence"
	("id", "taskid", "result_id", "poc_id", "target", "digest", "confidence", "payload", "created")
 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`

func evidenceInsertArgs(ev *evidence.Evidence, resultID int64, taskID string) ([]interface{}, error) {
	payload, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	created := time.Now()
	if t, perr := time.Parse(time.RFC3339, ev.Created); perr == nil {
		created = t
	}
	return []interface{}{
		ev.ID, taskID, resultID, ev.PocID, ev.Target, ev.Digest, ev.Confidence,
		string(payload), created.Format(evidenceTimeLayout),
	}, nil
}

// insertEvidenceTx 在调用方的事务里写证据。
//
// 集群回填是「先清后写」的整批事务，而 sqlite 连接池只有一条连接：事务未提交时
// 再用 dbx 写会直接自锁，因此必须复用同一个 tx。
func insertEvidenceTx(tx *sqlx.Tx, ev *evidence.Evidence, resultID int64, taskID string) error {
	if tx == nil || ev == nil || strings.TrimSpace(ev.ID) == "" {
		return nil
	}
	args, err := evidenceInsertArgs(ev, resultID, taskID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(evidenceInsertSQL, args...)
	return err
}

// SelectEvidenceByResultID 按命中 id 取证据。没有证据时返回 (nil, nil)。
func SelectEvidenceByResultID(resultID int64) (*evidence.Evidence, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	var payload string
	err := dbx.Get(&payload, `SELECT "payload" FROM "evidence" WHERE "result_id" = ? ORDER BY "created" DESC LIMIT 1`, resultID)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return decodeEvidence(payload)
}

// SelectEvidenceByID 按内容寻址 id 取证据（跨任务取最近的一份）。
func SelectEvidenceByID(id string) (*evidence.Evidence, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	var payload string
	err := dbx.Get(&payload, `SELECT "payload" FROM "evidence" WHERE "id" = ? ORDER BY "created" DESC LIMIT 1`, id)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return decodeEvidence(payload)
}

// SelectEvidenceByResultIDs 批量按 result id 读取证据，用于集群快照一次性带齐。
// 没有证据的 id 不会出现在返回的 map 里。
func SelectEvidenceByResultIDs(ids []int64) (map[int64]*evidence.Evidence, error) {
	out := make(map[int64]*evidence.Evidence)
	if dbx == nil {
		return out, fmt.Errorf("sqlite not initialized")
	}

	clean := make([]int64, 0, len(ids))
	seen := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		clean = append(clean, id)
	}
	if len(clean) == 0 {
		return out, nil
	}

	type row struct {
		ResultID int64  `db:"result_id"`
		Payload  string `db:"payload"`
	}
	for _, chunk := range chunkSlice(clean, idChunkSize/2) {
		holders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]interface{}, 0, len(chunk))
		for _, id := range chunk {
			args = append(args, id)
		}
		var rows []row
		if err := dbx.Select(&rows,
			`SELECT "result_id","payload" FROM "evidence"
			 WHERE "result_id" IN (`+holders+`) ORDER BY "created" ASC`, args...); err != nil {
			return out, err
		}
		for _, r := range rows {
			ev, err := decodeEvidence(r.Payload)
			if err != nil || ev == nil {
				continue
			}
			out[r.ResultID] = ev
		}
	}
	return out, nil
}

// SelectEvidenceIDsByResultIDs 批量返回 result id → 证据 id 的映射，
// 供台账列表直接带出 evidence_id，避免为每条命中再查一次库。
func SelectEvidenceIDsByResultIDs(ids []int64) (map[int64]string, error) {
	out := make(map[int64]string)
	if dbx == nil {
		return out, fmt.Errorf("sqlite not initialized")
	}

	clean := make([]int64, 0, len(ids))
	seen := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		clean = append(clean, id)
	}
	if len(clean) == 0 {
		return out, nil
	}

	type row struct {
		ResultID int64  `db:"result_id"`
		ID       string `db:"id"`
	}
	for _, chunk := range chunkSlice(clean, idChunkSize/2) {
		holders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]interface{}, 0, len(chunk))
		for _, id := range chunk {
			args = append(args, id)
		}
		var rows []row
		if err := dbx.Select(&rows,
			`SELECT "result_id","id" FROM "evidence"
			 WHERE "result_id" IN (`+holders+`) ORDER BY "created" ASC`, args...); err != nil {
			return out, err
		}
		for _, r := range rows {
			out[r.ResultID] = r.ID
		}
	}
	return out, nil
}

func decodeEvidence(payload string) (*evidence.Evidence, error) {
	if strings.TrimSpace(payload) == "" {
		return nil, nil
	}
	var ev evidence.Evidence
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

func isNoRows(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}
