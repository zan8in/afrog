package sqlite

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// judgement 是 Judge 角色的「研判意见」存储：advisory，不改 finding 台账。
//
// 与漏洞台账的分工：台账（vuln_ledger.status）是人/系统对命中认定的**结论**，
// 本表只是模型对同一份 Evidence 的**意见**——可能有出入，也可能被后续证据推翻。
// 二者刻意分表：模型永远不写台账，台账状态也不被模型覆盖。
//
// 一个研判对象可以有多条意见（不同 actor、不同时间），按 subject_id 归组读取。
const judgementDDL = `CREATE TABLE IF NOT EXISTS "judgement" (
	"id" TEXT PRIMARY KEY,
	"subject_id" TEXT NOT NULL DEFAULT '',
	"evidence_id" TEXT NOT NULL DEFAULT '',
	"conclusion" TEXT NOT NULL DEFAULT '',
	"false_positive" INTEGER NOT NULL DEFAULT 0,
	"reasoning" TEXT NOT NULL DEFAULT '',
	"review_steps" TEXT NOT NULL DEFAULT '',
	"actor" TEXT NOT NULL DEFAULT '',
	"created" TEXT NOT NULL DEFAULT '',
	"updated" TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS "idx_judgement_subject"
	ON "judgement" ("subject_id", "updated");`

const judgementTimeLayout = "2006-01-02 15:04:05"

// 研判结论取值。只描述倾向，不构成判定。
const (
	JudgementLikelyTrue  = "likely_true"
	JudgementLikelyFalse = "likely_false"
	JudgementUncertain   = "uncertain"
)

// Judgement 是模型对一条证据的研判意见。
type Judgement struct {
	ID string `db:"id" json:"id"`
	// SubjectID 是被研判的对象（observe.evidence 的 id，或它解析出的 evd_ 证据 id）。
	SubjectID  string `db:"subject_id" json:"subject_id"`
	EvidenceID string `db:"evidence_id" json:"evidence_id"`
	// Conclusion 取 likely_true / likely_false / uncertain。
	Conclusion string `db:"conclusion" json:"conclusion"`
	// FalsePositive 是结论的布尔投影，便于筛选与统计。
	FalsePositive bool `db:"false_positive" json:"false_positive"`
	// Reasoning 是一段两句以内的依据说明。
	Reasoning string `db:"reasoning" json:"reasoning"`
	// ReviewSteps 是给人工的复核步骤（JSON 字符串数组）。
	ReviewSteps string `db:"review_steps" json:"review_steps"`
	// Actor 是给出意见的主体，例如 agent:artex。
	Actor   string `db:"actor" json:"actor"`
	Created string `db:"created" json:"created"`
	Updated string `db:"updated" json:"updated"`
}

func ensureJudgement() error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	if _, err := execBusyRetry(judgementDDL); err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	return nil
}

// UpsertJudgement 写入或更新一条研判意见（按 id）。
func UpsertJudgement(j Judgement) error {
	if dbx == nil {
		return fmt.Errorf("sqlite not initialized")
	}
	if strings.TrimSpace(j.ID) == "" {
		return fmt.Errorf("judgement id is required")
	}
	switch j.Conclusion {
	case JudgementLikelyTrue, JudgementLikelyFalse, JudgementUncertain:
	default:
		return fmt.Errorf("invalid judgement conclusion %q", j.Conclusion)
	}
	// false_positive 是 conclusion 的投影，由本层统一派生，避免调用方漏设导致两者打架。
	j.FalsePositive = j.Conclusion == JudgementLikelyFalse
	now := time.Now().Format(judgementTimeLayout)
	if strings.TrimSpace(j.Created) == "" {
		j.Created = now
	}
	j.Updated = now

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := dbx.ExecContext(ctx, `INSERT INTO "judgement"
		("id","subject_id","evidence_id","conclusion","false_positive","reasoning","review_steps","actor","created","updated")
	 VALUES(?,?,?,?,?,?,?,?,?,?)
	 ON CONFLICT("id") DO UPDATE SET
		"subject_id"=excluded."subject_id",
		"evidence_id"=excluded."evidence_id",
		"conclusion"=excluded."conclusion",
		"false_positive"=excluded."false_positive",
		"reasoning"=excluded."reasoning",
		"review_steps"=excluded."review_steps",
		"actor"=excluded."actor",
		"updated"=excluded."updated"`,
		j.ID, j.SubjectID, j.EvidenceID, j.Conclusion, boolToInt(j.FalsePositive),
		j.Reasoning, j.ReviewSteps, j.Actor, j.Created, j.Updated)
	return err
}

// SelectJudgementByID 按 id 取一条研判意见；不存在时返回错误。
func SelectJudgementByID(id string) (*Judgement, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	var j Judgement
	if err := dbx.Get(&j, `SELECT * FROM "judgement" WHERE "id" = ?`, strings.TrimSpace(id)); err != nil {
		return nil, err
	}
	return &j, nil
}

// SelectJudgementsBySubject 取某个研判对象下的全部意见，updated 降序。
func SelectJudgementsBySubject(subjectIDs ...string) ([]Judgement, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	ids := make([]string, 0, len(subjectIDs))
	seen := make(map[string]struct{}, len(subjectIDs))
	for _, raw := range subjectIDs {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, nil
	}

	args := make([]interface{}, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	query := `SELECT * FROM "judgement" WHERE "subject_id" IN (` + placeholders(len(ids)) +
		`) ORDER BY "updated" DESC, "id" ASC`

	out := make([]Judgement, 0, len(ids))
	if err := dbx.Select(&out, query, args...); err != nil {
		return nil, err
	}
	return out, nil
}
