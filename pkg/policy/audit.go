package policy

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Record 是一条策略判定审计记录。字段刻意保持扁平，便于直接落 JSONL。
type Record struct {
	TS         string `json:"ts"`
	Actor      string `json:"actor,omitempty"`
	Action     string `json:"action"`
	Target     string `json:"target,omitempty"`
	Allow      bool   `json:"allow"`
	Rule       string `json:"rule"`
	Reason     string `json:"reason,omitempty"`
	BudgetLeft int    `json:"budget_left"`
}

// Auditor 把判定记录追加写入审计流。
type Auditor struct {
	mu sync.Mutex
	w  io.Writer
}

// NewAuditor 创建审计器；w 为 nil 时所有写入都是空操作。
func NewAuditor(w io.Writer) *Auditor {
	return &Auditor{w: w}
}

// Record 写入一条判定记录。
func (a *Auditor) Record(r Record) error {
	if a == nil || a.w == nil {
		return nil
	}
	if r.TS == "" {
		r.TS = time.Now().UTC().Format(time.RFC3339)
	}
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()
	_, err = a.w.Write(line)
	return err
}
