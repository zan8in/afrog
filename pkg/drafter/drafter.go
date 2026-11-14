// Package drafter 是 PoC Drafter 的「最后一公里」：候选草稿通过沙箱实跑拿到证据后，
// 进入待审队列，由人工终审决定是否入库（~/.config/afrog/pocs-my）。
//
// 边界：本包不做判定、不解析「是不是漏洞」，也不发任何请求。它只维护一条状态机
// （pending → approved / rejected）与文件搬运；实跑与证据由 verify.* 层产生，
// 判定权永远在确定性引擎 + Evidence，不在模型。
package drafter

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"gopkg.in/yaml.v2"
)

// draftIDRe 与 mcp 的草稿 id 规则一致：id 会成为文件名，必须挡住路径穿越。
var draftIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidID 报告一个 PoC id 是否可安全用作文件名。
func ValidID(id string) bool { return draftIDRe.MatchString(strings.TrimSpace(id)) }

// SubmitOptions 是提交一份候选 PoC 所需的全部输入。
type SubmitOptions struct {
	// ID 是 PoC id；缺省时从 YAML 里取。
	ID string
	// Path 是草稿 YAML 的绝对路径（validator 落盘的位置）。
	Path string
	// Target 是沙箱实跑的目标。
	Target string
	// EvidenceID / EvidenceDigest 是这次实跑拿到的证据标识，必须非空。
	EvidenceID     string
	EvidenceDigest string
	// Requests 是静态估算的请求量，仅作终审参考，可为 0。
	Requests int
}

// Submit 把一份已实跑出证据的草稿放进待审队列。
//
// 它会重新读一遍 Path 并解析：草稿可能在落盘后被改坏，队列里不该出现解析不了的行。
// 同一 id 重复提交会刷新内容并回到 pending —— YAML 变了，旧的实跑证据就不再代表它。
func Submit(opts SubmitOptions) (*sqlite.PocDraft, error) {
	path := strings.TrimSpace(opts.Path)
	if path == "" {
		return nil, fmt.Errorf("poc_path is required")
	}
	if strings.TrimSpace(opts.EvidenceID) == "" {
		return nil, fmt.Errorf("evidence_id is required: a candidate must pass a sandbox run before review")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("draft not readable: %w", err)
	}
	var draft poc.Poc
	if err := yaml.Unmarshal(data, &draft); err != nil {
		return nil, fmt.Errorf("draft is not valid yaml: %w", err)
	}

	id := strings.TrimSpace(opts.ID)
	if id == "" {
		id = strings.TrimSpace(draft.Id)
	}
	if !ValidID(id) {
		return nil, fmt.Errorf("invalid poc id %q", id)
	}
	if strings.TrimSpace(draft.Id) != "" && strings.TrimSpace(draft.Id) != id {
		return nil, fmt.Errorf("poc id %q does not match yaml id %q", id, draft.Id)
	}
	if len(draft.Rules) == 0 {
		return nil, fmt.Errorf("draft %q has no rules", id)
	}
	if strings.TrimSpace(opts.Target) == "" {
		return nil, fmt.Errorf("target is required: a candidate must be verified against a real target")
	}

	prev, err := sqlite.SelectPocDraft(id)
	if err != nil {
		return nil, err
	}
	created := ""
	if prev != nil {
		created = prev.Created
	}

	rec := sqlite.PocDraft{
		ID:             id,
		Status:         sqlite.PocDraftPending,
		Name:           strings.TrimSpace(draft.Info.Name),
		Severity:       strings.ToLower(strings.TrimSpace(draft.Info.Severity)),
		Capability:     draft.Capability().String(),
		Path:           path,
		Target:         strings.TrimSpace(opts.Target),
		EvidenceID:     strings.TrimSpace(opts.EvidenceID),
		EvidenceDigest: strings.TrimSpace(opts.EvidenceDigest),
		Requests:       opts.Requests,
		Created:        created,
	}
	if err := sqlite.UpsertPocDraft(rec); err != nil {
		return nil, err
	}
	return sqlite.SelectPocDraft(id)
}

// List 按状态列出候选；status 为空表示全部。
func List(status string) ([]sqlite.PocDraft, error) {
	return sqlite.SelectPocDrafts(status)
}

// Show 取单条候选详情。
func Show(id string) (*sqlite.PocDraft, error) {
	return sqlite.SelectPocDraft(id)
}

// ApproveResult 是批准入库的结果。
type ApproveResult struct {
	ID string `json:"id"`
	// Path 是最终写入 pocs-my 的路径。
	Path string `json:"path"`
}

// Approve 把一份待审候选写入用户 PoC 目录并标记为已批准。
//
// 入库前重新解析一次 YAML，并挡掉与既有（非 my）PoC 的 id 冲突：跨来源是按优先级
// 去重的（curated > my），若允许 id 撞车，写进去的 my 版本会被静默忽略。
func Approve(id string) (*ApproveResult, error) {
	rec, err := sqlite.SelectPocDraft(id)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, fmt.Errorf("poc draft %q not found", strings.TrimSpace(id))
	}
	if !ValidID(rec.ID) {
		return nil, fmt.Errorf("invalid poc id %q", rec.ID)
	}

	data, err := os.ReadFile(rec.Path)
	if err != nil {
		return nil, fmt.Errorf("draft not readable: %w", err)
	}
	var draft poc.Poc
	if err := yaml.Unmarshal(data, &draft); err != nil {
		return nil, fmt.Errorf("draft is not valid yaml: %w", err)
	}
	if len(draft.Rules) == 0 {
		return nil, fmt.Errorf("draft %q has no rules", rec.ID)
	}
	if conflict, ok := conflictsWithExisting(rec.ID); ok {
		return nil, fmt.Errorf("poc id %q is already provided by %s (%s); rename it before approving", rec.ID, conflict.Source, conflict.Path)
	}

	dir, err := myPocDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create my poc dir: %w", err)
	}
	dest := filepath.Join(dir, rec.ID+".yaml")
	if err := utils.WriteFileAtomic(dest, data, 0o644); err != nil {
		return nil, fmt.Errorf("write poc: %w", err)
	}
	if err := sqlite.SetPocDraftStatus(rec.ID, sqlite.PocDraftApproved, ""); err != nil {
		return nil, err
	}
	// 回流自动化：决议一落定就写流水，指标与 Learner 不必再让用户手动导出。
	recordReview(rec, sqlite.PocDecisionApproved, "")
	return &ApproveResult{ID: rec.ID, Path: dest}, nil
}

// Reject 驳回一条候选，保留草稿与原因以供复盘。
func Reject(id, note string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("id is required")
	}
	rec, err := sqlite.SelectPocDraft(id)
	if err != nil {
		return err
	}
	if rec == nil {
		return fmt.Errorf("poc draft %q not found", id)
	}
	note = strings.TrimSpace(note)
	if err := sqlite.SetPocDraftStatus(id, sqlite.PocDraftRejected, note); err != nil {
		return err
	}
	recordReview(rec, sqlite.PocDecisionRejected, note)
	return nil
}

// recordReview 把一次终审决议写进只追加的流水表；失败不影响已完成的决议本身
// （状态机已推进，流水缺失只会让指标少一条，不该把入库动作整个回滚掉）。
func recordReview(rec *sqlite.PocDraft, decision, reason string) {
	if rec == nil {
		return
	}
	_ = sqlite.InsertPocReview(sqlite.PocReview{
		DraftID:    rec.ID,
		Decision:   decision,
		Severity:   rec.Severity,
		Capability: rec.Capability,
		Requests:   rec.Requests,
		Target:     rec.Target,
		Reason:     reason,
		Actor:      reviewActor,
	})
}

// reviewActor 是终审决议的发起者。当前只有人工 CLI 一条路径；模型没有写 PoC 目录的入口。
const reviewActor = "human:cli"

// conflictsWithExisting 查找同 id 的非 my 来源 PoC；命中即返回。
func conflictsWithExisting(id string) (pocsrepo.Item, bool) {
	items, err := pocsrepo.ListMeta(pocsrepo.ListOptions{Source: "all"})
	if err != nil {
		return pocsrepo.Item{}, false
	}
	for _, it := range items {
		if it.ID == id && it.Source != pocsrepo.SourceMy {
			return it, true
		}
	}
	return pocsrepo.Item{}, false
}

// myPocDir 返回用户 PoC 目录，与命令行、Web 控制台共用同一份。
func myPocDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "afrog", "pocs-my"), nil
}
