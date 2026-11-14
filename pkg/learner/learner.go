// Package learner 是决策面 Learner 角色的 afrog 侧契约：喂终审结果、存调优建议。
//
// 边界（与 §7 红线一致）：afrog 不做学习、不改自己的规则/阈值。本包只做两件事——
//   - Brief：把人工终审的结果（含驳回原因）与流水线指标打包成「学习素材」；
//   - Record：把模型给出的调优建议（一段 diff 文本）作为 advisory 存下来，供人审。
//
// 应用建议永远由人走正常代码变更流程完成；afrog 不解析、不自动改任何规则。
package learner

import (
	"fmt"
	"strings"

	"github.com/rs/xid"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/drafter"
)

// suggestionIDPrefix 让调优建议 id 可辨认。
const suggestionIDPrefix = "lsg_"

// Brief 是给 Learner 的学习素材。
type Brief struct {
	// Stats 是当前流水线指标（含自动入库率）。
	Stats *drafter.Stats `json:"stats"`
	// Decisions 是最近的终审决议（含驳回原因），是 Learner 最直接的反馈来源。
	Decisions []sqlite.PocReview `json:"decisions"`
	// Suggestions 是既有待审建议，避免模型重复提同一件事。
	Suggestions []sqlite.LearnSuggestion `json:"suggestions"`
}

// BriefOptions 是学习素材的查询条件。
type BriefOptions struct {
	// Limit 限制每类样本条数，默认 50，上限 200。
	Limit int
}

// Build 组装学习素材。
func Build(opts BriefOptions) (*Brief, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	stats, err := drafter.GetStats()
	if err != nil {
		return nil, err
	}
	decisions, err := sqlite.SelectPocReviews("", limit)
	if err != nil {
		return nil, err
	}
	suggestions, err := sqlite.SelectLearnSuggestions(sqlite.LearnSuggestionPending, limit)
	if err != nil {
		return nil, err
	}
	return &Brief{Stats: stats, Decisions: decisions, Suggestions: suggestions}, nil
}

// RecordOptions 是一次调优建议的输入。
type RecordOptions struct {
	// Kind 取 rule / threshold / other；留空按 other。
	Kind    string
	Summary string
	// Diff 是建议的变更内容（文本/diff），afrog 不解析。
	Diff  string
	Actor string
	// Source 记录建议依据（例如「近 20 次终审」）。
	Source string
}

// Record 存下一条调优建议（advisory，供人审）。
func Record(opts RecordOptions) (*sqlite.LearnSuggestion, error) {
	summary := strings.TrimSpace(opts.Summary)
	if summary == "" {
		return nil, fmt.Errorf("summary is required")
	}
	if strings.TrimSpace(opts.Diff) == "" {
		return nil, fmt.Errorf("diff is required")
	}

	rec := sqlite.LearnSuggestion{
		ID:      suggestionIDPrefix + xid.New().String(),
		Kind:    normalizeKind(opts.Kind),
		Summary: summary,
		Diff:    opts.Diff,
		Status:  sqlite.LearnSuggestionPending,
		Actor:   strings.TrimSpace(opts.Actor),
		Source:  strings.TrimSpace(opts.Source),
	}
	if err := sqlite.UpsertLearnSuggestion(rec); err != nil {
		return nil, err
	}
	return sqlite.SelectLearnSuggestion(rec.ID)
}

// List 按状态列出建议；status 为空表示全部。
func List(status string) ([]sqlite.LearnSuggestion, error) {
	return sqlite.SelectLearnSuggestions(status, 0)
}

// Show 取单条建议详情。
func Show(id string) (*sqlite.LearnSuggestion, error) {
	return sqlite.SelectLearnSuggestion(id)
}

// Accept 标记一条建议为已采纳。注意：这只是记录人工决策，不会自动应用 diff。
func Accept(id, note string) error {
	return sqlite.SetLearnSuggestionStatus(id, sqlite.LearnSuggestionAccepted, strings.TrimSpace(note))
}

// Reject 标记一条建议为已驳回。
func Reject(id, note string) error {
	return sqlite.SetLearnSuggestionStatus(id, sqlite.LearnSuggestionRejected, strings.TrimSpace(note))
}

func normalizeKind(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case sqlite.LearnKindRule:
		return sqlite.LearnKindRule
	case sqlite.LearnKindThreshold:
		return sqlite.LearnKindThreshold
	default:
		return sqlite.LearnKindOther
	}
}
