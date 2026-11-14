// Package judge 是决策面 Judge 角色的 afrog 侧契约：拼研判材料、存研判意见。
//
// 边界（与 §7 红线一致）：afrog 不做判定。本包不发包、不改漏洞台账，只做两件事——
//   - Brief：把一条命中的证据、周边观测与子图上下文拼成一份研判材料，供外部模型研判；
//   - Record：把模型的研判意见作为 advisory 存下来（judgement 表），与台账分表隔离。
//
// 换句话说：模型给的是「意见」，台账里的「结论」仍然由确定性引擎与人维护。
package judge

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/xid"

	"github.com/zan8in/afrog/v3/pkg/agentapi"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/evidence"
	"github.com/zan8in/afrog/v3/pkg/observation"
)

// judgementIDPrefix 让研判意见 id 可辨认（与 evd_ / obs_ 同风格）。
const judgementIDPrefix = "jdg_"

// Brief 是给 Judge 的研判材料。
type Brief struct {
	Evidence *evidence.Evidence `json:"evidence"`
	// Observations 是证据目标周边的观测（同源的端口/指纹/TLS 等过程事实）。
	Observations []observation.Observation `json:"observations"`
	// Graph 是证据目标所处的攻击面子图，帮助判断「这台机器上还有什么」。
	Graph *agentapi.StateResult `json:"graph,omitempty"`
	// Judgements 是该对象上已有的研判意见（可能来自不同 actor）。
	Judgements []sqlite.Judgement `json:"judgements"`
}

// BriefOptions 是研判材料的查询条件。
type BriefOptions struct {
	// ID 是 observe.evidence 的 id：result 主键或 evd_ 证据 id。
	ID string
	// ObservationLimit 限制周边观测条数，默认 50，上限 200。
	ObservationLimit int
}

// Build 组装一份研判材料。ID 取不到证据时返回错误——没有证据就没有可研判的对象。
func Build(opts BriefOptions) (*Brief, error) {
	id := strings.TrimSpace(opts.ID)
	if id == "" {
		return nil, fmt.Errorf("id is required")
	}
	ev, err := agentapi.Evidence(id)
	if err != nil {
		return nil, err
	}
	if ev == nil {
		return nil, fmt.Errorf("evidence not found for %q", id)
	}

	limit := opts.ObservationLimit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	out := &Brief{Evidence: ev}
	if target := strings.TrimSpace(ev.Target); target != "" {
		// 观测与子图都是「上下文」，取不到不算失败：研判材料的主干是证据本身。
		subject := observation.EndpointSubject(target)
		if page, err := agentapi.Observations(sqlite.ObservationFilter{
			Subject:      subject,
			SubjectUnder: true,
			Limit:        limit,
		}); err == nil && page != nil {
			out.Observations = page.Items
		}
		if graph, err := agentapi.State(target, "", 2, "both"); err == nil {
			out.Graph = graph
		}
	}

	judgements, err := sqlite.SelectJudgementsBySubject(id, ev.ID)
	if err != nil {
		return nil, err
	}
	out.Judgements = judgements
	return out, nil
}

// RecordOptions 是一次研判意见的输入。
type RecordOptions struct {
	// SubjectID 是被研判对象的 id（与 Brief 的 ID 同口径）。
	SubjectID  string
	Conclusion string
	Reasoning  string
	// ReviewSteps 是给人工的复核步骤。
	ReviewSteps []string
	// Actor 是给出意见的主体，例如 agent:artex。
	Actor string
}

// Record 存下一条研判意见（advisory，不改台账）。
func Record(opts RecordOptions) (*sqlite.Judgement, error) {
	subject := strings.TrimSpace(opts.SubjectID)
	if subject == "" {
		return nil, fmt.Errorf("id is required")
	}

	conclusion := normalizeConclusion(opts.Conclusion)
	if conclusion == "" {
		return nil, fmt.Errorf("conclusion must be one of likely_true/likely_false/uncertain")
	}

	steps := make([]string, 0, len(opts.ReviewSteps))
	for _, s := range opts.ReviewSteps {
		if t := strings.TrimSpace(s); t != "" {
			steps = append(steps, t)
		}
	}
	stepsJSON, err := json.Marshal(steps)
	if err != nil {
		return nil, err
	}

	// 尽量把证据 id 补全，方便下游按证据回查；取不到就留空（研判对象可能只是 result 主键）。
	evidenceID := subject
	if ev, err := agentapi.Evidence(subject); err == nil && ev != nil {
		evidenceID = ev.ID
	}

	rec := sqlite.Judgement{
		ID:          judgementIDPrefix + xid.New().String(),
		SubjectID:   subject,
		EvidenceID:  evidenceID,
		Conclusion:  conclusion,
		Reasoning:   strings.TrimSpace(opts.Reasoning),
		ReviewSteps: string(stepsJSON),
		Actor:       strings.TrimSpace(opts.Actor),
	}
	if err := sqlite.UpsertJudgement(rec); err != nil {
		return nil, err
	}
	return sqlite.SelectJudgementByID(rec.ID)
}

// normalizeConclusion 归一化结论取值；非法时返回空串。
func normalizeConclusion(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case sqlite.JudgementLikelyTrue:
		return sqlite.JudgementLikelyTrue
	case sqlite.JudgementLikelyFalse:
		return sqlite.JudgementLikelyFalse
	case sqlite.JudgementUncertain:
		return sqlite.JudgementUncertain
	}
	return ""
}
