package scantask

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/executor"
)

// ActionKind 是原子动作类型（架构稿 §4.3）。
//
// 取值分两类：执行面（afrog CLI）一次能跑的模式，和工具面在进程内执行的动作。
// 一个任务里的动作必须同 kind：一次只跑一种模式。
type ActionKind string

const (
	// ActionRunPoc 在目标上运行一个 PoC。
	ActionRunPoc ActionKind = "run_poc"
	// ActionPortScan 以端口扫描为前置阶段扫描目标。
	ActionPortScan ActionKind = "port_scan"
	// ActionWebFingerprint 以 Web 指纹识别为前置阶段扫描目标。
	ActionWebFingerprint ActionKind = "web_fingerprint"

	// 以下三类是工具面动作：不经执行面的 CLI 子进程，而是在进程内执行（见 Dispatcher）。
	//
	// ActionProbeHTTP 对目标发起一次受限 HTTP 请求。
	ActionProbeHTTP ActionKind = "probe_http"
	// ActionReplayEvidence 重放一条已有证据，比对 digest 是否仍然一致。
	ActionReplayEvidence ActionKind = "replay_evidence"
	// ActionBrute 用带字典的 PoC 做弱口令尝试（破坏性，默认被策略拒绝）。
	ActionBrute ActionKind = "brute"
	// ActionOOBWait 等待一次带外（反连）回连，命中即写入观测流。
	ActionOOBWait ActionKind = "oob_wait"
)

// ToolFace 报告该类型是否由工具面在进程内执行。
//
// 执行面一次只拉起一个 CLI 子进程、只能单一模式；工具面动作没有这个约束，因此两者的
// 装配路径不同（见 Manager.buildSpec 与 Manager.startTask）。
func (k ActionKind) ToolFace() bool {
	switch k {
	case ActionProbeHTTP, ActionReplayEvidence, ActionBrute, ActionOOBWait:
		return true
	}
	return false
}

// Action 是任务里的一个原子工作单元：在某个目标上做一件事。
type Action struct {
	Kind   ActionKind
	Target string
	// PocID 只有 run_poc 与 brute 使用；为空表示该目标按批量的 PoC 选择展开。
	PocID string
	// Params 是工具面动作的附加参数（JSON 对象），执行面动作忽略。
	//
	// 它是工具入参的唯一载体：scantask 不理解具体字段，原样交给 Dispatcher，
	// 由工具面按自己的 schema 解释。
	Params json.RawMessage
}

// Batch 是任务的工作单元集合：一组动作 + 它们共享的执行选项。
//
// 现有「一次扫描」= 「目标 × PoC」的 run_poc 批量：调用方只给选项（Request），
// 动作由引擎在网络阶段展开，因此 Actions 为空即「扫描式批量」，行为与历史完全一致。
// 单 Action 提交 = 只含一个 Action 的批量，共享选项仍由 Options 提供。
type Batch struct {
	// Options 是批量动作共享的执行选项（性能 / 网络 / OOB / 结果去向等）。
	Options Request
	// Actions 是显式动作列表。为空表示「按 Options 展开的扫描式批量」。
	Actions []Action
}

var (
	// ErrMixedActionKinds 表示一个批量里混了不同的动作类型。
	ErrMixedActionKinds = errors.New("scantask: batch mixes action kinds")
	// ErrActionNoTarget 表示动作没有目标。
	ErrActionNoTarget = errors.New("scantask: action has no target")
	// ErrUnknownActionKind 表示动作类型无法由执行面表达。
	ErrUnknownActionKind = errors.New("scantask: unknown action kind")
	// ErrHeterogeneousBatch 表示显式动作凑不成「目标 × PoC」的完整笛卡尔积：
	// 执行面按笛卡尔积展开，给出残缺组合会把不存在的配对一起扫出去，因此直接拒绝。
	ErrHeterogeneousBatch = errors.New("scantask: actions do not form a target x poc cross product")
)

// buildSpec 把批量翻译成执行器规格。
func (b Batch) buildSpec() (*executor.Spec, func(), error) {
	if len(b.Actions) == 0 {
		// 扫描式批量：选项即规格。
		return BuildSpec(b.Options)
	}
	req, err := b.deriveRequest()
	if err != nil {
		return nil, func() {}, err
	}
	return BuildSpec(req)
}

// deriveRequest 把显式动作折叠成一份等价的 Request，交给 BuildSpec 走同一条装配路径。
func (b Batch) deriveRequest() (Request, error) {
	kind := b.Actions[0].Kind

	targets := make([]string, 0, len(b.Actions))
	targetSeen := make(map[string]bool, len(b.Actions))
	pocs := make([]string, 0, len(b.Actions))
	pocSeen := make(map[string]bool, len(b.Actions))

	for _, a := range b.Actions {
		if a.Kind != kind {
			return Request{}, ErrMixedActionKinds
		}
		t := strings.TrimSpace(a.Target)
		if t == "" {
			return Request{}, ErrActionNoTarget
		}
		if !targetSeen[t] {
			targetSeen[t] = true
			targets = append(targets, t)
		}
		if p := strings.TrimSpace(a.PocID); p != "" && !pocSeen[p] {
			pocSeen[p] = true
			pocs = append(pocs, p)
		}
	}

	req := b.Options
	req.Targets = targets

	switch kind {
	case ActionRunPoc:
		// 动作必须恰好是「目标 × PoC」的全部组合。
		want := len(targets)
		if len(pocs) > 0 {
			want = len(targets) * len(pocs)
		}
		if len(b.Actions) != want {
			return Request{}, ErrHeterogeneousBatch
		}
		req.PocIDs = pocs
		if len(pocs) > 0 {
			// 显式 PoC 集合是独占语义，清掉来源/文件覆盖，避免两条路径打架。
			req.PocSource = ""
			req.PocFile = ""
		}
	case ActionPortScan:
		if len(b.Actions) != len(targets) {
			return Request{}, ErrHeterogeneousBatch
		}
		req.PortScan = true
	case ActionWebFingerprint:
		if len(b.Actions) != len(targets) {
			return Request{}, ErrHeterogeneousBatch
		}
		req.WebFingerprint = true
	default:
		return Request{}, ErrUnknownActionKind
	}

	return req, nil
}

// actionKinds 返回批量里出现过的动作类型（去重、保持首次出现顺序）。
func actionKinds(actions []Action) []string {
	if len(actions) == 0 {
		return nil
	}
	seen := make(map[ActionKind]bool, len(actions))
	out := make([]string, 0, len(actions))
	for _, a := range actions {
		if seen[a.Kind] {
			continue
		}
		seen[a.Kind] = true
		out = append(out, string(a.Kind))
	}
	return out
}
