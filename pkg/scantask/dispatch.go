package scantask

import (
	"context"
	"errors"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/executor"
)

// Dispatcher 执行工具面动作：这些动作在进程内完成（由工具面走 policy.Gate），
// 不经执行面的 CLI 子进程，但同样纳入任务生命周期——排队、事件缓冲、订阅、
// 收尾全部复用，调用方拿到的任务语义与扫描任务完全一致。
//
// 实现方是工具面（pkg/mcp）。scantask 不依赖工具面，只定义契约：
// 派发者把一批同类型的动作跑成一条事件流，其余交给控制面。
type Dispatcher interface {
	// Supports 报告能否执行该动作类型。为假时 SubmitBatch 直接拒绝，
	// 避免任务被受理、占用并发名额之后才在 run 阶段失败。
	Supports(kind ActionKind) bool

	// Dispatch 执行一个同类型的动作批量，返回与执行面同形的事件流句柄。
	//
	// 返回后由控制面消费 Events() 直到通道关闭，并以 done / error 事件与 Err()
	// 决定收尾状态。约定与 executor.Handle 一致，取消走 Cancel()。
	Dispatch(ctx context.Context, taskID string, batch Batch) (executor.Handle, error)
}

// ErrNoDispatcher 表示批量是工具面动作，却没有可用的派发后端。
var ErrNoDispatcher = errors.New("scantask: no dispatcher for tool-face action kind")

// toolFaceKind 返回批量的动作类型，并报告它是否由工具面执行。
//
// 只看第一个动作的类型：批量内必须同类型，这一约束由组装规格时统一校验。
func toolFaceKind(batch Batch) (ActionKind, bool) {
	if len(batch.Actions) == 0 {
		return "", false
	}
	kind := batch.Actions[0].Kind
	return kind, kind.ToolFace()
}

// dispatchSpec 为工具面动作合成一份最小规格。
//
// 工具面动作的执行参数在 Action 里、由 Dispatcher 解释，Spec 只承担快照需要的两件事：
// 目标列表与任务名。它不会被交给执行面，因此其余字段一律留空，避免出现「看起来配了、
// 实际没生效」的字段。
func dispatchSpec(batch Batch) (*executor.Spec, func(), error) {
	kind := batch.Actions[0].Kind

	targets := make([]string, 0, len(batch.Actions))
	seen := make(map[string]bool, len(batch.Actions))
	for _, a := range batch.Actions {
		if a.Kind != kind {
			return nil, func() {}, ErrMixedActionKinds
		}
		t := strings.TrimSpace(a.Target)
		if t == "" {
			return nil, func() {}, ErrActionNoTarget
		}
		if !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}

	return &executor.Spec{
		Targets:  targets,
		TaskName: strings.TrimSpace(batch.Options.TaskName),
	}, func() {}, nil
}
