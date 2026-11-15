package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
	"github.com/zan8in/afrog/v3/pkg/scantask"
)

// dispatchLogLimit 是单条动作日志的长度上限：事件流是给人看的进度，不是证据存放处。
const dispatchLogLimit = 4096

// toolFaceTools 是工具面动作类型到工具名的映射（架构稿 §4.3）。
//
// 只列真正有工具的动作：枚举里放一个落不到实现的类型只会变成死值。
var toolFaceTools = map[scantask.ActionKind]string{
	scantask.ActionProbeHTTP:      "probe.http",
	scantask.ActionReplayEvidence: "verify.replay",
	scantask.ActionBrute:          "act.brute",
	scantask.ActionOOBWait:        "act.oob_wait",
}

// Dispatcher 把本工具面接成 scantask 的派发后端，供控制面把工具面动作当成
// 普通任务来调度（排队、事件流、订阅、收尾）。
//
// 门控、预算、审计仍由各工具处理器内部完成——派发只换了「谁来调度」，
// 没有改「谁来执行、谁来判定」。
func (s *Server) Dispatcher() scantask.Dispatcher { return dispatcher{s: s} }

// dispatcher 是一个无状态适配器：所有执行都落在 Server 已有的工具处理器上。
type dispatcher struct{ s *Server }

func (d dispatcher) Supports(kind scantask.ActionKind) bool {
	_, ok := toolFaceTools[kind]
	return ok
}

func (d dispatcher) Dispatch(ctx context.Context, _ string, batch scantask.Batch) (executor.Handle, error) {
	if len(batch.Actions) == 0 {
		return nil, fmt.Errorf("mcp: empty action batch")
	}
	tool, ok := toolFaceTools[batch.Actions[0].Kind]
	if !ok {
		return nil, fmt.Errorf("mcp: no tool for action kind %q", batch.Actions[0].Kind)
	}

	h := newDispatchHandle(ctx)
	go d.run(h, tool, batch)
	return h, nil
}

// run 逐个执行动作并把结果写进事件流，最后发一条 done（或 error）事件收尾。
//
// 动作互不依赖，单个失败不牵连其余：失败只记 error 级日志，只有全部失败才把整个任务
// 判为失败——这样「3 个目标里挂了 1 个」不会让另外 2 个的结果消失。
func (d dispatcher) run(h *dispatchHandle, tool string, batch scantask.Batch) {
	start := time.Now()
	executed, failed := 0, 0
	for _, a := range batch.Actions {
		if h.ctx.Err() != nil {
			break
		}
		out, err := d.callTool(h.ctx, tool, a)
		if err != nil {
			failed++
			h.emit(logEvent("error", fmt.Sprintf("%s %s: %v", tool, a.Target, err)))
			continue
		}
		executed++
		h.emit(logEvent("info", toolResultText(tool, a.Target, out)))
	}

	switch {
	case h.ctx.Err() != nil:
		// 被取消：不补 done，控制面已把任务收尾为 cancelled。
	case executed == 0 && failed > 0:
		h.emit(&scanstream.Event{Type: scanstream.TypeError, Error: &scanstream.ErrorEvent{
			Code:    "dispatch_failed",
			Message: fmt.Sprintf("all %d actions failed", failed),
		}})
	default:
		h.emit(&scanstream.Event{Type: scanstream.TypeDone, Done: &scanstream.DoneEvent{
			Status: "completed",
			Summary: &scanstream.Summary{
				Executed:  int64(executed),
				ElapsedMs: time.Since(start).Milliseconds(),
			},
		}})
	}
	h.close(nil)
}

// callTool 把一个动作翻成工具调用。入参由 actionArgs 组装，门控在处理器内部执行。
func (d dispatcher) callTool(ctx context.Context, tool string, a scantask.Action) (any, error) {
	args, err := actionArgs(a)
	if err != nil {
		return nil, err
	}
	return d.s.Call(ctx, tool, args)
}

// actionArgs 把动作翻译成工具入参：Params 是主体，Target / PocID 补上动作自带的定位信息。
//
// 各工具的入参名不同（probe.http 用 url，其余用 target），因此按类型补默认值，而不是
// 笼统地塞一个 target；Params 里显式给出的字段优先，不作覆盖。
func actionArgs(a scantask.Action) (json.RawMessage, error) {
	args := map[string]any{}
	if len(a.Params) > 0 {
		if err := json.Unmarshal(a.Params, &args); err != nil {
			return nil, fmt.Errorf("action params must be a JSON object: %w", err)
		}
		// 字面量 null 是合法 JSON，但会把 map 清成 nil，之后写默认值就会 panic。
		if args == nil {
			args = map[string]any{}
		}
	}

	target := strings.TrimSpace(a.Target)
	switch a.Kind {
	case scantask.ActionProbeHTTP:
		if _, ok := args["url"]; !ok {
			args["url"] = target
		}
	case scantask.ActionReplayEvidence:
		if _, ok := args["target"]; !ok {
			args["target"] = target
		}
	case scantask.ActionBrute:
		if _, ok := args["target"]; !ok {
			args["target"] = target
		}
		if _, ok := args["poc_id"]; !ok && strings.TrimSpace(a.PocID) != "" {
			args["poc_id"] = strings.TrimSpace(a.PocID)
		}
	case scantask.ActionOOBWait:
		// filter / filter_type / timeout_sec 由 Params 给出；target 只用于观测流的 subject。
		if _, ok := args["target"]; !ok {
			args["target"] = target
		}
	}
	return json.Marshal(args)
}

// logEvent 把一次动作的结果包成诊断事件。
//
// 用 log 而不是 result：result 会按严重级别进命中统计，而 HTTP 探测成功、重放一致
// 这类事实不是漏洞命中。工具面的真正产物（观测、证据、命中）由处理器自己落库。
func logEvent(level, text string) *scanstream.Event {
	return &scanstream.Event{
		Type: scanstream.TypeLog,
		Log:  &scanstream.LogEvent{Level: level, Text: clampText(text, dispatchLogLimit)},
	}
}

func toolResultText(tool, target string, out any) string {
	b, err := json.Marshal(out)
	if err != nil {
		return fmt.Sprintf("%s %s: ok", tool, target)
	}
	return fmt.Sprintf("%s %s: %s", tool, target, string(b))
}

// dispatchHandle 是进程内动作的句柄：与执行面的子进程句柄同形，供控制面一视同仁地
// 驱动事件流与控制。
//
// 事件流由执行协程唯一写入并关闭（emit 与 close 同 goroutine），因此无需为通道加锁；
// 取消通过 ctx 通知执行协程，它停止后自行 close。
type dispatchHandle struct {
	ctx    context.Context
	cancel context.CancelFunc
	events chan *scanstream.Event
	done   chan struct{}

	closeOnce sync.Once
	mu        sync.Mutex
	err       error
}

func newDispatchHandle(parent context.Context) *dispatchHandle {
	ctx, cancel := context.WithCancel(parent)
	return &dispatchHandle{
		ctx:    ctx,
		cancel: cancel,
		events: make(chan *scanstream.Event, 64),
		done:   make(chan struct{}),
	}
}

func (h *dispatchHandle) Events() <-chan *scanstream.Event { return h.events }
func (h *dispatchHandle) Done() <-chan struct{}            { return h.done }

// PID 对进程内动作没有意义，返回 0。
func (h *dispatchHandle) PID() int { return 0 }

func (h *dispatchHandle) Err() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.err
}

// Pause / Resume 没有可挂起的进程：如实报告不支持，避免上层把「暂停不了」当成成功。
func (h *dispatchHandle) Pause() error  { return executor.ErrPauseUnsupported }
func (h *dispatchHandle) Resume() error { return executor.ErrPauseUnsupported }

// Cancel 取消尚未完成的动作；事件流由执行协程停止后关闭。
func (h *dispatchHandle) Cancel() error {
	select {
	case <-h.done:
		return executor.ErrAlreadyDone
	default:
	}
	h.cancel()
	return nil
}

// emit 投递一条事件。取消后执行协程会尽快退出，这里用 ctx 兜底以免卡住。
func (h *dispatchHandle) emit(ev *scanstream.Event) {
	select {
	case h.events <- ev:
	case <-h.ctx.Done():
	}
}

// close 结束事件流与 Done 通道，只由执行协程调用，因此可以安全关闭通道。
func (h *dispatchHandle) close(err error) {
	h.mu.Lock()
	h.err = err
	h.mu.Unlock()

	h.closeOnce.Do(func() {
		h.cancel()
		close(h.events)
		close(h.done)
	})
}
