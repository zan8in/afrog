package scantask

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
)

// ---------------------------------------------------------------------------
// 工具面派发的测试替身：假 Dispatcher 返回与执行面同形的句柄，
// 使工具面任务能走完整生命周期而不依赖 pkg/mcp。
// ---------------------------------------------------------------------------

type fakeDispatcher struct {
	mu       sync.Mutex
	supports map[ActionKind]bool
	handles  map[string]*fakeHandle
	batches  map[string]Batch
	// startErr 非空时 Dispatch 直接失败。
	startErr error
}

func newFakeDispatcher(kinds ...ActionKind) *fakeDispatcher {
	d := &fakeDispatcher{
		supports: make(map[ActionKind]bool),
		handles:  make(map[string]*fakeHandle),
		batches:  make(map[string]Batch),
	}
	for _, k := range kinds {
		d.supports[k] = true
	}
	return d
}

func (d *fakeDispatcher) Supports(kind ActionKind) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.supports[kind]
}

func (d *fakeDispatcher) Dispatch(_ context.Context, taskID string, batch Batch) (executor.Handle, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.startErr != nil {
		return nil, d.startErr
	}
	h := &fakeHandle{
		events: make(chan *scanstream.Event, 64),
		done:   make(chan struct{}),
	}
	d.handles[taskID] = h
	d.batches[taskID] = batch
	return h, nil
}

func (d *fakeDispatcher) handle(t *testing.T, taskID string) *fakeHandle {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	h, ok := d.handles[taskID]
	if !ok {
		t.Fatalf("dispatcher never received task %s", taskID)
	}
	return h
}

func (d *fakeDispatcher) batch(t *testing.T, taskID string) Batch {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	b, ok := d.batches[taskID]
	if !ok {
		t.Fatalf("dispatcher never received task %s", taskID)
	}
	return b
}

func (d *fakeDispatcher) emit(t *testing.T, taskID, typ string, fill func(*scanstream.Event)) {
	t.Helper()
	ev := &scanstream.Event{Type: typ}
	if fill != nil {
		fill(ev)
	}
	d.handle(t, taskID).events <- ev
}

// finish 追加 done 事件并结束事件流，模拟工具面动作跑完。
func (d *fakeDispatcher) finish(t *testing.T, taskID, doneStatus string) {
	t.Helper()
	d.emit(t, taskID, scanstream.TypeDone, func(ev *scanstream.Event) {
		ev.Done = &scanstream.DoneEvent{Status: doneStatus, Summary: &scanstream.Summary{Executed: 2}}
	})
	if err := d.handle(t, taskID).Cancel(); err != nil && !errors.Is(err, executor.ErrAlreadyDone) {
		t.Fatalf("finish: %v", err)
	}
}

// submitToolFace 提交一个目标各一个动作的工具面批量。
func submitToolFace(t *testing.T, rig *testRig, kind ActionKind, targets ...string) string {
	t.Helper()
	actions := make([]Action, 0, len(targets))
	for _, tg := range targets {
		actions = append(actions, Action{Kind: kind, Target: tg})
	}
	snap, err := rig.mgr.SubmitBatch(Batch{
		Options: Request{TaskName: "probe"},
		Actions: actions,
	})
	if err != nil {
		t.Fatalf("SubmitBatch: %v", err)
	}
	return snap.ID
}

// ---------------------------------------------------------------------------
// 用例
// ---------------------------------------------------------------------------

// 工具面任务的排队、事件、收尾与扫描任务完全一致，且执行面自始至终没有被调用。
func TestSubmitBatch_ToolFaceRunsThroughDispatcher(t *testing.T) {
	disp := newFakeDispatcher(ActionProbeHTTP)
	rig := newRig(t, Options{Dispatcher: disp})
	id := submitToolFace(t, rig, ActionProbeHTTP, "http://a.example", "http://b.example")

	sub, _, err := rig.mgr.Subscribe(id, 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	waitStatus(t, rig, id, StatusRunning, 10*time.Second)

	if b := disp.batch(t, id); len(b.Actions) != 2 || b.Options.TaskName != "probe" {
		t.Fatalf("dispatched batch = %+v, want the original batch verbatim", b)
	}
	rig.exec.mu.Lock()
	started := len(rig.exec.handles)
	rig.exec.mu.Unlock()
	if started != 0 {
		t.Fatalf("executor must not be used for tool-face tasks, started %d", started)
	}

	disp.emit(t, id, scanstream.TypeLog, func(ev *scanstream.Event) {
		ev.Log = &scanstream.LogEvent{Level: "info", Text: "probe.http http://a.example: ok"}
	})
	disp.finish(t, id, "completed")

	events := collect(t, sub, 10*time.Second)
	assertContiguous(t, events)

	snap := rig.task(t, id).Snapshot()
	if snap.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", snap.Status)
	}
	if snap.Name != "probe" {
		t.Fatalf("name = %q, want probe", snap.Name)
	}
	if snap.ActionCount != 2 || len(snap.ActionKinds) != 1 || snap.ActionKinds[0] != string(ActionProbeHTTP) {
		t.Fatalf("actions = %d/%v, want 2 x [probe_http]", snap.ActionCount, snap.ActionKinds)
	}
	if len(snap.Targets) != 2 {
		t.Fatalf("targets = %v, want the two requested", snap.Targets)
	}
	if snap.Pausable {
		t.Fatal("tool-face task has no suspendable process and must not be pausable")
	}
	if snap.Summary == nil || snap.Summary.Executed != 2 {
		t.Fatalf("summary = %+v, want executed=2", snap.Summary)
	}
}

// oob_wait 也是工具面动作：能派发到后端，且 Params（filter / filter_type）原样透传。
func TestSubmitBatch_ToolFaceOOBWaitDispatchesParams(t *testing.T) {
	disp := newFakeDispatcher(ActionOOBWait)
	rig := newRig(t, Options{Dispatcher: disp})

	const params = `{"filter":"f1","filter_type":"dns"}`
	snap, err := rig.mgr.SubmitBatch(Batch{
		Options: Request{TaskName: "oob"},
		Actions: []Action{{Kind: ActionOOBWait, Target: "http://a.example", Params: json.RawMessage(params)}},
	})
	if err != nil {
		t.Fatalf("SubmitBatch: %v", err)
	}
	waitStatus(t, rig, snap.ID, StatusRunning, 10*time.Second)

	if snap.ActionCount != 1 || len(snap.ActionKinds) != 1 || snap.ActionKinds[0] != string(ActionOOBWait) {
		t.Fatalf("actions = %d/%v, want 1 x [oob_wait]", snap.ActionCount, snap.ActionKinds)
	}
	if b := disp.batch(t, snap.ID); len(b.Actions) != 1 || string(b.Actions[0].Params) != params {
		t.Fatalf("dispatched batch = %+v, want Params verbatim", b)
	}

	disp.finish(t, snap.ID, "completed")
	waitTerminal(t, rig, snap.ID, 5*time.Second)
}

// 没有派发后端时，工具面动作在受理阶段就被拒，不会占名额、也不会留下半截任务。
func TestSubmitBatch_ToolFaceWithoutDispatcherIsRejected(t *testing.T) {
	rig := newRig(t, Options{})
	_, err := rig.mgr.SubmitBatch(Batch{Actions: []Action{{Kind: ActionProbeHTTP, Target: "http://a.example"}}})
	if !errors.Is(err, ErrNoDispatcher) {
		t.Fatalf("err = %v, want ErrNoDispatcher", err)
	}
	if got := len(rig.mgr.List()); got != 0 {
		t.Fatalf("rejected batch registered %d task(s), want 0", got)
	}
}

// 派发后端存在但不认这个类型时，同样在受理阶段拒绝。
func TestSubmitBatch_UnsupportedToolFaceKindIsRejected(t *testing.T) {
	disp := newFakeDispatcher(ActionProbeHTTP) // 刻意不支持 brute
	rig := newRig(t, Options{Dispatcher: disp})
	_, err := rig.mgr.SubmitBatch(Batch{Actions: []Action{{Kind: ActionBrute, Target: "http://a.example"}}})
	if !errors.Is(err, ErrNoDispatcher) {
		t.Fatalf("err = %v, want ErrNoDispatcher", err)
	}
	if got := len(rig.mgr.List()); got != 0 {
		t.Fatalf("rejected batch registered %d task(s), want 0", got)
	}
}

// 工具面规格只承载快照需要的目标与任务名，重复目标会被去重。
func TestSubmitBatch_ToolFaceSpecCarriesOnlyTargetsAndName(t *testing.T) {
	disp := newFakeDispatcher(ActionProbeHTTP)
	rig := newRig(t, Options{Dispatcher: disp})
	id := submitToolFace(t, rig, ActionProbeHTTP, "http://a.example", "http://a.example", "http://b.example")

	spec := rig.task(t, id).Spec()
	if spec.TaskName != "probe" {
		t.Fatalf("task name = %q, want probe", spec.TaskName)
	}
	if len(spec.Targets) != 2 || spec.Targets[0] != "http://a.example" || spec.Targets[1] != "http://b.example" {
		t.Fatalf("targets = %v, want deduped [a b]", spec.Targets)
	}

	waitStatus(t, rig, id, StatusRunning, 10*time.Second)
	disp.finish(t, id, "completed")
	waitTerminal(t, rig, id, 5*time.Second)
}

// 一个批量里混了不同动作类型必须被拒。
func TestSubmitBatch_ToolFaceRejectsMixedKinds(t *testing.T) {
	disp := newFakeDispatcher(ActionProbeHTTP)
	rig := newRig(t, Options{Dispatcher: disp})
	_, err := rig.mgr.SubmitBatch(Batch{Actions: []Action{
		{Kind: ActionProbeHTTP, Target: "http://a.example"},
		{Kind: ActionRunPoc, Target: "http://b.example"},
	}})
	if !errors.Is(err, ErrMixedActionKinds) {
		t.Fatalf("err = %v, want ErrMixedActionKinds", err)
	}
}

// 工具面动作同样要求目标非空。
func TestSubmitBatch_ToolFaceRejectsActionWithoutTarget(t *testing.T) {
	disp := newFakeDispatcher(ActionProbeHTTP)
	rig := newRig(t, Options{Dispatcher: disp})
	_, err := rig.mgr.SubmitBatch(Batch{Actions: []Action{{Kind: ActionProbeHTTP, Target: "  "}}})
	if !errors.Is(err, ErrActionNoTarget) {
		t.Fatalf("err = %v, want ErrActionNoTarget", err)
	}
}

// 工具面任务与扫描任务共享同一份并发名额：一个在跑，另一个（无论是哪种）都得排队。
func TestSubmitBatch_ToolFaceSharesConcurrencyWithScans(t *testing.T) {
	disp := newFakeDispatcher(ActionProbeHTTP)
	rig := newRig(t, Options{Dispatcher: disp, MaxRunning: 1})

	first := submitToolFace(t, rig, ActionProbeHTTP, "http://a.example")
	waitStatus(t, rig, first, StatusRunning, 10*time.Second)

	second := submit(t, rig) // 普通扫描任务（执行面）
	if got := rig.task(t, second).Snapshot().Status; got != StatusQueued {
		t.Fatalf("scan task status = %s, want queued while a tool-face task holds the slot", got)
	}

	disp.finish(t, first, "completed")
	waitTerminal(t, rig, first, 5*time.Second)
	waitStatus(t, rig, second, StatusRunning, 10*time.Second)
	rig.exec.finish(t, second, "completed")
	waitTerminal(t, rig, second, 5*time.Second)
}

// 派发失败要落到 failed，并把名额还回去。
func TestSubmitBatch_ToolFaceDispatchFailureFreesSlot(t *testing.T) {
	disp := newFakeDispatcher(ActionProbeHTTP)
	disp.startErr = errors.New("dispatch boom")
	rig := newRig(t, Options{Dispatcher: disp, MaxRunning: 1})

	id := submitToolFace(t, rig, ActionProbeHTTP, "http://a.example")
	snap := waitTerminal(t, rig, id, 5*time.Second)
	if snap.Status != StatusFailed || snap.Error == "" {
		t.Fatalf("snapshot = %+v, want failed with an error message", snap)
	}

	disp.startErr = nil
	next := submitToolFace(t, rig, ActionProbeHTTP, "http://b.example")
	waitStatus(t, rig, next, StatusRunning, 10*time.Second)
}

// 取消运行中的工具面任务要能收尾为 cancelled。
func TestSubmitBatch_ToolFaceCancelFinalisesCancelled(t *testing.T) {
	disp := newFakeDispatcher(ActionProbeHTTP)
	rig := newRig(t, Options{Dispatcher: disp})
	id := submitToolFace(t, rig, ActionProbeHTTP, "http://a.example")
	waitStatus(t, rig, id, StatusRunning, 10*time.Second)

	if err := rig.mgr.Control(id, ControlCancel); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if snap := waitTerminal(t, rig, id, 5*time.Second); snap.Status != StatusCancelled {
		t.Fatalf("status = %s, want cancelled", snap.Status)
	}
}
