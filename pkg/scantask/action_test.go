package scantask

import (
	"errors"
	"testing"
	"time"
)

// 单 Action 提交：一个 run_poc 动作 = 目标 1 / PoC 1 的批量。
func TestSubmitBatch_SingleRunPocAction(t *testing.T) {
	rig := newRig(t, Options{})

	snap, err := rig.mgr.SubmitBatch(Batch{
		Options: Request{Concurrency: 1},
		Actions: []Action{{Kind: ActionRunPoc, Target: "http://a.example", PocID: "poc-1"}},
	})
	if err != nil {
		t.Fatalf("SubmitBatch: %v", err)
	}

	if snap.ActionCount != 1 || len(snap.ActionKinds) != 1 || snap.ActionKinds[0] != "run_poc" {
		t.Fatalf("snapshot = count %d kinds %v, want 1 / [run_poc]", snap.ActionCount, snap.ActionKinds)
	}

	task := rig.task(t, snap.ID)
	if got := task.Batch(); len(got.Actions) != 1 || got.Actions[0].PocID != "poc-1" {
		t.Fatalf("task.Batch() = %+v, want the submitted action", got)
	}

	// 子进程被拉起后才有 spec。
	waitStatus(t, rig, snap.ID, StatusRunning, 10*time.Second)
	spec := rig.exec.spec(t, snap.ID)
	if len(spec.Targets) != 1 || spec.Targets[0] != "http://a.example" {
		t.Fatalf("spec.Targets = %v, want [http://a.example]", spec.Targets)
	}
	if len(spec.PocIDs) != 1 || spec.PocIDs[0] != "poc-1" {
		t.Fatalf("spec.PocIDs = %v, want [poc-1]", spec.PocIDs)
	}
	if spec.Concurrency != 1 {
		t.Fatalf("spec.Concurrency = %d, want 1（共享选项要透传）", spec.Concurrency)
	}

	rig.exec.finish(t, snap.ID, "completed")
	if got := waitTerminal(t, rig, snap.ID, 10*time.Second); got.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", got.Status)
	}
}

// 「目标 × PoC」的完整笛卡尔积批量：2 目标 × 2 PoC = 4 个动作。
func TestSubmitBatch_RunPocCrossProduct(t *testing.T) {
	rig := newRig(t, Options{})

	var actions []Action
	for _, tgt := range []string{"http://a.example", "http://b.example"} {
		for _, poc := range []string{"poc-1", "poc-2"} {
			actions = append(actions, Action{Kind: ActionRunPoc, Target: tgt, PocID: poc})
		}
	}

	snap, err := rig.mgr.SubmitBatch(Batch{Actions: actions})
	if err != nil {
		t.Fatalf("SubmitBatch: %v", err)
	}
	if snap.ActionCount != 4 {
		t.Fatalf("ActionCount = %d, want 4", snap.ActionCount)
	}

	waitStatus(t, rig, snap.ID, StatusRunning, 10*time.Second)
	spec := rig.exec.spec(t, snap.ID)
	if len(spec.Targets) != 2 {
		t.Fatalf("spec.Targets = %v, want 2 distinct targets", spec.Targets)
	}
	if len(spec.PocIDs) != 2 {
		t.Fatalf("spec.PocIDs = %v, want 2 distinct pocs", spec.PocIDs)
	}
}

// 端口扫描批量：每个目标一个动作，共享选项里的 PortScan 由动作类型决定。
func TestSubmitBatch_PortScanBatch(t *testing.T) {
	rig := newRig(t, Options{})

	snap, err := rig.mgr.SubmitBatch(Batch{
		Actions: []Action{
			{Kind: ActionPortScan, Target: "10.0.0.1"},
			{Kind: ActionPortScan, Target: "10.0.0.2"},
		},
	})
	if err != nil {
		t.Fatalf("SubmitBatch: %v", err)
	}
	waitStatus(t, rig, snap.ID, StatusRunning, 10*time.Second)
	spec := rig.exec.spec(t, snap.ID)
	if !spec.PortScan {
		t.Fatal("spec.PortScan = false, want true")
	}
	if len(spec.Targets) != 2 {
		t.Fatalf("spec.Targets = %v, want 2", spec.Targets)
	}
	rig.exec.finish(t, snap.ID, "completed")
	waitTerminal(t, rig, snap.ID, 10*time.Second)
}

// 空批量退化为扫描式批量：行为与 Submit 完全一致。
func TestSubmitBatch_EmptyActionsFallsBackToScan(t *testing.T) {
	rig := newRig(t, Options{})

	snap, err := rig.mgr.SubmitBatch(Batch{Options: Request{Targets: []string{"http://a.example"}}})
	if err != nil {
		t.Fatalf("SubmitBatch: %v", err)
	}
	if snap.ActionCount != 0 || len(snap.ActionKinds) != 0 {
		t.Fatalf("snapshot = count %d kinds %v, want 0 / empty（扫描式批量）", snap.ActionCount, snap.ActionKinds)
	}
	waitStatus(t, rig, snap.ID, StatusRunning, 10*time.Second)
	if spec := rig.exec.spec(t, snap.ID); len(spec.Targets) != 1 {
		t.Fatalf("spec.Targets = %v, want 1", spec.Targets)
	}
	rig.exec.finish(t, snap.ID, "completed")
	waitTerminal(t, rig, snap.ID, 10*time.Second)
}

func TestSubmitBatch_RejectsMixedKinds(t *testing.T) {
	rig := newRig(t, Options{})
	_, err := rig.mgr.SubmitBatch(Batch{Actions: []Action{
		{Kind: ActionRunPoc, Target: "http://a.example"},
		{Kind: ActionPortScan, Target: "http://a.example"},
	}})
	if !errors.Is(err, ErrMixedActionKinds) {
		t.Fatalf("err = %v, want ErrMixedActionKinds", err)
	}
}

func TestSubmitBatch_RejectsUnknownKind(t *testing.T) {
	rig := newRig(t, Options{})
	_, err := rig.mgr.SubmitBatch(Batch{Actions: []Action{{Kind: "teleport", Target: "http://a.example"}}})
	if !errors.Is(err, ErrUnknownActionKind) {
		t.Fatalf("err = %v, want ErrUnknownActionKind", err)
	}
}

func TestSubmitBatch_RejectsActionWithoutTarget(t *testing.T) {
	rig := newRig(t, Options{})
	_, err := rig.mgr.SubmitBatch(Batch{Actions: []Action{{Kind: ActionRunPoc, Target: "  "}}})
	if !errors.Is(err, ErrActionNoTarget) {
		t.Fatalf("err = %v, want ErrActionNoTarget", err)
	}
}

// 残缺组合（(t1,pocA) + (t2,pocB)）不能在一次进程里表达：笛卡尔积会多扫出不存在的配对。
func TestSubmitBatch_RejectsHeterogeneousCrossProduct(t *testing.T) {
	rig := newRig(t, Options{})
	_, err := rig.mgr.SubmitBatch(Batch{Actions: []Action{
		{Kind: ActionRunPoc, Target: "http://a.example", PocID: "poc-1"},
		{Kind: ActionRunPoc, Target: "http://b.example", PocID: "poc-2"},
	}})
	if !errors.Is(err, ErrHeterogeneousBatch) {
		t.Fatalf("err = %v, want ErrHeterogeneousBatch", err)
	}
}

// Submit 在模型上就是「Options 展开」的批量：动作类型不显式，ActionCount 为 0。
func TestSubmit_IsAScanBatch(t *testing.T) {
	rig := newRig(t, Options{})
	id := submit(t, rig)
	if got := rig.task(t, id).Snapshot().ActionCount; got != 0 {
		t.Fatalf("ActionCount = %d, want 0（扫描式批量）", got)
	}
	if got := rig.task(t, id).Batch(); len(got.Actions) != 0 {
		t.Fatalf("Batch().Actions = %v, want empty", got.Actions)
	}
}
