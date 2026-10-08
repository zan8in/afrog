package sqlite

import (
	"context"
	"encoding/json"
	"testing"
)

// TestProbeEventsPersistAndFilter 锁定资产发现明细的落库与读取：
// 端口与 Web 探测按 kind 区分，data 原样透传，且只能取回本任务的记录。
func TestProbeEventsPersistAndFilter(t *testing.T) {
	withFixture(t)

	if err := InsertProbeEvent(ProbeEvent{
		TaskID: "t-1", Kind: "port", TS: 1, Target: "a.example", Port: 80,
		Data: json.RawMessage(`{"host":"a.example","port":80}`),
	}); err != nil {
		t.Fatalf("insert port: %v", err)
	}
	if err := InsertProbeEvent(ProbeEvent{
		TaskID: "t-1", Kind: "webprobe", TS: 2, Target: "http://a.example/",
		Status: 200, Title: "示例站",
		Data: json.RawMessage(`{"url":"http://a.example/","status":200,"title":"示例站"}`),
	}); err != nil {
		t.Fatalf("insert webprobe: %v", err)
	}
	// 别的任务不应被带出来
	if err := InsertProbeEvent(ProbeEvent{
		TaskID: "t-2", Kind: "port", TS: 3, Target: "b.example", Port: 443,
		Data: json.RawMessage(`{"host":"b.example","port":443}`),
	}); err != nil {
		t.Fatalf("insert other task: %v", err)
	}

	all, err := SelectProbeEvents("t-1", "")
	if err != nil {
		t.Fatalf("select all: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("rows = %d, want 2", len(all))
	}
	if string(all[0].Data) == "" || !json.Valid(all[0].Data) {
		t.Fatalf("data not valid json: %q", string(all[0].Data))
	}

	ports, err := SelectProbeEvents("t-1", "port")
	if err != nil {
		t.Fatalf("select port: %v", err)
	}
	if len(ports) != 1 || ports[0].Target != "a.example" || ports[0].Port != 80 {
		t.Fatalf("port filter failed: %+v", ports)
	}

	byID, err := ProbeByID("t-1", []int64{all[0].ID, all[1].ID})
	if err != nil {
		t.Fatalf("probe by id: %v", err)
	}
	if len(byID) != 2 {
		t.Fatalf("probe by id rows = %d, want 2", len(byID))
	}
	// 跨任务取不到别的任务的记录
	if cross, _ := ProbeByID("t-2", []int64{all[0].ID}); len(cross) != 0 {
		t.Fatalf("probe by id leaked other task: %+v", cross)
	}
}

// TestProbeEventsPrunedWithScanTasks 锁定清理口径：任务快照被淘汰后，
// 其资产发现明细也一并删除，避免白占存储。
func TestProbeEventsPrunedWithScanTasks(t *testing.T) {
	withFixture(t)

	for _, taskID := range []string{"t-1", "t-2"} {
		if err := UpsertScanTask(sampleScanTask(taskID, "2026-10-01 10:00:00")); err != nil {
			t.Fatalf("upsert scan task %s: %v", taskID, err)
		}
		if err := InsertProbeEvent(ProbeEvent{
			TaskID: taskID, Kind: "port", TS: 1, Target: "a.example", Port: 80,
			Data: json.RawMessage(`{"host":"a.example","port":80}`),
		}); err != nil {
			t.Fatalf("insert probe %s: %v", taskID, err)
		}
	}

	// 删掉 t-1 的快照，再触发一次清理
	if _, err := dbx.Exec(`DELETE FROM scan_task WHERE taskid = ?`, "t-1"); err != nil {
		t.Fatalf("delete scan task: %v", err)
	}
	if err := pruneScanTasks(context.Background()); err != nil {
		t.Fatalf("prune: %v", err)
	}

	left, err := SelectProbeEvents("t-1", "")
	if err != nil {
		t.Fatalf("select t-1: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("probes of removed task not pruned: %+v", left)
	}
	kept, _ := SelectProbeEvents("t-2", "")
	if len(kept) != 1 {
		t.Fatalf("probes of kept task = %d, want 1", len(kept))
	}
}
