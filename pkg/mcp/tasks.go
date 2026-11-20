package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/policy"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
	"github.com/zan8in/afrog/v3/pkg/scantask"
)

// defaultWait 是一次长任务调用的「短等窗口」。
//
// 窗口内跑完就照旧返回完整结果（旧契约不变）；超过窗口则转成 task_id 句柄，由
// task.* 继续跟踪。取 30s：比典型单 PoC 验证（数秒）宽裕，又短于一次关键词批量
// 扫描（实测约 200s），从而把「小检测」留在同步路径、把「大扫描」推给异步句柄。
const defaultWait = 30 * time.Second

// taskEventLimit 是 task.events 单次返回的事件条数上限：
// 任务的事件缓冲可以到 5000 条，一次全吐出去会把调用方的上下文撑爆。
const taskEventLimit = 200

// taskManager 返回控制面任务管理器，首次调用时懒加载。
//
// 装配口径与 pkg/scanapi 一致：执行器负责扫描（子进程），Dispatcher 负责工具面
// 动作（进程内）。懒加载而非构造时装配，是为了让「只读、从不发包」的会话
// （只调 observe.* / poc.search）不必付出拉子进程执行器的代价。
func (s *Server) taskManager() (*scantask.Manager, error) {
	s.taskOnce.Do(func() {
		ex, err := s.scanExecutor()
		if err != nil {
			s.taskErr = err
			return
		}
		mgr, err := scantask.New(scantask.Options{
			Executor:   ex,
			Dispatcher: s.Dispatcher(),
			// 任务收尾是「资源变了」的一个确定时点：任务列表、该任务详情、以及本次
			// 扫描可能新增的结论都变了。而此刻没有任何调用在途，只能靠会话登记的
			// 通道推 notifications/resources/updated（见 notifyResourceUpdated）。
			OnTaskFinished: s.onTaskFinished,
		})
		if err != nil {
			s.taskErr = err
			return
		}
		s.taskMgr = mgr
	})
	return s.taskMgr, s.taskErr
}

// onTaskFinished 在任务收尾后推送资源变更通知：三个受影响的资源一次推完，
// 客户端据此重读即可拿到刚出炉的任务状态与结论。
func (s *Server) onTaskFinished(snap *scantask.Snapshot) {
	s.notifyResourceUpdated(resourceTasksURI, resourceTaskPrefix+snap.ID, resourceFindingsURI)
}

// watchTimeout 为任务挂一个超时看护：到点若任务仍未结束，就取消它并登记
// 「这是超时结束的」。
//
// 超时不再靠调用方的 ctx：窗口结束后调用方可能已经走了，而任务还要跑；真正决定
// 任务寿命的是这里的看护。登记表供 scanStatus 把「被超时取消」与「被人取消」区分开。
func (s *Server) watchTimeout(mgr *scantask.Manager, taskID string, timeout time.Duration) {
	if mgr == nil || timeout <= 0 {
		return
	}
	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		<-timer.C

		// 到点时任务已经自己收尾就别再动它：晚到的取消会把一条成功的任务写成失败。
		task, ok := mgr.Get(taskID)
		if !ok || task.Status().Terminal() {
			return
		}
		s.markTimedOut(taskID)
		_ = mgr.Control(taskID, scantask.ControlCancel)
	}()
}

func (s *Server) markTimedOut(taskID string) {
	s.timeoutMu.Lock()
	if s.timeouts == nil {
		s.timeouts = make(map[string]struct{})
	}
	s.timeouts[taskID] = struct{}{}
	s.timeoutMu.Unlock()
}

func (s *Server) timedOut(taskID string) bool {
	s.timeoutMu.Lock()
	_, ok := s.timeouts[taskID]
	s.timeoutMu.Unlock()
	return ok
}

// --- task.list / task.status / task.events / task.control ---

// taskListTool 列出本会话已提交的任务。
func (s *Server) taskListTool() *Tool {
	type args struct {
		Status string `json:"status"`
		Limit  int    `json:"limit"`
	}
	return &Tool{
		Name:        "task.list",
		Title:       "列出任务",
		Description: "只读：列出本服务已受理的扫描/动作任务及其状态（queued/running/completed/failed/cancelled/timeout）、进度、命中数与时间。长任务转成 task_id 句柄后，用它看「有哪些还在跑」。默认按最新在前返回。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"status": map[string]any{"type": "string", "description": "只看某一状态的任务（queued/running/paused/completed/failed/cancelled）；留空为全部"},
				"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": 200, "description": "返回条数上限，默认 50"},
			},
			"required": []string{},
		},
		OutputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tasks": map[string]any{"type": "array", "items": taskViewSchema(), "description": "按最新在前排序；filter 命中不足 limit 时可能更短"},
				"count": map[string]any{"type": "integer", "description": "本次返回的条数"},
			},
			"required": []string{"tasks", "count"},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			if err := s.gate.Take(policy.Action{Name: "task.list"}, 0); err != nil {
				return nil, err
			}
			mgr, err := s.taskManager()
			if err != nil {
				return nil, err
			}

			limit := a.Limit
			if limit <= 0 {
				limit = 50
			}
			if limit > 200 {
				limit = 200
			}
			want := strings.TrimSpace(a.Status)

			snaps := mgr.List()
			tasks := make([]map[string]any, 0, limit)
			// 最新在前：调用方刚拿到的 task_id 总在列表最上面。
			for i := len(snaps) - 1; i >= 0 && len(tasks) < limit; i-- {
				view := s.taskView(snaps[i])
				if want != "" && view["status"] != want {
					continue
				}
				tasks = append(tasks, view)
			}
			return map[string]any{"tasks": tasks, "count": len(tasks)}, nil
		},
	}
}

// taskStatusTool 查一个任务的完整状态。
func (s *Server) taskStatusTool() *Tool {
	type args struct {
		TaskID string `json:"task_id"`
	}
	return &Tool{
		Name:        "task.status",
		Title:       "查看任务状态",
		Description: "只读：按 task_id 返回任务的完整状态——状态、进度、命中统计、收尾汇总（summary，含 executed/found/by_severity/elapsed_ms）、错误原因与时间。长任务转成句柄后，靠它判断「跑完没有、结论是什么」；completed 之后 summary/hits 就是最终结论。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"task_id": map[string]any{"type": "string", "description": "scan.start / act.brute 返回的 task_id"},
			},
			"required": []string{"task_id"},
		},
		OutputSchema: taskViewSchema(),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			taskID := strings.TrimSpace(a.TaskID)
			if taskID == "" {
				return nil, fmt.Errorf("task_id is required")
			}
			if err := s.gate.Take(policy.Action{Name: "task.status"}, 0); err != nil {
				return nil, err
			}
			mgr, err := s.taskManager()
			if err != nil {
				return nil, err
			}
			snap := s.snapshotOf(mgr, taskID)
			if snap == nil {
				return nil, fmt.Errorf("task not found: %s", taskID)
			}
			return s.taskView(snap), nil
		},
	}
}

// taskEventsTool 按 last_seq 增量拉取任务事件（拉取式，不保持通道）。
//
// 它是 Subscribe 的对偶：MCP 的 Streamable HTTP 是一次 POST 一问一答、没有服务端
// 推送流，所以「看任务跑到哪了」只能靠调用方主动来拉。调用方每次带上上次拿到的
// last_seq，即可只取增量、不重不漏。
func (s *Server) taskEventsTool() *Tool {
	type args struct {
		TaskID  string `json:"task_id"`
		FromSeq uint64 `json:"from_seq"`
		Limit   int    `json:"limit"`
	}
	return &Tool{
		Name:        "task.events",
		Title:       "拉取任务事件",
		Description: "只读：按 from_seq 增量拉取任务事件（seq 大于 from_seq 的），并带回当前状态。放进来的 last_seq 下次原样当 from_seq 传回，即可只取新增事件。事件类型：status/scan_info/progress/phase/result/port/webprobe/host/log/done/error。它不建立长连接，因此在没有服务端推送的传输（Streamable HTTP）下也能观察长任务。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"task_id":  map[string]any{"type": "string", "description": "scan.start / act.brute 返回的 task_id"},
				"from_seq": map[string]any{"type": "integer", "minimum": 0, "description": "只取 seq 大于它的增量；首次传 0，之后传上次返回的 last_seq"},
				"limit":    map[string]any{"type": "integer", "minimum": 1, "maximum": 1000, "description": "单次最多返回条数，默认 200"},
			},
			"required": []string{"task_id"},
		},
		OutputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"task_id":       map[string]any{"type": "string"},
				"status":        map[string]any{"type": "string", "description": "拉取时的任务状态"},
				"events":        map[string]any{"type": "array", "items": eventSchema()},
				"count":         map[string]any{"type": "integer", "description": "本批条数"},
				"last_seq":      map[string]any{"type": "integer", "description": "本批最后一条事件的 seq，下次原样作为 from_seq"},
				"has_more":      map[string]any{"type": "boolean", "description": "为 true 表示还有没返回的事件，需继续拉"},
				"done":          map[string]any{"type": "boolean", "description": "任务已到终态（completed/failed/cancelled/timeout）；此时再拉不会再有新事件"},
				"truncated":     map[string]any{"type": "boolean", "description": "更早的事件已被缓冲淘汰；只有从 buffered_from 起才拿得到"},
				"buffered_from": map[string]any{"type": "integer", "description": "缓冲区里仍保留的最早 seq"},
			},
			"required": []string{"task_id", "status", "events", "count", "last_seq", "has_more", "done"},
		},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			taskID := strings.TrimSpace(a.TaskID)
			if taskID == "" {
				return nil, fmt.Errorf("task_id is required")
			}
			if err := s.gate.Take(policy.Action{Name: "task.events"}, 0); err != nil {
				return nil, err
			}
			mgr, err := s.taskManager()
			if err != nil {
				return nil, err
			}

			limit := a.Limit
			if limit <= 0 {
				limit = taskEventLimit
			}
			if limit > 1000 {
				limit = 1000
			}

			events, snap, err := mgr.Events(taskID, a.FromSeq)
			if err != nil {
				return nil, fmt.Errorf("task not found: %s", taskID)
			}

			hasMore := len(events) > limit
			if hasMore {
				events = events[:limit]
			}

			lastSeq := a.FromSeq
			items := make([]map[string]any, 0, len(events))
			for _, ev := range events {
				items = append(items, eventView(ev))
				lastSeq = ev.Seq
			}

			out := map[string]any{
				"task_id":  taskID,
				"status":   s.scanStatus(taskID, snap.Status),
				"events":   items,
				"count":    len(items),
				"last_seq": lastSeq,
				"has_more": hasMore,
				"done":     snap.Status.Terminal(),
			}
			if snap.Truncated {
				out["truncated"] = true
			}
			if snap.BufferedFrom > 0 {
				out["buffered_from"] = snap.BufferedFrom
			}
			return out, nil
		},
	}
}

// taskControlTool 对任务执行取消/暂停/恢复。
func (s *Server) taskControlTool() *Tool {
	type args struct {
		TaskID string `json:"task_id"`
		Action string `json:"action"`
	}
	return &Tool{
		Name:        "task.control",
		Title:       "控制任务",
		Description: "对指定任务执行取消（cancel）/暂停（pause）/恢复（resume），返回控制后的最新状态。长任务跑偏了或已经不需要了，用它及时止损、释放并发名额。注意：暂停/恢复依赖子进程支持，不支持时如实报错，不会假装成功；取消对排队中与运行中的任务都有效。",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"task_id": map[string]any{"type": "string", "description": "scan.start / act.brute 返回的 task_id"},
				"action":  map[string]any{"type": "string", "enum": []string{"cancel", "pause", "resume"}, "description": "控制动作"},
			},
			"required": []string{"task_id", "action"},
		},
		OutputSchema: taskControlSchema(),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a args
			if err := decodeArgs(raw, &a); err != nil {
				return nil, err
			}
			taskID := strings.TrimSpace(a.TaskID)
			if taskID == "" {
				return nil, fmt.Errorf("task_id is required")
			}
			action, ok := taskControlAction(a.Action)
			if !ok {
				return nil, fmt.Errorf("unknown action %q: want cancel, pause or resume", a.Action)
			}
			if err := s.gate.Take(policy.Action{Name: "task.control"}, 0); err != nil {
				return nil, err
			}
			mgr, err := s.taskManager()
			if err != nil {
				return nil, err
			}
			if _, found := mgr.Get(taskID); !found {
				return nil, fmt.Errorf("task not found: %s", taskID)
			}
			if err := mgr.Control(taskID, action); err != nil {
				return nil, err
			}
			view := s.taskView(s.snapshotOf(mgr, taskID))
			if view == nil {
				view = map[string]any{"task_id": taskID}
			}
			view["action"] = action.String()
			return view, nil
		},
	}
}

// taskControlAction 把入参的动作名翻成控制面枚举。
func taskControlAction(name string) (scantask.ControlAction, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "cancel":
		return scantask.ControlCancel, true
	case "pause":
		return scantask.ControlPause, true
	case "resume":
		return scantask.ControlResume, true
	default:
		return 0, false
	}
}

// taskView 把控制面快照整理成工具返回：字段名与 tool 面其它工具保持一致，
// 时间统一用 RFC3339（零值不输出）。
func (s *Server) taskView(snap *scantask.Snapshot) map[string]any {
	if snap == nil {
		return nil
	}
	out := map[string]any{
		"task_id":   snap.ID,
		"status":    s.scanStatus(snap.ID, snap.Status),
		"targets":   snap.Targets,
		"hits":      snap.Hits,
		"hit_total": snap.HitTotal,
		"last_seq":  snap.LastSeq,
		"pausable":  snap.Pausable,
		"progress": map[string]any{
			"percent":    snap.Progress.Percent,
			"finished":   snap.Progress.Finished,
			"total":      snap.Progress.Total,
			"rate":       snap.Progress.Rate,
			"elapsed_ms": snap.Progress.ElapsedMs,
		},
	}
	if snap.Name != "" {
		out["name"] = snap.Name
	}
	if !snap.CreatedAt.IsZero() {
		out["created_at"] = snap.CreatedAt.Format(time.RFC3339)
	}
	if !snap.StartedAt.IsZero() {
		out["started_at"] = snap.StartedAt.Format(time.RFC3339)
	}
	if !snap.EndedAt.IsZero() {
		out["ended_at"] = snap.EndedAt.Format(time.RFC3339)
	}
	if snap.ScanInfo.TotalScans > 0 {
		out["scan_info"] = map[string]any{
			"total_targets": snap.ScanInfo.TotalTargets,
			"total_pocs":    snap.ScanInfo.TotalPocs,
			"total_scans":   snap.ScanInfo.TotalScans,
			"oob_enabled":   snap.ScanInfo.OOBEnabled,
			"oob_status":    snap.ScanInfo.OOBStatus,
		}
	}
	if snap.Summary != nil {
		out["summary"] = map[string]any{
			"executed":    snap.Summary.Executed,
			"found":       snap.Summary.Found,
			"by_severity": snap.Summary.BySeverity,
			"elapsed_ms":  snap.Summary.ElapsedMs,
		}
	}
	if snap.Error != "" {
		out["error"] = snap.Error
	}
	return out
}

// taskViewSchema 是 taskView 的对外契约，供 task.list / task.status / task.control 共用：
// 三个工具返回的都是同一份「任务视图」，字段只有一处定义，免得其中一个加了字段、
// 另两个的契约悄悄落后。只在收尾/上报后才出现的字段一律不进 required。
func taskViewSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"task_id":   map[string]any{"type": "string"},
			"status":    map[string]any{"type": "string", "description": "queued / running / paused / completed / failed / cancelled / timeout"},
			"targets":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"progress": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"percent":    map[string]any{"type": "integer"},
					"finished":   map[string]any{"type": "integer"},
					"total":      map[string]any{"type": "integer"},
					"rate":       map[string]any{"type": "integer"},
					"elapsed_ms": map[string]any{"type": "integer"},
				},
			},
			"hits":       map[string]any{"type": "object", "description": "按严重级别的命中数"},
			"hit_total":  map[string]any{"type": "integer"},
			"pausable":   map[string]any{"type": "boolean", "description": "该任务是否支持暂停/恢复"},
			"last_seq":   map[string]any{"type": "integer", "description": "已产生事件的最大 seq，供 task.events 增量拉取"},
			"summary":    map[string]any{"type": "object", "description": "收尾汇总：executed / found / by_severity / elapsed_ms；未收尾时不出现"},
			"scan_info":  map[string]any{"type": "object", "description": "total_targets / total_pocs / total_scans / oob_enabled / oob_status；引擎上报前不出现"},
			"name":       map[string]any{"type": "string", "description": "任务名；未命名时不出现"},
			"created_at": map[string]any{"type": "string", "description": "RFC3339；未受理前不出现"},
			"started_at": map[string]any{"type": "string", "description": "RFC3339；未开始前不出现"},
			"ended_at":   map[string]any{"type": "string", "description": "RFC3339；未收尾时不出现"},
			"error":      map[string]any{"type": "string", "description": "失败/超时的原因；正常收尾不出现"},
		},
		"required": []string{"task_id", "status"},
	}
}

// taskControlSchema 在任务视图上补一个 action：控制类工具要能看出「这次做了什么」。
func taskControlSchema() map[string]any {
	schema := taskViewSchema()
	schema["properties"].(map[string]any)["action"] = map[string]any{
		"type": "string", "enum": []string{"cancel", "pause", "resume"}, "description": "本次执行的控制动作",
	}
	schema["required"] = []string{"task_id", "status", "action"}
	return schema
}

// eventSchema 是事件信封的契约：seq / ts_ms / type 恒在，其余按 type 取对应载荷。
// 各载荷的内部结构差异很大（命中、端口、进度各有各的字段），这里只声明「有哪些载荷槽」，
// 不展开到每个槽的内部——展开只会写出一个跟不上 scanstream 演进的假契约。
func eventSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"seq":       map[string]any{"type": "integer"},
			"ts_ms":     map[string]any{"type": "integer"},
			"type":      map[string]any{"type": "string", "enum": []string{"status", "scan_info", "progress", "phase", "result", "port", "webprobe", "host", "log", "done", "error"}},
			"status":    map[string]any{"type": "object", "description": "type=status 时的载荷"},
			"scan_info": map[string]any{"type": "object", "description": "type=scan_info 时的载荷"},
			"progress":  map[string]any{"type": "object", "description": "type=progress 时的载荷"},
			"phase":     map[string]any{"type": "object", "description": "type=phase 时的载荷"},
			"result":    map[string]any{"type": "object", "description": "type=result 时的命中（poc_id / severity / target 等）"},
			"port":      map[string]any{"type": "object", "description": "type=port 时的载荷"},
			"webprobe":  map[string]any{"type": "object", "description": "type=webprobe 时的载荷"},
			"host":      map[string]any{"type": "object", "description": "type=host 时的载荷"},
			"log":       map[string]any{"type": "object", "description": "type=log 时的载荷"},
			"done":      map[string]any{"type": "object", "description": "type=done 时的收尾（status / summary）"},
			"error":     map[string]any{"type": "object", "description": "type=error 时的载荷"},
		},
		"required": []string{"seq", "ts_ms", "type"},
	}
}

// eventView 把一条事件整理成对外的扁平结构：信封字段 + type + 对应载荷。
func eventView(ev *scanstream.Event) map[string]any {
	out := map[string]any{
		"seq":   ev.Seq,
		"ts_ms": ev.TsMs,
		"type":  ev.Type,
	}
	// 载荷字段名与 scanstream.Event 的 JSON 键一一对应，调用方按 type 取值即可。
	switch {
	case ev.Status != nil:
		out["status"] = ev.Status
	case ev.ScanInfo != nil:
		out["scan_info"] = ev.ScanInfo
	case ev.Progress != nil:
		out["progress"] = ev.Progress
	case ev.Phase != nil:
		out["phase"] = ev.Phase
	case ev.Result != nil:
		out["result"] = ev.Result
	case ev.Port != nil:
		out["port"] = ev.Port
	case ev.WebProbe != nil:
		out["webprobe"] = ev.WebProbe
	case ev.Host != nil:
		out["host"] = ev.Host
	case ev.Log != nil:
		out["log"] = ev.Log
	case ev.Done != nil:
		out["done"] = ev.Done
	case ev.Error != nil:
		out["error"] = ev.Error
	}
	return out
}
