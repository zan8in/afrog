package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/gorilla/mux"
	"github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
)

// diffFinding 是差异对比中的一条记录：本次命中 + 上次的命中次数（若两次都有）。
type diffFinding struct {
	VulID        string `json:"vulid"`
	VulName      string `json:"vulname"`
	Target       string `json:"target"`
	FullTarget   string `json:"fulltarget"`
	Severity     string `json:"severity"`
	HitCount     int64  `json:"hit_count"`
	PrevHitCount int64  `json:"prev_hit_count"`
}

// diffCounts 是四分类的数量汇总。
type diffCounts struct {
	New        int `json:"new"`
	Fixed      int `json:"fixed"`
	Persisting int `json:"persisting"`
	Unchanged  int `json:"unchanged"`
}

// diffData 是 /scans/{taskId}/diff 的响应体。
//
// 分类口径（互斥）：
//   - new        本次命中、上次未命中
//   - fixed      上次命中、本次未命中
//   - persisting 两次都命中，且命中次数或严重级别发生变化
//   - unchanged  两次都命中，且命中次数与严重级别完全一致
type diffData struct {
	TaskID     string        `json:"task_id"`
	ProjectID  string        `json:"project_id,omitempty"`
	BaseTaskID string        `json:"base_task_id,omitempty"`
	HasBase    bool          `json:"has_base"`
	Counts     diffCounts    `json:"counts"`
	New        []diffFinding `json:"new"`
	Fixed      []diffFinding `json:"fixed"`
	Persisting []diffFinding `json:"persisting"`
	Unchanged  []diffFinding `json:"unchanged"`
}

// severityWeight 用于把命中按严重级别从高到低排序。
var severityWeight = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
}

func sortFindings(items []diffFinding) {
	sort.SliceStable(items, func(i, j int) bool {
		wi := severityWeight[strings.ToLower(items[i].Severity)]
		wj := severityWeight[strings.ToLower(items[j].Severity)]
		if wi != wj {
			return wi > wj
		}
		if items[i].VulID != items[j].VulID {
			return items[i].VulID < items[j].VulID
		}
		return items[i].Target < items[j].Target
	})
}

// findingKey 是差异对比的最小单元：PoC + 目标主键。
// 不带 fulltarget，避免同一目标上 URL 参数的波动造成误判为「新增」。
func findingKey(vulid, target string) string {
	return vulid + "\x00" + target
}

// scanDiffHandler 返回某次扫描与其「上一次扫描」的差异。
//
// 基准任务的选择顺序：
//  1. 显式传入 ?against=<taskId>
//  2. 同一项目下、时间上早于当前任务的最近一次任务
//
// 两者都取不到时返回 has_base=false，前端据此展示空状态。
func scanDiffHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	taskID := strings.TrimSpace(mux.Vars(r)["taskId"])
	if taskID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少任务ID"})
		return
	}

	projectID, err := sqlite.SelectTaskProject(taskID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "读取任务归属失败"})
		return
	}

	baseTaskID := strings.TrimSpace(r.URL.Query().Get("against"))
	if baseTaskID == "" && projectID != "" {
		baseTaskID, err = sqlite.SelectPreviousProjectTask(projectID, taskID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "查找历史任务失败"})
			return
		}
	}
	if baseTaskID == taskID {
		baseTaskID = ""
	}

	current, err := sqlite.SelectTaskFindings(taskID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "读取本次扫描结果失败"})
		return
	}

	data := diffData{
		TaskID:     taskID,
		ProjectID:  projectID,
		BaseTaskID: baseTaskID,
		HasBase:    baseTaskID != "",
		New:        make([]diffFinding, 0, len(current)),
		Fixed:      make([]diffFinding, 0),
		Persisting: make([]diffFinding, 0),
		Unchanged:  make([]diffFinding, 0),
	}

	var base []db.TaskFinding
	if data.HasBase {
		base, err = sqlite.SelectTaskFindings(baseTaskID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "读取历史扫描结果失败"})
			return
		}
	}

	baseIndex := make(map[string]db.TaskFinding, len(base))
	for _, f := range base {
		baseIndex[findingKey(f.VulID, f.Target)] = f
	}

	seen := make(map[string]bool, len(current))
	for _, f := range current {
		key := findingKey(f.VulID, f.Target)
		seen[key] = true

		cur := diffFinding{
			VulID:      f.VulID,
			VulName:    f.VulName,
			Target:     f.Target,
			FullTarget: f.FullTarget,
			Severity:   f.Severity,
			HitCount:   f.HitCount,
		}

		prev, ok := baseIndex[key]
		if !ok {
			data.New = append(data.New, cur)
			continue
		}

		cur.PrevHitCount = prev.HitCount
		if cur.HitCount == prev.HitCount && strings.EqualFold(cur.Severity, prev.Severity) {
			data.Unchanged = append(data.Unchanged, cur)
		} else {
			data.Persisting = append(data.Persisting, cur)
		}
	}

	for _, f := range base {
		if seen[findingKey(f.VulID, f.Target)] {
			continue
		}
		data.Fixed = append(data.Fixed, diffFinding{
			VulID:        f.VulID,
			VulName:      f.VulName,
			Target:       f.Target,
			FullTarget:   f.FullTarget,
			Severity:     f.Severity,
			HitCount:     0,
			PrevHitCount: 0,
		})
	}

	sortFindings(data.New)
	sortFindings(data.Fixed)
	sortFindings(data.Persisting)
	sortFindings(data.Unchanged)

	data.Counts = diffCounts{
		New:        len(data.New),
		Fixed:      len(data.Fixed),
		Persisting: len(data.Persisting),
		Unchanged:  len(data.Unchanged),
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: data})
}
