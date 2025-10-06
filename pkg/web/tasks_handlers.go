package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

type apiResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, payload apiResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// POST /api/pocs/tasks
func pocsTasksCreateHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PocID   string      `json:"poc_id"`
		PocIDs  []string    `json:"poc_ids"` // 新增：支持多个 POC
		Targets []string    `json:"targets"`
		Options TaskOptions `json:"options"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "请求体无效"})
		return
	}

	// 统一整理 POC IDs：优先使用 poc_ids；否则使用 poc_id（单个）
	var pids []string
	if len(req.PocIDs) > 0 {
		for _, s := range req.PocIDs {
			ps := strings.TrimSpace(s)
			if ps != "" {
				pids = append(pids, ps)
			}
		}
	} else if strings.TrimSpace(req.PocID) != "" {
		pids = []string{strings.TrimSpace(req.PocID)}
	}
	if len(pids) == 0 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "poc_ids 不能为空"})
		return
	}

	tm := EnsureTaskManager()
	task, err := tm.CreateTask(pids, req.Targets, req.Options)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Message: "任务已创建",
		Data: map[string]any{
			"task_id": task.ID,
			"status":  task.Status,
		},
	})
}

// GET /api/pocs/tasks/{id}
func pocsTasksGetHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := strings.TrimSpace(vars["id"])
	if taskID == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "task_id 不能为空"})
		return
	}
	tm := EnsureTaskManager()
	task, err := tm.GetTask(taskID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, apiResponse{Success: false, Message: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Message: "ok",
		Data: map[string]any{
			"task_id":           task.ID,
			"status":            task.Status,
			"total_targets":     task.TotalTargets,
			"completed_targets": task.CompletedTargets,
			"last_heartbeat":    task.LastHeartbeat.Format(time.RFC3339),
		},
	})
}

// GET /api/pocs/tasks/{id}/stream
func pocsTasksStreamHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := strings.TrimSpace(vars["id"])
	if taskID == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "task_id 不能为空"})
		return
	}

	// SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	tm := EnsureTaskManager()
	sub, cancel := tm.Subscribe(taskID)
	defer cancel()

	// initial heartbeat
	fmtWriteSSE(w, "heartbeat", map[string]string{"ts": time.Now().Format(time.RFC3339)})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	notify := r.Context().Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-notify:
			return
		case evt := <-sub:
			fmtWriteSSE(w, evt.Type, evt.Data)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-ticker.C:
			fmtWriteSSE(w, "heartbeat", map[string]string{"ts": time.Now().Format(time.RFC3339)})
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}
}

func fmtWriteSSE(w http.ResponseWriter, event string, data interface{}) {
	w.Write([]byte("event: " + event + "\n"))
	js, _ := json.Marshal(data)
	w.Write([]byte("data: " + string(js) + "\n\n"))
}

// POST /api/pocs/tasks/{id}/cancel
func pocsTasksCancelHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := strings.TrimSpace(vars["id"])
	if taskID == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "task_id 不能为空"})
		return
	}
	tm := EnsureTaskManager()
	if err := tm.Cancel(taskID); err != nil {
		writeJSON(w, http.StatusNotFound, apiResponse{Success: false, Message: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Message: "已取消", Data: map[string]string{"task_id": taskID, "status": "canceled"}})
}

// POST /api/pocs/tasks/{id}/pause
func pocsTasksPauseHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := strings.TrimSpace(vars["id"])
	if taskID == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "task_id 不能为空"})
		return
	}
	tm := EnsureTaskManager()
	if err := tm.Pause(taskID); err != nil {
		writeJSON(w, http.StatusNotFound, apiResponse{Success: false, Message: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Message: "已暂停", Data: map[string]string{"task_id": taskID, "status": "paused"}})
}

// POST /api/pocs/tasks/{id}/resume
func pocsTasksResumeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := strings.TrimSpace(vars["id"])
	if taskID == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Success: false, Message: "task_id 不能为空"})
		return
	}
	tm := EnsureTaskManager()
	if err := tm.Resume(taskID); err != nil {
		writeJSON(w, http.StatusNotFound, apiResponse{Success: false, Message: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Message: "已恢复", Data: map[string]string{"task_id": taskID, "status": "running"}})
}