package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/notify"
	"github.com/zan8in/gologger"
)

// 通知集成是 Curated 会员能力：配置读写与测试发送都在这里统一做会员校验。
// 配置常驻内存（启动时从磁盘加载，保存后回写内存），扫描热路径上不读文件。

var (
	notifierOnce sync.Once
	notifierInst *notify.Notifier
)

// getNotifier 返回全局通知器；首次调用时从磁盘加载配置。
func getNotifier() *notify.Notifier {
	notifierOnce.Do(func() {
		notifierInst = notify.NewNotifier()
		// 按项目订阅需要「任务 → 项目」的归属查询；notify 包不依赖数据库，由这里注入，
		// 未归属任何项目的任务返回空串，由白名单逻辑决定是否放行。
		notifierInst.SetProjectResolver(func(taskID string) string {
			pid, err := sqlite.SelectTaskProject(taskID)
			if err != nil {
				return ""
			}
			return pid
		})
		cfg, err := notify.Load()
		if err != nil {
			// 配置坏了不该拦住扫描，退化为「不发送」并留下告警。
			gologger.Warning().Msgf("load notifications config failed: %v", err)
			return
		}
		notifierInst.SetConfig(cfg)
	})
	return notifierInst
}

// notificationsGetHandler 返回通知配置。
func notificationsGetHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	_ = json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "ok",
		Data:    getNotifier().Config(),
	})
}

// notificationsSaveHandler 保存通知配置。
//
// 保存后重新读回并返回：normalize 会给新渠道补 ID、收敛数值范围，
// 前端需要拿到这份「落库后的真实配置」才能保持渠道 ID 稳定。
func notificationsSaveHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持PUT方法"})
		return
	}

	var cfg notify.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}

	if err := notify.Save(cfg); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "通知配置保存失败"})
		return
	}

	saved, err := notify.Load()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "通知配置读取失败"})
		return
	}
	getNotifier().SetConfig(saved)

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "已保存", Data: saved})
}

type notifyTestRequest struct {
	// ChannelID 为空时对全部已启用渠道发送。
	ChannelID string `json:"channel_id"`
}

// notificationsTestHandler 发送一条测试消息并同步返回每个渠道的结果。
func notificationsTestHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	var req notifyTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}

	// 给整个测试一个上限，避免多个渠道串行卡住请求。
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	results, err := getNotifier().Test(ctx, req.ChannelID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
		return
	}

	_ = json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "ok",
		Data:    map[string]any{"results": results},
	})
}

// notificationsLogsHandler 返回最近的发送记录与成功/失败汇总。
//
// 通知是「配完就忘」的功能，用户最大的不安是「到底发出去没有」；
// 这个接口就是回答这个问题的：每条记录带渠道、结果、尝试次数与失败原因。
func notificationsLogsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	limit := 50
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}

	items, stats := getNotifier().RecentDeliveries(limit)
	_ = json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "ok",
		Data:    map[string]any{"items": items, "stats": stats},
	})
}

// notificationsResendHandler 手动重发某条历史记录（自动重试仍失败后的补发）。
func notificationsResendHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}
	if req.ID <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少id"})
		return
	}

	rec, err := getNotifier().Resend(req.ID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: rec})
}

// notifyTaskDone 在任务收尾后按配置推送汇总或异常提醒。
func notifyTaskDone(t *Task) {
	if t == nil {
		return
	}

	stats := t.severitySnapshot()
	res := notify.TaskResult{
		TaskName:   t.Name,
		Targets:    t.getTargets(),
		Status:     string(t.Status()),
		Err:        t.errMessage(),
		Hits:       t.hitCount(),
		BySeverity: stats,
	}
	if p := t.getProgress(); p != nil {
		res.Scans = int(p.Finished)
	}
	if started := t.started(); !started.IsZero() {
		res.Elapsed = time.Since(started)
	}

	getNotifier().OnTaskDone(t.ID, res)
}
