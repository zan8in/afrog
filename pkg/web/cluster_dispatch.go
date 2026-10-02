package web

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/mux"
)

// 多实例编排（v2：远程派发 —— 执行节点一侧）。
//
// 发起端用集群共享密钥把一次扫描派发过来；本机作为执行节点跑这次扫描，任务与命中
// 都留在本机（单一数据源），发起端只镜像状态、按需只读拉取命中明细。
//
// 幂等：派发请求带 dispatch_id，同一个 id 重复到达只会起一次扫描。控制台重试或
// 网络抖动造成的重复请求，因此不会变成两次扫描。
//
// 鉴权与 /api/cluster/self 一致：只认集群共享密钥（未配置 token 即关闭该能力），
// 不认 Web 登录态。

// inboundDispatchRequest 是发起端提交的派发请求。
type inboundDispatchRequest struct {
	DispatchID       string            `json:"dispatch_id"`
	OriginInstanceID string            `json:"origin_instance_id"`
	OriginName       string            `json:"origin_name"`
	Request          ScanCreateRequest `json:"request"`
}

// inboundDispatchResponse 返回执行节点上的任务号与展示名。
type inboundDispatchResponse struct {
	TaskID string `json:"task_id"`
	Name   string `json:"name"`
	Node   string `json:"node"`
}

var (
	dispatchMu sync.Mutex
	// dispatchIndex 记录 dispatch_id → 本机 task_id，用于幂等去重。
	// 与任务同生命周期（进程内存态）：进程重启后任务本身也不复存在。
	dispatchIndex = make(map[string]string)
)

// requireClusterToken 校验集群共享密钥，失败时直接写响应并返回 false。
//
// 未配置 token 的实例一律拒绝远程派发：这是一项显式开启的能力，不该因为
// 「恰好配了同伴」而自动对外暴露。
func requireClusterToken(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Content-Type", "application/json")
	cfg, _ := currentClusterConfig()
	expected := strings.TrimSpace(cfg.Token)
	if expected == "" {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "本实例未配置 cluster.token，不接收远程派发"})
		return false
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(r.Header.Get(clusterTokenHeader))), []byte(expected)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "集群令牌不匹配"})
		return false
	}
	return true
}

// clusterInboundDispatchHandler 接收一次远程派发并起扫（幂等）。
func clusterInboundDispatchHandler(w http.ResponseWriter, r *http.Request) {
	if !requireClusterToken(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req inboundDispatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}
	dispatchID := strings.TrimSpace(req.DispatchID)
	if dispatchID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少 dispatch_id"})
		return
	}

	// 幂等：同一个 dispatch_id 只起一次。用一个空串占位来串行化并发重复请求，
	// 起扫失败再回滚占位，让重试能够真正重来。
	dispatchMu.Lock()
	if id, ok := dispatchIndex[dispatchID]; ok && id != "" {
		dispatchMu.Unlock()
		writeInboundDispatchOK(w, id)
		return
	}
	if _, inflight := dispatchIndex[dispatchID]; inflight {
		dispatchMu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "starting", Data: inboundDispatchResponse{}})
		return
	}
	dispatchIndex[dispatchID] = ""
	dispatchMu.Unlock()

	id, _, err := launchScan(req.Request, scanOrigin{
		Source:           scanSourceRemote,
		DispatchID:       dispatchID,
		OriginInstanceID: strings.TrimSpace(req.OriginInstanceID),
		OriginName:       strings.TrimSpace(req.OriginName),
	})
	if err != nil {
		dispatchMu.Lock()
		delete(dispatchIndex, dispatchID)
		dispatchMu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
		return
	}

	dispatchMu.Lock()
	dispatchIndex[dispatchID] = id
	dispatchMu.Unlock()
	writeInboundDispatchOK(w, id)
}

func writeInboundDispatchOK(w http.ResponseWriter, taskID string) {
	name := ""
	if t := findTask(taskID); t != nil {
		name = t.Name
	}
	cfg, _ := currentClusterConfig()
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "started", Data: inboundDispatchResponse{
		TaskID: taskID,
		Name:   name,
		Node:   strings.TrimSpace(cfg.Name),
	}})
}

// clusterInboundTaskStatusHandler 返回执行节点上的任务状态，供发起端对账。
func clusterInboundTaskStatusHandler(w http.ResponseWriter, r *http.Request) {
	if !requireClusterToken(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}
	taskID := strings.TrimSpace(mux.Vars(r)["taskId"])
	t := findTask(taskID)
	if t == nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "任务不存在"})
		return
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: remoteStatusOf(t)})
}

// clusterInboundTaskStopHandler 停止执行节点上的一个任务。
func clusterInboundTaskStopHandler(w http.ResponseWriter, r *http.Request) {
	if !requireClusterToken(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}
	taskID := strings.TrimSpace(mux.Vars(r)["taskId"])
	if ok, msg := stopTaskByID(taskID); !ok {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: msg})
		return
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "stopped", Data: map[string]bool{"stopped": true}})
}

// clusterInboundTaskFindingsHandler 以只读方式返回某个任务的命中明细。
//
// 复用本机 /reports 的查询实现，保证发起端代理回来的结构与本地报告页完全一致；
// 默认不展开大字段（PocInfo / ResultList），详情由前端按需再取。
func clusterInboundTaskFindingsHandler(w http.ResponseWriter, r *http.Request) {
	if !requireClusterToken(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	taskID := strings.TrimSpace(mux.Vars(r)["taskId"])
	q := r.URL.Query()
	keyword := strings.TrimSpace(q.Get("keyword"))
	severityParam := normalizeSeverityParam(q.Get("severity"))
	page := positiveIntParam(q.Get("page"), 1)
	pageSize := positiveIntParam(q.Get("page_size"), 50)
	if pageSize > 500 {
		pageSize = 500
	}

	data, err := queryReportList(taskID, severityParam, keyword, splitSeverity(severityParam), page, pageSize, false, false, false)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: data})
}

// normalizeSeverityParam 把 "High, critical" 归一化成 "high,critical"。
func normalizeSeverityParam(raw string) string {
	return strings.Join(splitSeverity(raw), ",")
}

func splitSeverity(raw string) []string {
	out := make([]string, 0, 5)
	for _, s := range strings.Split(raw, ",") {
		if v := strings.ToLower(strings.TrimSpace(s)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func positiveIntParam(raw string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}
