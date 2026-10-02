package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
)

// 多实例编排（v2：远程派发 —— 发起端一侧）。
//
// 本机把一次扫描派发给某个同伴执行。真正的任务与命中都留在执行节点（单一数据源），
// 本机只保存一条「影子记录」：节点、远端任务号、镜像状态。任务列表把影子记录并入，
// 命中明细按需只读代理拉取。
//
// 断连一致性：dispatch_id 幂等（重试不会起两次）；联系不上执行节点时只把 node_ok
// 置 false 并记下原因，状态保留最后一次成功对账的结果，不误判为失败；节点恢复后
// 由后台对账按远端任务号收敛。

// clusterTaskStatus 是任务的跨节点状态快照：执行节点返回它，发起端镜像它。
type clusterTaskStatus struct {
	TaskID   string           `json:"task_id"`
	Name     string           `json:"name"`
	Status   string           `json:"status"`
	Source   string           `json:"source"`
	Node     string           `json:"node,omitempty"`
	Progress ScanProgressData `json:"progress"`
	Error    string           `json:"error,omitempty"`
	Hits     map[string]int   `json:"hits,omitempty"`
	HitTotal int              `json:"hit_total"`
	Targets  []string         `json:"targets,omitempty"`
	Created  string           `json:"created_at,omitempty"`
	Started  string           `json:"started_at,omitempty"`
	Ended    string           `json:"ended_at,omitempty"`
}

// remoteStatusOf 组装本机任务的跨节点状态快照，供发起端对账。
func remoteStatusOf(t *Task) clusterTaskStatus {
	item := t.listItem()
	return clusterTaskStatus{
		TaskID:   item.TaskID,
		Name:     item.Name,
		Status:   item.Status,
		Source:   item.Source,
		Node:     localNodeName(),
		Progress: item.Progress,
		Error:    item.Error,
		Hits:     item.Hits,
		HitTotal: item.HitTotal,
		Targets:  item.Targets,
		Created:  item.CreatedAt,
		Started:  item.StartedAt,
		Ended:    item.EndedAt,
	}
}

// remoteTask 是发起端的影子记录。字段只在 mu 保护下读写。
type remoteTask struct {
	ID         string // 本机影子任务号（列表与详情都用它）
	DispatchID string // 幂等键
	NodeName   string
	NodeURL    string
	// RemoteTaskID 是执行节点上的任务号；拿到之前只能靠重试派发收敛。
	RemoteTaskID string
	Name         string
	Status       string
	Progress     ScanProgressData
	Error        string
	Hits         map[string]int
	HitTotal     int
	Targets      []string
	CreatedAt    string
	StartedAt    string
	EndedAt      string
	// NodeOK 是最近一次能否联系上执行节点。false 时 Status 仍是最后一次成功对账的结果。
	NodeOK   bool
	LastSeen time.Time

	// request 保留原始派发请求，供「还没拿到远端任务号」时幂等重试。
	request ScanCreateRequest

	mu sync.Mutex
}

var remoteStore = struct {
	mu    sync.Mutex
	items map[string]*remoteTask
	order []string
}{items: make(map[string]*remoteTask)}

func addRemoteTask(rt *remoteTask) {
	remoteStore.mu.Lock()
	defer remoteStore.mu.Unlock()
	remoteStore.items[rt.ID] = rt
	remoteStore.order = append(remoteStore.order, rt.ID)
}

func getRemoteTask(id string) *remoteTask {
	remoteStore.mu.Lock()
	defer remoteStore.mu.Unlock()
	return remoteStore.items[strings.TrimSpace(id)]
}

func removeRemoteTask(id string) {
	remoteStore.mu.Lock()
	defer remoteStore.mu.Unlock()
	delete(remoteStore.items, id)
}

func remoteTaskSnapshot() []*remoteTask {
	remoteStore.mu.Lock()
	defer remoteStore.mu.Unlock()
	out := make([]*remoteTask, 0, len(remoteStore.order))
	for _, id := range remoteStore.order {
		if rt, ok := remoteStore.items[id]; ok {
			out = append(out, rt)
		}
	}
	return out
}

// remoteTaskItem 把影子记录转成任务列表项。node_ok / node_name 让前端标出节点与失联。
func remoteTaskItem(rt *remoteTask) scanListItem {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return scanListItem{
		TaskID:    rt.ID,
		Name:      rt.Name,
		Status:    rt.Status,
		Source:    scanSourceRemote,
		NodeName:  rt.NodeName,
		NodeOK:    rt.NodeOK,
		Targets:   append([]string(nil), rt.Targets...),
		CreatedAt: rt.CreatedAt,
		StartedAt: rt.StartedAt,
		EndedAt:   rt.EndedAt,
		Progress:  rt.Progress,
		Hits:      rt.Hits,
		HitTotal:  rt.HitTotal,
		Error:     rt.Error,
	}
}

// remoteScanItems 把全部影子记录并入 /api/scans 列表。
func remoteScanItems() []scanListItem {
	snap := remoteTaskSnapshot()
	out := make([]scanListItem, 0, len(snap))
	for _, rt := range snap {
		out = append(out, remoteTaskItem(rt))
	}
	return out
}

// -----------------------
// 后台对账
// -----------------------

var (
	remoteReconcileOnce sync.Once
	remoteHTTPClient    = &http.Client{Timeout: 15 * time.Second}
	remoteReconcileTick = 10 * time.Second
)

// startRemoteReconciler 懒启动对账协程：第一次派发时才起，进程内只起一次。
func startRemoteReconciler() {
	remoteReconcileOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(remoteReconcileTick)
			defer ticker.Stop()
			for range ticker.C {
				for _, rt := range remoteTaskSnapshot() {
					_ = reconcileRemoteTask(rt)
				}
			}
		}()
	})
}

// reconcileRemoteTask 让影子记录向执行节点的真实状态收敛。
//
// 三种情况：还没拿到远端任务号（幂等重试派发）、已拿到（拉状态）、已经终态（不再轮询）。
func reconcileRemoteTask(rt *remoteTask) error {
	rt.mu.Lock()
	if isTerminalRemoteStatus(rt.Status) {
		rt.mu.Unlock()
		return nil
	}
	nodeURL, remoteID, dispatchID, scanReq := rt.NodeURL, rt.RemoteTaskID, rt.DispatchID, rt.request
	rt.mu.Unlock()

	peer, ok := findClusterPeer(nodeURL)
	if !ok {
		markRemoteUnreachable(rt, "执行节点已不在集群配置中")
		return fmt.Errorf("peer not configured: %s", nodeURL)
	}
	token := clusterToken()

	if remoteID == "" {
		taskID, name, hardMsg, softMsg := postRemoteDispatch(peer, token, dispatchID, scanReq)
		if hardMsg != "" {
			markRemoteSettled(rt, string(TaskFailed), hardMsg)
			return nil
		}
		if taskID == "" {
			markRemoteUnreachable(rt, softMsg)
			return fmt.Errorf("dispatch retry pending: %s", softMsg)
		}
		rt.mu.Lock()
		rt.RemoteTaskID = taskID
		if name != "" {
			rt.Name = name
		}
		rt.NodeOK = true
		rt.Error = ""
		rt.mu.Unlock()
	}

	st, err := fetchRemoteStatus(peer, token, rt.RemoteTaskID)
	if err != nil {
		markRemoteUnreachable(rt, err.Error())
		return err
	}
	applyRemoteStatus(rt, st)
	return nil
}

func isTerminalRemoteStatus(s string) bool {
	switch s {
	case string(TaskCompleted), string(TaskFailed), string(TaskCancelled):
		return true
	}
	return false
}

// markRemoteUnreachable 只标记「联系不上」：保留最后一次成功对账的状态，
// 不把它改写成失败——节点恢复后还要继续收敛。
func markRemoteUnreachable(rt *remoteTask, msg string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.NodeOK = false
	rt.Error = strings.TrimSpace(msg)
	if strings.TrimSpace(rt.Status) == "" {
		rt.Status = string(TaskStarting)
	}
}

// markRemoteSettled 记录执行节点明确给出的终态（例如参数被拒绝）。
func markRemoteSettled(rt *remoteTask, status, msg string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.Status = status
	rt.Error = strings.TrimSpace(msg)
	rt.NodeOK = true
}

func applyRemoteStatus(rt *remoteTask, st clusterTaskStatus) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if strings.TrimSpace(st.Status) != "" {
		rt.Status = st.Status
	}
	if strings.TrimSpace(st.Name) != "" {
		rt.Name = st.Name
	}
	rt.Progress = st.Progress
	rt.Error = strings.TrimSpace(st.Error)
	rt.Hits = st.Hits
	rt.HitTotal = st.HitTotal
	if len(st.Targets) > 0 {
		rt.Targets = append([]string(nil), st.Targets...)
	}
	if st.Started != "" {
		rt.StartedAt = st.Started
	}
	if st.Ended != "" {
		rt.EndedAt = st.Ended
	}
	rt.NodeOK = true
	rt.LastSeen = time.Now()
}

// -----------------------
// 与执行节点通信
// -----------------------

func findClusterPeer(nodeURL string) (config.ClusterPeer, bool) {
	reg := activeClusterRegistry()
	if reg == nil {
		return config.ClusterPeer{}, false
	}
	for _, p := range reg.peers {
		if p.URL == nodeURL {
			return p, true
		}
	}
	return config.ClusterPeer{}, false
}

func clusterToken() string {
	if reg := activeClusterRegistry(); reg != nil && strings.TrimSpace(reg.token) != "" {
		return strings.TrimSpace(reg.token)
	}
	cfg, _ := currentClusterConfig()
	return strings.TrimSpace(cfg.Token)
}

func localNodeName() string {
	cfg, _ := currentClusterConfig()
	if v := strings.TrimSpace(cfg.Name); v != "" {
		return v
	}
	return serverInstanceID
}

func doClusterGet(target, token string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set(clusterTokenHeader, token)
	}
	return remoteHTTPClient.Do(req)
}

func doClusterPost(target, token string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set(clusterTokenHeader, token)
	}
	return remoteHTTPClient.Do(req)
}

// postRemoteDispatch 把派发请求发给执行节点。
//
// 返回的 hardMsg 表示对方明确拒绝（参数不合法、令牌不对），不该再重试；softMsg
// 表示这次没谈成但值得重试（连不上、对方正在处理同一 dispatch_id）。
func postRemoteDispatch(peer config.ClusterPeer, token, dispatchID string, scanReq ScanCreateRequest) (taskID, name, hardMsg, softMsg string) {
	body, err := json.Marshal(inboundDispatchRequest{
		DispatchID:       dispatchID,
		OriginInstanceID: serverInstanceID,
		OriginName:       localNodeName(),
		Request:          scanReq,
	})
	if err != nil {
		return "", "", "构造派发请求失败：" + err.Error(), ""
	}

	resp, err := doClusterPost(peer.URL+"/api/cluster/inbound/dispatch", token, body)
	if err != nil {
		return "", "", "", "无法连接执行节点：" + err.Error()
	}
	defer resp.Body.Close()

	var out struct {
		Success bool                    `json:"success"`
		Message string                  `json:"message"`
		Data    inboundDispatchResponse `json:"data"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
	msg := strings.TrimSpace(out.Message)

	switch {
	case resp.StatusCode == http.StatusAccepted:
		return "", "", "", "执行节点正在处理该派发，稍后自动重试"
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return "", "", "执行节点拒绝了派发（" + firstNonEmpty(msg, "检查两端的 cluster.token，以及对方是否开启了远程派发") + "）", ""
	case resp.StatusCode >= 400:
		return "", "", "执行节点拒绝：" + firstNonEmpty(msg, fmt.Sprintf("HTTP %d", resp.StatusCode)), ""
	case !out.Success:
		return "", "", "执行节点拒绝：" + firstNonEmpty(msg, "未知原因"), ""
	}
	return out.Data.TaskID, out.Data.Name, "", ""
}

func fetchRemoteStatus(peer config.ClusterPeer, token, remoteTaskID string) (clusterTaskStatus, error) {
	target := peer.URL + "/api/cluster/inbound/tasks/" + url.PathEscape(remoteTaskID)
	resp, err := doClusterGet(target, token)
	if err != nil {
		return clusterTaskStatus{}, fmt.Errorf("无法连接执行节点：%s", err.Error())
	}
	defer resp.Body.Close()

	var out struct {
		Success bool              `json:"success"`
		Message string            `json:"message"`
		Data    clusterTaskStatus `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return clusterTaskStatus{}, fmt.Errorf("执行节点返回内容无法解析")
	}
	if resp.StatusCode != http.StatusOK || !out.Success {
		return clusterTaskStatus{}, fmt.Errorf("执行节点返回：%s", firstNonEmpty(strings.TrimSpace(out.Message), fmt.Sprintf("HTTP %d", resp.StatusCode)))
	}
	return out.Data, nil
}

func firstNonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

func newRemoteTask(peer config.ClusterPeer, scanReq ScanCreateRequest) *remoteTask {
	name := strings.TrimSpace(scanReq.TaskName)
	if name == "" {
		switch {
		case strings.TrimSpace(scanReq.ProjectID) != "":
			name = "远程任务 · 项目 " + strings.TrimSpace(scanReq.ProjectID)
		case len(scanReq.Targets) == 1:
			name = "远程任务 · " + strings.TrimSpace(scanReq.Targets[0])
		case len(scanReq.Targets) > 1:
			name = fmt.Sprintf("远程任务 · %s 等 %d 个目标", strings.TrimSpace(scanReq.Targets[0]), len(scanReq.Targets))
		default:
			name = "远程任务"
		}
	}
	return &remoteTask{
		ID:         nextTaskID(getTaskManager()),
		DispatchID: serverInstanceID + "-" + utils.CreateRandomString(10),
		NodeName:   peer.Name,
		NodeURL:    peer.URL,
		Name:       name,
		Status:     string(TaskStarting),
		Targets:    append([]string(nil), scanReq.Targets...),
		CreatedAt:  time.Now().Format("2006-01-02 15:04:05"),
		request:    scanReq,
	}
}

// -----------------------
// HTTP API（发起端，JWT + Curated）
// -----------------------

// clusterRemoteDispatchHandler 把一次扫描派发给选定节点。
func clusterRemoteDispatchHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		NodeURL string            `json:"node_url"`
		Request ScanCreateRequest `json:"request"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}

	nodeURL := normalizePeerURL(req.NodeURL)
	if nodeURL == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少执行节点地址"})
		return
	}
	peer, ok := findClusterPeer(nodeURL)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "该节点不在集群配置中，请先在「编辑节点」里登记"})
		return
	}
	token := clusterToken()
	if token == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "本实例未配置 cluster.token，无法派发"})
		return
	}

	rt := newRemoteTask(peer, req.Request)
	addRemoteTask(rt)
	startRemoteReconciler()

	taskID, name, hardMsg, softMsg := postRemoteDispatch(peer, token, rt.DispatchID, req.Request)
	if hardMsg != "" {
		removeRemoteTask(rt.ID)
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: hardMsg})
		return
	}

	rt.mu.Lock()
	if taskID != "" {
		rt.RemoteTaskID = taskID
		if name != "" {
			rt.Name = name
		}
		rt.NodeOK = true
	} else {
		rt.NodeOK = false
		rt.Error = softMsg
	}
	rt.mu.Unlock()

	// 立即拉一次状态，界面不用等下一轮对账。
	if taskID != "" {
		if st, err := fetchRemoteStatus(peer, token, taskID); err == nil {
			applyRemoteStatus(rt, st)
		}
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "dispatched", Data: remoteTaskItem(rt)})
}

// clusterRemoteTaskListHandler 返回本机作为发起端的全部远程任务。
func clusterRemoteTaskListHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}
	items := remoteScanItems()
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: map[string]any{
		"items": items,
		"total": len(items),
	}})
}

// clusterRemoteTaskHandler 返回影子任务的当前状态，并顺手做一次对账。
func clusterRemoteTaskHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}
	rt := getRemoteTask(mux.Vars(r)["taskId"])
	if rt == nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "远程任务不存在"})
		return
	}
	if err := reconcileRemoteTask(rt); err != nil {
		gologger.Debug().Str("taskId", rt.ID).Str("error", err.Error()).Msg("远程任务对账未成功")
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: remoteTaskItem(rt)})
}

// clusterRemoteTaskStopHandler 请求执行节点停止该任务。
func clusterRemoteTaskStopHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}
	rt := getRemoteTask(mux.Vars(r)["taskId"])
	if rt == nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "远程任务不存在"})
		return
	}

	rt.mu.Lock()
	nodeURL, remoteID := rt.NodeURL, rt.RemoteTaskID
	rt.mu.Unlock()
	if remoteID == "" {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "任务尚未在执行节点上启动（或节点失联），请稍后重试"})
		return
	}
	peer, ok := findClusterPeer(nodeURL)
	if !ok {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "执行节点已不在集群配置中"})
		return
	}

	resp, err := doClusterPost(peer.URL+"/api/cluster/inbound/tasks/"+url.PathEscape(remoteID)+"/stop", clusterToken(), nil)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无法连接执行节点：" + err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: fmt.Sprintf("执行节点返回 HTTP %d", resp.StatusCode)})
		return
	}

	rt.mu.Lock()
	rt.Status = string(TaskCancelled)
	rt.mu.Unlock()
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "stopped", Data: map[string]bool{"stopped": true}})
}

// clusterRemoteTaskFindingsHandler 以只读方式代理执行节点上该任务的命中明细。
//
// 直接把对方的响应体转发回去（同源同结构），前端无需为远程任务另写一套渲染。
func clusterRemoteTaskFindingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}
	rt := getRemoteTask(mux.Vars(r)["taskId"])
	if rt == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "远程任务不存在"})
		return
	}

	rt.mu.Lock()
	nodeURL, remoteID := rt.NodeURL, rt.RemoteTaskID
	rt.mu.Unlock()
	if remoteID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "任务尚未在执行节点上启动（或节点失联）"})
		return
	}
	peer, ok := findClusterPeer(nodeURL)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "执行节点已不在集群配置中"})
		return
	}

	q := r.URL.Query()
	qs := url.Values{}
	for _, k := range []string{"page", "page_size", "severity", "keyword"} {
		if v := strings.TrimSpace(q.Get(k)); v != "" {
			qs.Set(k, v)
		}
	}
	target := peer.URL + "/api/cluster/inbound/tasks/" + url.PathEscape(remoteID) + "/findings"
	if encoded := qs.Encode(); encoded != "" {
		target += "?" + encoded
	}

	resp, err := doClusterGet(target, clusterToken())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无法连接执行节点：" + err.Error()})
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 16<<20))
}
