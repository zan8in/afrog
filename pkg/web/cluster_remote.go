package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/zan8in/afrog/v3/pkg/config"
	db2 "github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
)

// 多实例编排（v2：远程派发 —— 发起端一侧）。
//
// 本机把一次扫描派发给某个同伴执行。真正的任务与命中都留在执行节点（单一数据源），
// 本机只保存一条「影子记录」：节点、远端任务号、镜像状态。任务列表把影子记录并入，
// 命中明细按需只读代理拉取。
//
// 任务终结后把执行节点上的命中整批回填进本地 result 表（node 列记来源节点），
// 报告、台账、导出与 AI 研判才能在本机直接查到这些远程命中——没有回填的话，
// 派发出去的命中只能在远程任务详情页看，进不了本机的报告与台账。
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
//
// 刻意不回传完整目标清单：这份快照每 10s 拉一次，而发起端在派发时就已持有同一份清单
// （resolveDispatchRequest 先在本地把项目解析成具体目标再派发，清单也随影子记录落盘）。
// 回传一份上千 / 上万条的目标纯属重复，开销还会随「目标数 × 在跑的远程任务数」线性放大。
// 字段本身保留：对端是旧版本时仍会回传，见 applyRemoteStatus 的兜底。
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
	// ScheduleID 非空表示这次派发由计划扫描触发，用于列表追溯与排查。
	ScheduleID string
	// ProjectID 只在发起端有意义：按项目派发时，命中回填到本地这个项目名下。
	// 执行节点不需要（也不该）拥有该项目，所以派发请求里不会带它。
	ProjectID string
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
	// Backfilled 表示已经把执行节点上的命中回填进本地 result 表；置位后不再重放。
	Backfilled bool
	// lastBackfillErr 记录上一次回填失败的原因，用来抑制重复日志（仅内存态）。
	lastBackfillErr string

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
	remoteStore.items[rt.ID] = rt
	remoteStore.order = append(remoteStore.order, rt.ID)
	remoteStore.mu.Unlock()
	persistRemoteTasks()
}

func getRemoteTask(id string) *remoteTask {
	remoteStore.mu.Lock()
	defer remoteStore.mu.Unlock()
	return remoteStore.items[strings.TrimSpace(id)]
}

func removeRemoteTask(id string) {
	remoteStore.mu.Lock()
	delete(remoteStore.items, id)
	remoteStore.mu.Unlock()
	persistRemoteTasks()
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
	targets := append([]string(nil), rt.Targets...)
	return scanListItem{
		TaskID:      rt.ID,
		Name:        rt.Name,
		Status:      rt.Status,
		Source:      scanSourceRemote,
		ScheduleID:  rt.ScheduleID,
		NodeName:    rt.NodeName,
		NodeOK:      rt.NodeOK,
		Targets:     targets,
		Target:      firstTarget(targets),
		TargetTotal: len(targets),
		CreatedAt:   rt.CreatedAt,
		StartedAt:   rt.StartedAt,
		EndedAt:     rt.EndedAt,
		Progress:    rt.Progress,
		Hits:        rt.Hits,
		HitTotal:    rt.HitTotal,
		Error:       rt.Error,
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
// 影子记录持久化
// -----------------------
//
// 影子记录只留在内存里的话，发起端一重启，任务列表里的远程任务就凭空消失——
// 而任务其实还在执行节点上跑。这里把它们落盘，启动时读回来：终态任务继续展示，
// 未完成的任务交给对账协程按远端任务号收敛。

const (
	remoteTasksFileName = "remote_tasks.json"
	// maxRemoteTasks 限制落盘记录数，避免文件随派发次数无限增长。
	maxRemoteTasks = 200
)

// 落盘开关与路径默认关闭，由 StartServer 显式开启：单元测试直接调处理器时
// 不该去写用户的配置目录。
var (
	remotePersistEnabled    bool
	remoteTasksPathOverride string
	remotePersistMu         sync.Mutex
)

// remoteTaskRecord 是 remoteTask 的可序列化形态。remoteTask 带 mutex 与并发访问，
// 不能直接落盘，单独抽一份「纯数据」结构，读写两侧都走转换函数。
type remoteTaskRecord struct {
	ID           string           `json:"id"`
	DispatchID   string           `json:"dispatch_id"`
	NodeName     string           `json:"node_name"`
	NodeURL      string           `json:"node_url"`
	ScheduleID   string           `json:"schedule_id,omitempty"`
	ProjectID    string           `json:"project_id,omitempty"`
	RemoteTaskID string           `json:"remote_task_id,omitempty"`
	Name         string           `json:"name"`
	Status       string           `json:"status"`
	Progress     ScanProgressData `json:"progress"`
	Error        string           `json:"error,omitempty"`
	Hits         map[string]int   `json:"hits,omitempty"`
	HitTotal     int              `json:"hit_total"`
	Targets      []string         `json:"targets,omitempty"`
	CreatedAt    string           `json:"created_at,omitempty"`
	StartedAt    string           `json:"started_at,omitempty"`
	EndedAt      string           `json:"ended_at,omitempty"`
	NodeOK       bool             `json:"node_ok"`
	LastSeen     string           `json:"last_seen,omitempty"`
	// Backfilled 记录命中是否已回填本地，重启后不必再来一遍。
	Backfilled bool `json:"backfilled,omitempty"`
	// Request 是原始派发请求：还没拿到远端任务号时，重启后仍要靠它幂等重试。
	Request ScanCreateRequest `json:"request"`
}

type remoteTaskStore struct {
	Items []remoteTaskRecord `json:"items"`
}

func remoteTasksFilePath() (string, error) {
	if p := strings.TrimSpace(remoteTasksPathOverride); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "afrog")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, remoteTasksFileName), nil
}

func remoteTaskToRecord(rt *remoteTask) remoteTaskRecord {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rec := remoteTaskRecord{
		ID:           rt.ID,
		DispatchID:   rt.DispatchID,
		NodeName:     rt.NodeName,
		NodeURL:      rt.NodeURL,
		ScheduleID:   rt.ScheduleID,
		ProjectID:    rt.ProjectID,
		RemoteTaskID: rt.RemoteTaskID,
		Name:         rt.Name,
		Status:       rt.Status,
		Progress:     rt.Progress,
		Error:        rt.Error,
		Hits:         rt.Hits,
		HitTotal:     rt.HitTotal,
		Targets:      append([]string(nil), rt.Targets...),
		CreatedAt:    rt.CreatedAt,
		StartedAt:    rt.StartedAt,
		EndedAt:      rt.EndedAt,
		NodeOK:       rt.NodeOK,
		Backfilled:   rt.Backfilled,
		Request:      rt.request,
	}
	if !rt.LastSeen.IsZero() {
		rec.LastSeen = rt.LastSeen.Format(scheduleTimeLayout)
	}
	return rec
}

func recordToRemoteTask(rec remoteTaskRecord) *remoteTask {
	rt := &remoteTask{
		ID:           rec.ID,
		DispatchID:   rec.DispatchID,
		NodeName:     rec.NodeName,
		NodeURL:      rec.NodeURL,
		ScheduleID:   rec.ScheduleID,
		ProjectID:    rec.ProjectID,
		RemoteTaskID: rec.RemoteTaskID,
		Name:         rec.Name,
		Status:       rec.Status,
		Progress:     rec.Progress,
		Error:        rec.Error,
		Hits:         rec.Hits,
		HitTotal:     rec.HitTotal,
		Targets:      append([]string(nil), rec.Targets...),
		CreatedAt:    rec.CreatedAt,
		StartedAt:    rec.StartedAt,
		EndedAt:      rec.EndedAt,
		NodeOK:       rec.NodeOK,
		Backfilled:   rec.Backfilled,
		request:      rec.Request,
	}
	if rec.LastSeen != "" {
		if ts, err := time.ParseInLocation(scheduleTimeLayout, rec.LastSeen, time.Local); err == nil {
			rt.LastSeen = ts
		}
	}
	return rt
}

// pruneRemoteRecords 裁剪到上限：优先丢「最早且已终结」的记录，运行中的任务不会
// 因为数量上限被静默抹掉；极端情况下（全都未终结）才按时间顺序丢最早的。
func pruneRemoteRecords(recs []remoteTaskRecord) []remoteTaskRecord {
	if len(recs) <= maxRemoteTasks {
		return recs
	}
	keep := make([]remoteTaskRecord, 0, maxRemoteTasks)
	overflow := len(recs) - maxRemoteTasks
	for _, rec := range recs {
		if overflow > 0 && isTerminalRemoteStatus(rec.Status) {
			overflow--
			continue
		}
		keep = append(keep, rec)
	}
	if len(keep) > maxRemoteTasks {
		keep = keep[len(keep)-maxRemoteTasks:]
	}
	return keep
}

// persistRemoteTasks 把当前影子记录整体原子写盘。未开启落盘时静默返回。
func persistRemoteTasks() {
	if !remotePersistEnabled {
		return
	}
	snap := remoteTaskSnapshot()
	recs := make([]remoteTaskRecord, 0, len(snap))
	for _, rt := range snap {
		recs = append(recs, remoteTaskToRecord(rt))
	}
	recs = pruneRemoteRecords(recs)

	remotePersistMu.Lock()
	defer remotePersistMu.Unlock()
	path, err := remoteTasksFilePath()
	if err != nil {
		gologger.Debug().Msgf("远程任务落盘失败: %v", err)
		return
	}
	data, err := json.MarshalIndent(remoteTaskStore{Items: recs}, "", "  ")
	if err != nil {
		gologger.Debug().Msgf("远程任务序列化失败: %v", err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		gologger.Debug().Msgf("远程任务落盘失败: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		gologger.Debug().Msgf("远程任务落盘失败: %v", err)
	}
}

// RestoreRemoteTasks 在服务启动时把落盘的影子记录读回内存，返回恢复的条数。
// 读失败不阻断启动：最坏情况只是丢一份镜像视图，任务本身仍在执行节点上。
func RestoreRemoteTasks() int {
	path, err := remoteTasksFilePath()
	if err != nil {
		gologger.Warning().Msgf("远程任务记录路径不可用: %v", err)
		return 0
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			gologger.Warning().Msgf("读取远程任务记录失败: %v", err)
		}
		return 0
	}
	var store remoteTaskStore
	if err := json.Unmarshal(data, &store); err != nil {
		gologger.Warning().Msgf("远程任务记录无法解析: %v", err)
		return 0
	}

	remoteStore.mu.Lock()
	defer remoteStore.mu.Unlock()
	restored := 0
	for _, rec := range store.Items {
		if strings.TrimSpace(rec.ID) == "" {
			continue
		}
		if _, ok := remoteStore.items[rec.ID]; ok {
			continue
		}
		remoteStore.items[rec.ID] = recordToRemoteTask(rec)
		remoteStore.order = append(remoteStore.order, rec.ID)
		restored++
	}
	if restored > 0 {
		gologger.Info().Msgf("已恢复 %d 条远程派发任务记录", restored)
	}
	return restored
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
				snap := remoteTaskSnapshot()
				active := false
				for _, rt := range snap {
					if !remoteTaskTerminal(rt) {
						active = true
						_ = reconcileRemoteTask(rt)
					}
					// 任务终结后把执行节点上的命中回填到本地：台账、报告与导出
					// 都只认本地 result 表。回填是「先清后写」的幂等重放，
					// 没成功就留给下一轮继续重试。
					if remoteTaskNeedsBackfill(rt) {
						active = true
						backfillRemoteFindings(rt)
					}
				}
				// 状态变化都发生在这里，顺手把镜像记录落盘一次；全是终态任务
				// 时不再重复写盘，避免空转产生无意义的 IO。
				if active {
					persistRemoteTasks()
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

// remoteTaskTerminal 读取影子记录的当前状态并判断是否已终结。
func remoteTaskTerminal(rt *remoteTask) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return isTerminalRemoteStatus(rt.Status)
}

// remoteTaskNeedsBackfill 判断这条影子记录是否还欠一次命中回填。
//
// 终态且拿到过远端任务号才需要回填：派发被拒这类记录根本没有远端任务，
// 也不能永久占着「欠回填」状态，否则每轮空转并触发一次无意义的落盘。
func remoteTaskNeedsBackfill(rt *remoteTask) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return isTerminalRemoteStatus(rt.Status) && !rt.Backfilled && strings.TrimSpace(rt.RemoteTaskID) != ""
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
	// 新版本执行节点不再回传目标清单（见 remoteStatusOf），镜像记录沿用派发时那份。
	// 这里保留兜底：对端仍是旧版本时会回传，以对端为准，混跑集群的行为与改动前一致。
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

// fetchRemoteResults 原样拉取执行节点上某个任务的全部命中，供回填使用。
//
// 走的是结果快照接口（不是报告页那个做了展示层归一化的接口）：回填要的是能原样
// 落库的完整数据，否则本地报告会缺请求响应证据，AI 研判也拿不到原文。
func fetchRemoteResults(peer config.ClusterPeer, token, remoteTaskID string) ([]db2.ResultData, error) {
	target := peer.URL + "/api/cluster/inbound/tasks/" + url.PathEscape(remoteTaskID) + "/results"
	resp, err := doClusterGet(target, token)
	if err != nil {
		return nil, fmt.Errorf("无法连接执行节点：%s", err.Error())
	}
	defer resp.Body.Close()

	var out struct {
		Success bool             `json:"success"`
		Message string           `json:"message"`
		Data    []db2.ResultData `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("执行节点返回内容无法解析")
	}
	if resp.StatusCode != http.StatusOK || !out.Success {
		return nil, fmt.Errorf("执行节点返回：%s", firstNonEmpty(strings.TrimSpace(out.Message), fmt.Sprintf("HTTP %d", resp.StatusCode)))
	}
	return out.Data, nil
}

// backfillRemoteFindings 把执行节点上的命中回填到本地 result 表。
//
// 落库用的是发起端的影子任务号：发起端的报告、台账、导出都按它组织，前端不需要
// 为远程命中再走一套查询；node 列记下来源节点，多节点命中才不会混成一团。按项目
// 派发的任务同时把归属登记进 task_project，项目台账与项目导出才看得到这些命中。
//
// 幂等：先按影子任务号清空再整批写入。影子任务号只由回填写入（本机扫描不会拿到
// 已被占用的号），所以重放不会和本机数据撞车，中途失败重来也不会写出重复命中。
func backfillRemoteFindings(rt *remoteTask) {
	rt.mu.Lock()
	id, nodeName, nodeURL, remoteID, projectID := rt.ID, rt.NodeName, rt.NodeURL, rt.RemoteTaskID, rt.ProjectID
	rt.mu.Unlock()

	if strings.TrimSpace(remoteID) == "" {
		return
	}

	if err := runRemoteBackfill(id, nodeName, nodeURL, remoteID, projectID); err != nil {
		noteBackfillFailure(rt, err.Error())
		return
	}

	rt.mu.Lock()
	rt.Backfilled = true
	rt.lastBackfillErr = ""
	rt.mu.Unlock()
	persistRemoteTasks()
}

// runRemoteBackfill 执行一次「拉取 + 落库 + 归属登记」；任一步失败都直接返回错误，
// 是否重试交给调用方（下一轮对账会再来一次）。
func runRemoteBackfill(id, nodeName, nodeURL, remoteID, projectID string) error {
	peer, ok := findClusterPeer(nodeURL)
	if !ok {
		return fmt.Errorf("执行节点已不在集群配置中（%s）", nodeURL)
	}

	rows, err := fetchRemoteResults(peer, clusterToken(), remoteID)
	if err != nil {
		return err
	}
	// 先清后写：影子任务号只由回填写入（本机扫描不会拿到已被占用的号），
	// 所以重放不会和本机数据撞车，中途失败重来也不会写出重复命中。
	if _, err := sqlite.DeleteResultsByTask(id); err != nil {
		return fmt.Errorf("清理旧命中失败: %w", err)
	}
	if len(rows) > 0 {
		if _, err := sqlite.InsertRawResults(id, nodeName, rows); err != nil {
			return fmt.Errorf("写入命中失败: %w", err)
		}
	}
	if pid := strings.TrimSpace(projectID); pid != "" {
		if err := sqlite.LinkTaskProject(id, pid); err != nil {
			return fmt.Errorf("项目归属登记失败: %w", err)
		}
	}
	gologger.Info().Msgf("远程命中已回填: task=%s node=%s hits=%d project=%s", id, nodeName, len(rows), strings.TrimSpace(projectID))
	return nil
}

// noteBackfillFailure 只在失败原因变化时记一条告警：执行节点长期不可达时，
// 每 10s 刷一条一模一样的日志没有意义——界面上的「节点失联」已经说明了情况。
func noteBackfillFailure(rt *remoteTask, msg string) {
	rt.mu.Lock()
	changed := rt.lastBackfillErr != msg
	rt.lastBackfillErr = msg
	rt.mu.Unlock()
	if changed {
		gologger.Warning().Msgf("远程命中回填失败: task=%s err=%s", rt.ID, msg)
	}
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

// resolveDispatchRequest 把「按项目派发」在本地解析成具体目标：项目与资产库只
// 存在于发起端，执行节点不需要（也不该）拥有该项目。
func resolveDispatchRequest(scanReq ScanCreateRequest) (ScanCreateRequest, error) {
	pid := strings.TrimSpace(scanReq.ProjectID)
	if pid == "" {
		return scanReq, nil
	}
	project, ok := findProject(pid)
	if !ok {
		return scanReq, errProjectNotFound
	}
	targets, err := resolveScanTargets(scanReq)
	if err != nil {
		return scanReq, err
	}
	scanReq.Targets = targets
	scanReq.ProjectID = ""
	if strings.TrimSpace(scanReq.TaskName) == "" {
		scanReq.TaskName = "远程任务 · 项目 " + strings.TrimSpace(project.Name)
	}
	return scanReq, nil
}

// dispatchRemoteScan 把一次扫描派发给指定同伴：先在本地解析项目，再落一条影子
// 记录并立即尝试首次派发。「手动派发」与「计划扫描派发」共用这一条路径。
//
// 返回的 error 表示这次派发在本地就被判定不可能成功（未配令牌、项目无效、对方
// 明确拒绝）；执行节点暂时连不上不算失败——影子记录会保留，交给后台对账继续重试，
// 此时返回的 item 上 NodeOK=false、Error 写明原因。
func dispatchRemoteScan(peer config.ClusterPeer, scanReq ScanCreateRequest, origin scanOrigin) (scanListItem, error) {
	token := clusterToken()
	if token == "" {
		return scanListItem{}, fmt.Errorf("本实例未配置 cluster.token，无法派发")
	}
	// 派发请求里不该带项目（执行节点不需要也不该知道），但发起端要记住它：
	// 命中回填时才能把这些命中归到本地项目名下。
	originProjectID := strings.TrimSpace(scanReq.ProjectID)
	scanReq, err := resolveDispatchRequest(scanReq)
	if err != nil {
		return scanListItem{}, err
	}

	rt := newRemoteTask(peer, scanReq)
	rt.ProjectID = originProjectID
	rt.ScheduleID = strings.TrimSpace(origin.ScheduleID)
	addRemoteTask(rt)
	startRemoteReconciler()

	taskID, name, hardMsg, softMsg := postRemoteDispatch(peer, token, rt.DispatchID, scanReq)
	if hardMsg != "" {
		removeRemoteTask(rt.ID)
		return scanListItem{}, fmt.Errorf("%s", hardMsg)
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
	persistRemoteTasks()
	return remoteTaskItem(rt), nil
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

	item, err := dispatchRemoteScan(peer, req.Request, scanOrigin{})
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
		return
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "dispatched", Data: item})
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

	// 先尽力把停止请求转发给执行节点。是否成功决定后面是「确认停止」还是「只结束本机镜像」。
	confirmed, failStatus, failMsg := requestRemoteStop(nodeURL, remoteID)
	if confirmed {
		rt.mu.Lock()
		rt.Status = string(TaskCancelled)
		rt.NodeOK = true
		rt.Error = ""
		rt.EndedAt = time.Now().Format("2006-01-02 15:04:05")
		rt.mu.Unlock()
		persistRemoteTasks()
		_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "stopped", Data: map[string]bool{"stopped": true}})
		return
	}

	if !wantsForceStop(r) {
		// 非强制：保持严格语义，如实回报为何停不下来；界面据此提示可改用「强制结束」。
		w.WriteHeader(failStatus)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: failMsg})
		return
	}

	// 强制结束：执行节点不可达 / 尚未在其上启动时，允许只把本机这份镜像收敛为终态，
	// 否则这条记录会永远卡在「启动中/扫描中」，既停不掉也删不掉。Error 里明确标注
	// 远端状态未经确认，避免用户误以为远端一定已停。
	rt.mu.Lock()
	rt.Status = string(TaskCancelled)
	rt.NodeOK = false
	rt.Error = "已强制结束本机镜像（执行节点状态未确认）：" + failMsg
	rt.EndedAt = time.Now().Format("2006-01-02 15:04:05")
	rt.mu.Unlock()
	persistRemoteTasks()
	_ = json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "forced",
		Data:    map[string]bool{"stopped": true, "forced": true},
	})
}

// requestRemoteStop 尽力请求执行节点停止远端任务。
//
// 返回是否已确认停止；未确认时同时给出建议的 HTTP 状态与原因，供非强制路径如实回报。
func requestRemoteStop(nodeURL, remoteID string) (confirmed bool, status int, msg string) {
	if strings.TrimSpace(remoteID) == "" {
		return false, http.StatusConflict, "任务尚未在执行节点上启动（或节点失联），请稍后重试"
	}
	peer, ok := findClusterPeer(nodeURL)
	if !ok {
		return false, http.StatusConflict, "执行节点已不在集群配置中"
	}
	resp, err := doClusterPost(peer.URL+"/api/cluster/inbound/tasks/"+url.PathEscape(remoteID)+"/stop", clusterToken(), nil)
	if err != nil {
		return false, http.StatusBadGateway, "无法连接执行节点：" + err.Error()
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return false, http.StatusBadGateway, fmt.Sprintf("执行节点返回 HTTP %d", resp.StatusCode)
	}
	return true, 0, ""
}

// wantsForceStop 判断是否为「强制结束」：显式带 ?force=1 时才允许只收敛本机镜像。
func wantsForceStop(r *http.Request) bool {
	v := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("force")))
	return v == "1" || v == "true" || v == "yes"
}

// clusterRemoteTaskDeleteHandler 从本机列表移除一条远程任务镜像记录。
//
// 只允许删除已终结的任务：运行中的任务一旦删掉镜像记录，发起端就再也拿不回它
// 的状态与命中，等于丢了一条正在跑的任务；应先停止再删除。
// 删除只影响本机这份镜像视图，不回删已回填到本地 result 表的命中——那些命中已经
// 进入报告与台账，属于扫描结果，不该因为清理列表而消失。
func clusterRemoteTaskDeleteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rt := getRemoteTask(mux.Vars(r)["taskId"])
	if rt == nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "远程任务不存在"})
		return
	}
	if !remoteTaskTerminal(rt) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "任务仍在执行节点上运行，请先停止再删除"})
		return
	}
	removeRemoteTask(rt.ID)
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "deleted", Data: map[string]bool{"deleted": true}})
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
