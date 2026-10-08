package web

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	db2 "github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
)

type TaskStatus string

const (
	TaskStarting  TaskStatus = "starting"
	TaskRunning   TaskStatus = "running"
	TaskPaused    TaskStatus = "paused"
	TaskCompleted TaskStatus = "completed"
	TaskFailed    TaskStatus = "failed"
	TaskCancelled TaskStatus = "cancelled"
)

// isActive reports whether a task still occupies a slot in the task manager.
func isActive(s TaskStatus) bool {
	return s == TaskRunning || s == TaskPaused || s == TaskStarting
}

// 提交扫描时的业务错误。定义成哨兵值是为了让 Web 起扫与计划调度器共用同一套
// 目标解析逻辑，同时各自决定如何呈现（HTTP 状态码 / 计划状态）。
var (
	errProjectNotFound  = errors.New("项目不存在")
	errNoProjectTargets = errors.New("该项目没有有效目标")
	errNoValidTargets   = errors.New("缺少有效扫描目标")
)

type ScanEvent struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
	// Seq 是任务内单调递增的事件序号。它既用于「补发」时定位起点，
	// 也作为 SSE 的 id 字段，让浏览器重连时能带上 Last-Event-ID 续传。
	Seq uint64 `json:"seq,omitempty"`
}

// Task tracks one scan. Its mutable fields are read and written from the HTTP
// handler goroutines and from the event-drain goroutine at the same time, so
// they are reached only through the accessors below.
type Task struct {
	ID            string
	Name          string
	CreatedAt     time.Time
	SeverityStats map[string]int
	Subscribers   map[chan ScanEvent]struct{}

	// 发起入口与归属：创建后不再变更，读时无需加锁。
	// source 为 manual（页面手动起扫）或 schedule（计划扫描），
	// 供任务列表标出来源并让「计划扫描」的任务在前端可见。
	source     string
	scheduleID string
	projectID  string
	// 远程派发来源（仅 source=remote 时有值）：dispatchID 是幂等键，
	// origin* 标明是哪个控制台派发的，用于列表/详情展示与去重。
	dispatchID       string
	originInstanceID string
	originName       string

	// spec 是本次扫描的规格快照，排队到真正执行时由 runScanTask 使用。
	spec *executor.Spec
	// targets 保留原始目标列表，scan_info 事件只展示前 5 个。
	targets []string

	mu        sync.Mutex
	status    TaskStatus
	startTime time.Time
	endedAt   time.Time
	handle    executor.Handle
	// seq 是已派发事件的最大序号；buf 保留最近 eventBufferSize 条事件，
	// 供「补录」的订阅者（计划扫描触发的任务）补看开扫以来的过程事件。
	seq uint64
	buf []ScanEvent
	// progress / scanInfo / summary 都是引擎口径的数据：progress 来自每秒一次的
	// 进度事件，scanInfo 来自开始执行前的前置汇总，summary 来自 done 事件。
	progress   *scanstream.ProgressEvent
	scanInfo   *scanstream.ScanInfoEvent
	summary    *scanstream.Summary
	doneStatus string
	errText    string

	// finalized makes finalizeTask run exactly once. Both the stop handler and
	// the drain goroutine reach it when a scan is cancelled, and running it
	// twice would decrement the manager's running count twice and let the
	// queue admit more scans than maxRunning allows.
	finalized atomic.Bool
}

func (t *Task) Status() TaskStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status
}

func (t *Task) setStatus(s TaskStatus) {
	t.mu.Lock()
	t.status = s
	t.mu.Unlock()
}

func (t *Task) started() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.startTime
}

func (t *Task) setStarted(at time.Time) {
	t.mu.Lock()
	t.startTime = at
	t.mu.Unlock()
}

// setEnded 记录任务收尾时刻，供任务列表展示。
func (t *Task) setEnded(at time.Time) {
	t.mu.Lock()
	t.endedAt = at
	t.mu.Unlock()
}

// ended 返回任务收尾时刻，零值表示还没结束。
func (t *Task) ended() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.endedAt
}

func (t *Task) setHandle(h executor.Handle) {
	t.mu.Lock()
	t.handle = h
	t.mu.Unlock()
}

func (t *Task) getHandle() executor.Handle {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.handle
}

func (t *Task) getTargets() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.targets
}

func (t *Task) setProgress(p *scanstream.ProgressEvent) {
	t.mu.Lock()
	t.progress = p
	t.mu.Unlock()
}

func (t *Task) getProgress() *scanstream.ProgressEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.progress
}

func (t *Task) setScanInfo(info *scanstream.ScanInfoEvent) {
	t.mu.Lock()
	t.scanInfo = info
	t.mu.Unlock()
}

func (t *Task) getScanInfo() *scanstream.ScanInfoEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.scanInfo
}

func (t *Task) setDone(status string, summary *scanstream.Summary) {
	t.mu.Lock()
	t.doneStatus = status
	if summary != nil {
		t.summary = summary
	}
	t.mu.Unlock()
}

func (t *Task) getSummary() *scanstream.Summary {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.summary
}

func (t *Task) setErrText(msg string) {
	if strings.TrimSpace(msg) == "" {
		return
	}
	t.mu.Lock()
	t.errText = msg
	t.mu.Unlock()
}

func (t *Task) errMessage() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.errText
}

// doneState 返回引擎自报的收尾状态（completed/stopped）与错误信息。
func (t *Task) doneState() (string, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.doneStatus, t.errText
}

// addHit 累加严重级别计数。
func (t *Task) addHit(severity string) {
	t.mu.Lock()
	if t.SeverityStats == nil {
		t.SeverityStats = make(map[string]int)
	}
	t.SeverityStats[severity]++
	t.mu.Unlock()
}

// hitCount 返回命中总数。
func (t *Task) hitCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	total := 0
	for _, n := range t.SeverityStats {
		total += n
	}
	return total
}

// severitySnapshot 返回命中级别分布的副本，供通知汇总使用。
// 直接读 SeverityStats 会与事件排空协程的写入竞争。
func (t *Task) severitySnapshot() map[string]int {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make(map[string]int, len(t.SeverityStats))
	for k, v := range t.SeverityStats {
		out[k] = v
	}
	return out
}

// terminalStatus 把引擎自报的收尾状态与子进程退出码折算成任务状态。
// 注意 cmd/afrog 在 runner 报错时是先发 error 事件再正常 return（退出码 0），
// 因此只要收到过 error 事件就判为失败。
func (t *Task) terminalStatus(exitErr error) TaskStatus {
	done, errText := t.doneState()
	switch done {
	case "stopped":
		return TaskCancelled
	case "completed":
		return TaskCompleted
	}
	if exitErr != nil || errText != "" {
		return TaskFailed
	}
	return TaskCompleted
}

// progressSnapshot 汇总任务当前的进度口径。
//
// total 优先取引擎上报的 scan_info.total_scans（与命令行 tasks= 同源，见协议文档 5.2）：
// 主机发现/端口扫描/Web 探测这些前置阶段里引擎还没算出任务总数，此间的 progress
// 事件会带 total=0，只看最后一次事件会把总数显示成 0。finished 则用 done 事件里的
// 实际执行数修正。
func progressSnapshot(t *Task) ScanProgressData {
	snap := ScanProgressData{}
	if p := t.getProgress(); p != nil {
		snap.Percent = p.Percent
		snap.Finished = int(p.Finished)
		snap.Total = int(p.Total)
		snap.ElapsedMs = p.ElapsedMs
	}
	if info := t.getScanInfo(); info != nil && info.TotalScans > 0 {
		snap.Total = info.TotalScans
	}
	if s := t.getSummary(); s != nil {
		snap.Finished = int(s.Executed)
		if s.ElapsedMs > 0 {
			snap.ElapsedMs = s.ElapsedMs
		}
	}
	if snap.ElapsedMs <= 0 {
		if started := t.started(); !started.IsZero() {
			snap.ElapsedMs = time.Since(started).Milliseconds()
		}
	}
	snap.Rate = calcRate(t.started(), int64(snap.Finished))
	if t.Status() == TaskCompleted {
		// 引擎只在扫描真正跑完时才让百分数到 100，整数取整会停在 99。
		snap.Percent = 100
	}
	return snap
}

type TaskManager struct {
	mu         sync.Mutex
	tasks      map[string]*Task
	maxRunning int
	running    int
	queue      []string
	seqByDate  map[string]int
}

func newTaskManager() *TaskManager {
	return &TaskManager{tasks: make(map[string]*Task), maxRunning: getMaxRunning(), seqByDate: make(map[string]int)}
}

var tmOnce sync.Once
var tm *TaskManager

func getTaskManager() *TaskManager {
	tmOnce.Do(func() { tm = newTaskManager() })
	return tm
}

// findTask 按任务号取本机内存中的任务，未找到返回 nil。
func findTask(taskID string) *Task {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil
	}
	m := getTaskManager()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tasks[taskID]
}

// stopTaskByID 结束一个本机任务：先终止子进程（SIGTERM → 宽限期 → SIGKILL），再收尾。
// 返回是否找到任务；找不到时给出可直接展示的原因。Web 停止与集群远程停止共用。
func stopTaskByID(taskID string) (bool, string) {
	t := findTask(taskID)
	if t == nil {
		return false, "任务不存在"
	}
	if h := t.getHandle(); h != nil {
		if err := h.Cancel(); err != nil && !errors.Is(err, executor.ErrAlreadyDone) {
			gologger.Debug().Str("taskId", taskID).Str("error", err.Error()).Msg("stop: cancel process failed")
		}
	}
	t.setStatus(TaskCancelled)
	finalizeTask(getTaskManager(), t, TaskCancelled)
	return true, ""
}

func getMaxRunning() int {
	v := strings.TrimSpace(os.Getenv("AFROG_MAX_RUNNING_TASKS"))
	if v == "" {
		return 6
	}
	i, err := strconv.Atoi(v)
	if err != nil || i <= 0 {
		return 6
	}
	return i
}

// taskIDSuffix 是本进程的随机后缀。序号只是进程内计数器，重启后会从 1 重来，
// 而同一天先后启动的进程会生成同一个 taskid；sqlite 的命中是按 taskid 关联的，
// 没有后缀就会把旧任务的命中算到新任务（及其所属项目）头上。
var taskIDSuffix = utils.CreateRandomString(6)

func nextTaskID(m *TaskManager) string {
	d := time.Now().Format("20060102")
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seqByDate[d]++
	return fmt.Sprintf("%s-%05d-%s", d, m.seqByDate[d], taskIDSuffix)
}

// eventBufferSize 是每个任务保留的事件条数上限。计划扫描触发的任务要在前端
// 「补看」开扫以来的过程（Web 探测 / 端口 / 命中），事件只发一次、不重放的话
// 后加入的订阅者就永远看不到；所以按条数留一个窗口，超出后丢弃最旧的。
const eventBufferSize = 3000

func publish(t *Task, ev ScanEvent) {
	t.mu.Lock()
	t.seq++
	ev.Seq = t.seq
	t.recordEventLocked(ev)
	for ch := range t.Subscribers {
		select {
		case ch <- ev:
		default:
			if ev.Type == "status" {
				select {
				case <-ch:
				default:
				}
				select {
				case ch <- ev:
				default:
				}
			}
		}
	}
	t.mu.Unlock()
}

// recordEventLocked 把事件写入环形窗口。调用方必须持有 t.mu。
func (t *Task) recordEventLocked(ev ScanEvent) {
	t.buf = append(t.buf, ev)
	over := len(t.buf) - eventBufferSize
	if over <= 0 {
		return
	}
	copy(t.buf, t.buf[over:])
	t.buf = t.buf[:len(t.buf)-over]
}

// addSubscriber 注册订阅者，并在 replay 为真时一并返回缓冲区中 Seq > fromSeq 的
// 历史事件：补录场景（前端刚发现一个非本页发起的任务）需要从头补发，
// 重连场景由浏览器带 Last-Event-ID 续传，二者都不会漏事件。
func addSubscriber(t *Task, fromSeq uint64, replay bool) (chan ScanEvent, []ScanEvent) {
	ch := make(chan ScanEvent, 256)
	t.mu.Lock()
	if t.Subscribers == nil {
		t.Subscribers = make(map[chan ScanEvent]struct{})
	}
	t.Subscribers[ch] = struct{}{}
	var history []ScanEvent
	if replay {
		for _, ev := range t.buf {
			if ev.Seq > fromSeq {
				history = append(history, ev)
			}
		}
	}
	t.mu.Unlock()
	return ch, history
}

func removeSubscriber(t *Task, ch chan ScanEvent) {
	t.mu.Lock()
	delete(t.Subscribers, ch)
	t.mu.Unlock()
	close(ch)
}

// startTask 取得一个运行名额（名额用尽则排队），随后拉起扫描子进程。
func startTask(m *TaskManager, t *Task) {
	m.mu.Lock()
	if m.running >= m.maxRunning {
		m.queue = append(m.queue, t.ID)
		m.mu.Unlock()
		gologger.Debug().Msgf("start scan queued: taskId=%s running=%d maxRunning=%d", t.ID, m.running, m.maxRunning)
		publish(t, ScanEvent{Type: "status", Data: map[string]string{"status": "starting"}})
		return
	}
	m.running++
	m.mu.Unlock()

	t.setStatus(TaskRunning)
	t.setStarted(time.Now())
	gologger.Debug().Msgf("start scan running: taskId=%s capacity available", t.ID)
	publish(t, ScanEvent{Type: "status", Data: map[string]string{"status": "running"}})

	go runScanTask(m, t)
}

// finalizeTask 收尾一个任务：补发最终进度与汇总、通知订阅者、释放名额并放行队列。
// 它由多个路径到达（子进程退出、终止接口、启动失败），靠 finalized 保证只生效一次。
func finalizeTask(m *TaskManager, t *Task, status TaskStatus) {
	if t.finalized.Swap(true) {
		return
	}
	t.setEnded(time.Now())
	t.setStatus(status)

	// 最后一次 progress 采样最多滞后 1 秒，补发一次避免前端停在半截数字上。
	if t.getProgress() != nil || t.getSummary() != nil {
		snap := progressSnapshot(t)
		publish(t, ScanEvent{Type: "progress", Data: map[string]interface{}{
			"percent":   snap.Percent,
			"finished":  snap.Finished,
			"total":     snap.Total,
			"rate":      snap.Rate,
			"elapsedMs": snap.ElapsedMs,
		}})
	}
	if info := t.getScanInfo(); info != nil {
		publish(t, ScanEvent{Type: "scan_info", Data: scanInfoPayload(t, info)})
	}
	publish(t, ScanEvent{Type: "status", Data: map[string]string{"status": string(status)}})

	// 终态快照落库：这是命中分布 / 目标数 / 用时的最终版本，重启后靠它展示。
	persistScanTask(t)

	m.mu.Lock()
	if m.running > 0 {
		m.running--
	}
	var next *Task
	if len(m.queue) > 0 {
		next = m.tasks[m.queue[0]]
		m.queue = m.queue[1:]
	}
	m.mu.Unlock()
	if next != nil {
		startTask(m, next)
	}
}

func scansCreateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		gologger.Debug().Str("path", r.URL.Path).Str("method", r.Method).Msg("start scan failed: method not allowed")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	var req ScanCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Debug().Str("path", r.URL.Path).Msg("start scan failed: invalid json")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}
	if !req.EnableStream {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Debug().Str("path", r.URL.Path).Msg("start scan failed: enable_stream must be true")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "enable_stream 必须为 true"})
		return
	}

	id, scanInfo, err := launchScan(req, scanOrigin{Source: scanSourceManual})
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Debug().Str("path", r.URL.Path).Str("error", err.Error()).Msg("start scan rejected")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
		return
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "created",
		Data: map[string]interface{}{
			"taskId":   id,
			"scanInfo": scanInfo,
		},
	})
}

// 任务发起入口。计划扫描、远程派发与手动扫描共用同一条执行路径，
// 只在列表里用 source 区分，方便前端标出来源。
const (
	scanSourceManual   = "manual"
	scanSourceSchedule = "schedule"
	// scanSourceRemote 表示这次扫描由别的控制台派发（本机是执行节点）。
	scanSourceRemote = "remote"
)

// scanOrigin 描述任务的发起入口。
type scanOrigin struct {
	Source     string
	ScheduleID string
	// DispatchID 是远程派发的幂等键：同一个 dispatch_id 重复到达只起一次扫描。
	DispatchID       string
	OriginInstanceID string
	OriginName       string
}

// scansListHandler 返回本实例内存中的任务列表（运行中 + 已完成，新的在前）。
//
// 任务状态是进程内存态：重启后不复存在，历史命中仍可从报告/台账查询。
// 这个接口的作用是让「不是本页面发起」的扫描（典型是计划扫描）也能在前端可见。
//
// scope=active 是给轮询用的轻量口径：只回内存里活跃或刚结束的任务，不读 sqlite 历史。
// 历史任务不会变化，前端首次加载拿一次全量就够了，每 10s 重读一遍纯属浪费。
func scansListHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	m := getTaskManager()
	items := m.listScans()
	if strings.TrimSpace(r.URL.Query().Get("scope")) == "active" {
		items = m.listScansActive()
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: map[string]interface{}{
		"items": items,
		"total": len(items),
	}})
}

// scanListItem 是任务列表项，字段刻意保持扁平，便于前端直接渲染。
type scanListItem struct {
	TaskID     string `json:"task_id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Source     string `json:"source"` // manual | schedule | remote
	ScheduleID string `json:"schedule_id,omitempty"`
	ProjectID  string `json:"project_id,omitempty"`
	// NodeName 在远程场景里标明「对端」：发起端看到的是执行节点，
	// 执行节点看到的是发起方。具体语义由 source 决定。
	NodeName string `json:"node_name,omitempty"`
	// NodeOK 仅对发起端的远程任务有意义：false 表示暂时联系不上执行节点，
	// 此时状态是最后一次成功对账的结果，不应当当作失败。
	NodeOK bool `json:"node_ok,omitempty"`
	// Targets 是完整目标清单，刻意不进 JSON：一个任务上千目标时，把清单塞进列表
	// 会让每 10s 一次的轮询响应涨到 MB 级（实测 62 条任务 ≈ 1.8MB，其中 99% 是它）。
	// 只需要摘要（Target / TargetTotal）；真要全量时走 GET /scans/{taskId}/targets。
	// 服务端内部仍需要它（任务快照落库），所以是 json:"-" 而不是删字段。
	Targets []string `json:"-"`
	// Target 是首个目标，列表摘要用。
	Target string `json:"target,omitempty"`
	// TargetTotal 是目标总数。前端据此区分「确实没有目标」与「清单未随列表下发」，
	// 并决定「重跑」时是否需要按需拉一次全量清单。
	TargetTotal int    `json:"target_total"`
	CreatedAt   string `json:"created_at,omitempty"`
	StartedAt   string `json:"started_at,omitempty"`
	EndedAt     string `json:"ended_at,omitempty"`

	Progress ScanProgressData `json:"progress"`
	Hits     map[string]int   `json:"hits"`
	HitTotal int              `json:"hit_total"`
	Error    string           `json:"error,omitempty"`

	// ScanInfo 是引擎开扫前的前置汇总。前端「补录」一个非本页发起的任务时，
	// 目标数 / PoC 数 / 总扫描数只能来自这里——scan_info 事件早就发过了，不会重放。
	ScanInfo *scanInfoItem `json:"scan_info,omitempty"`
}

// scanInfoItem 与前端 ScanInfo 一一对应。
type scanInfoItem struct {
	TotalTargets int    `json:"total_targets"`
	TotalPocs    int    `json:"total_pocs"`
	TotalScans   int    `json:"total_scans"`
	OOBEnabled   bool   `json:"oob_enabled"`
	OOBStatus    string `json:"oob_status"`
}

// formatScanTime 用与 reports/ledger 一致的本地时间格式，空值返回空串。
func formatScanTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02 15:04:05")
}

// firstTarget 取首个目标做列表摘要；没有目标时返回空串。
func firstTarget(targets []string) string {
	if len(targets) == 0 {
		return ""
	}
	return targets[0]
}

// listItem 组装任务列表项。
func (t *Task) listItem() scanListItem {
	t.mu.Lock()
	source := t.source
	if source == "" {
		source = scanSourceManual
	}
	targets := append([]string(nil), t.targets...)
	item := scanListItem{
		TaskID:      t.ID,
		Name:        t.Name,
		Status:      string(t.status),
		Source:      source,
		ScheduleID:  t.scheduleID,
		ProjectID:   t.projectID,
		NodeName:    t.originName,
		Targets:     targets,
		Target:      firstTarget(targets),
		TargetTotal: len(targets),
		CreatedAt:   formatScanTime(t.CreatedAt),
		StartedAt:   formatScanTime(t.startTime),
		EndedAt:     formatScanTime(t.endedAt),
		Error:       t.errText,
	}
	t.mu.Unlock()

	item.Progress = progressSnapshot(t)
	item.Hits = t.severitySnapshot()
	for _, n := range item.Hits {
		item.HitTotal += n
	}
	if info := t.getScanInfo(); info != nil {
		item.ScanInfo = &scanInfoItem{
			TotalTargets: info.TotalTargets,
			TotalPocs:    info.TotalPocs,
			TotalScans:   info.TotalScans,
			OOBEnabled:   info.OOBEnabled,
			OOBStatus:    info.OOBStatus,
		}
	}
	return item
}

// persistScanTask 把任务快照落库。任务的实时状态属进程内存态，服务一停就没了；
// 落一份快照，重启后计划扫描的「上次执行」仍能在扫描列表里打开查看。
// 写入失败只记日志：持久化是附加能力，不该让扫描本身报错。
func persistScanTask(t *Task) {
	if t == nil {
		return
	}
	item := t.listItem()

	rec := db2.ScanTaskRow{
		TaskID:     item.TaskID,
		Name:       item.Name,
		Status:     item.Status,
		Source:     item.Source,
		ScheduleID: item.ScheduleID,
		ProjectID:  item.ProjectID,
		Targets:    item.Targets,
		Hits:       item.Hits,
		HitTotal:   item.HitTotal,
		Percent:    item.Progress.Percent,
		Finished:   item.Progress.Finished,
		Total:      item.Progress.Total,
		ElapsedMs:  item.Progress.ElapsedMs,
		Error:      item.Error,
		CreatedAt:  item.CreatedAt,
		StartedAt:  item.StartedAt,
		EndedAt:    item.EndedAt,
	}
	if item.ScanInfo != nil {
		rec.TotalTargets = item.ScanInfo.TotalTargets
		rec.TotalPocs = item.ScanInfo.TotalPocs
		rec.TotalScans = item.ScanInfo.TotalScans
		rec.OOBEnabled = item.ScanInfo.OOBEnabled
		rec.OOBStatus = item.ScanInfo.OOBStatus
	}
	if err := sqlite.UpsertScanTask(rec); err != nil {
		gologger.Debug().Msgf("持久化扫描任务失败: taskId=%s err=%v", t.ID, err)
	}
}

// listScans 按创建时间倒序返回任务列表项（新的在前）。
//
// 数据来自两处：本进程内存中的任务（权威，含运行态），以及 sqlite 里的历史快照
// （本次启动之前跑过的任务）。同一个任务两边都有时以内存为准。
func (m *TaskManager) listScans() []scanListItem {
	m.mu.Lock()
	tasks := make([]*Task, 0, len(m.tasks))
	for _, t := range m.tasks {
		tasks = append(tasks, t)
	}
	m.mu.Unlock()

	out := make([]scanListItem, 0, len(tasks))
	inMemory := make(map[string]struct{}, len(tasks))
	for _, t := range tasks {
		out = append(out, t.listItem())
		inMemory[t.ID] = struct{}{}
	}
	out = append(out, historicalScanItems(inMemory)...)
	// 远程派发任务：本机只是发起端，任务与命中都在执行节点上。
	// 这里并入同一条列表，前端用 source=remote + node_name 标出来。
	out = append(out, remoteScanItems()...)

	// 两侧时间都已是 "2006-01-02 15:04:05" 的本地时间字符串，字典序即时间序。
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

// recentEndedWindow 是轻量轮询回看的「刚结束」窗口。
//
// 轮询间隔 10s，两次轮询之间起停的短任务（计划扫描里的常见情况）只能靠这个窗口
// 带给前端；没有它，这类任务要等下一次全量刷新才会出现在列表里。
const recentEndedWindow = 5 * time.Minute

// listScansActive 是轮询用的轻量口径：只返回内存中「活跃或刚结束」的任务，
// 外加同口径的远程任务。刻意不读 sqlite 历史——历史任务不会变化，
// 前端首次加载时取一次全量即可，每 10s 重读一遍（上限 200 条）纯属浪费。
func (m *TaskManager) listScansActive() []scanListItem {
	m.mu.Lock()
	tasks := make([]*Task, 0, len(m.tasks))
	for _, t := range m.tasks {
		tasks = append(tasks, t)
	}
	m.mu.Unlock()

	now := time.Now()
	out := make([]scanListItem, 0, len(tasks))
	for _, t := range tasks {
		if !isActive(t.Status()) && !endedRecently(t.ended(), now) {
			continue
		}
		out = append(out, t.listItem())
	}
	// 远程任务由对账协程维护，终态收敛不依赖这里的轮询；只带上仍在跑的，
	// 避免轻量轮询把 200 条已结束的远程记录一起重发。
	for _, rt := range remoteTaskSnapshot() {
		if !isActive(TaskStatus(rt.Status)) {
			continue
		}
		out = append(out, remoteTaskItem(rt))
	}

	// 与 listScans 保持同一排序口径：时间已是 "2006-01-02 15:04:05"，字典序即时间序。
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

// endedRecently 判断任务是否在给定窗口内收尾；未结束（零值）不算。
func endedRecently(endedAt, now time.Time) bool {
	if endedAt.IsZero() {
		return false
	}
	return now.Sub(endedAt) <= recentEndedWindow
}

// historicalScanItems 读取历史任务快照，跳过内存里已有的任务（以内存为准）。
func historicalScanItems(skip map[string]struct{}) []scanListItem {
	rows, err := sqlite.SelectScanTasks(0)
	if err != nil {
		gologger.Debug().Msgf("读取历史扫描任务失败: %v", err)
		return nil
	}
	out := make([]scanListItem, 0, len(rows))
	for _, row := range rows {
		if _, ok := skip[row.TaskID]; ok {
			continue
		}
		out = append(out, scanItemFromRow(row))
	}
	return out
}

// scanItemFromRow 把历史快照转成列表项。
//
// 快照里仍是 starting/running/paused，说明进程在扫描中途退出过（正常收尾会写成终态）：
// 这种任务已经没有可控制的进程，统一按「失败」呈现，与前端对僵尸任务的收敛口径一致。
func scanItemFromRow(row db2.ScanTaskRow) scanListItem {
	status := row.Status
	if isActive(TaskStatus(status)) {
		status = string(TaskFailed)
	}
	source := row.Source
	if source == "" {
		source = scanSourceManual
	}
	targets := row.Targets
	if targets == nil {
		targets = []string{}
	}
	hits := row.Hits
	if hits == nil {
		hits = map[string]int{}
	}
	// 按项目派发的任务没有目标清单（目标由服务端按项目成员决定），
	// 数量只能取引擎上报的 total_targets，否则列表会显示成 0。
	targetTotal := len(targets)
	if targetTotal == 0 {
		targetTotal = row.TotalTargets
	}

	item := scanListItem{
		TaskID:      row.TaskID,
		Name:        row.Name,
		Status:      status,
		Source:      source,
		ScheduleID:  row.ScheduleID,
		ProjectID:   row.ProjectID,
		Targets:     targets,
		Target:      firstTarget(targets),
		TargetTotal: targetTotal,
		CreatedAt:   row.CreatedAt,
		StartedAt:   row.StartedAt,
		EndedAt:     row.EndedAt,
		Progress: ScanProgressData{
			Percent:   row.Percent,
			Finished:  row.Finished,
			Total:     row.Total,
			ElapsedMs: row.ElapsedMs,
		},
		Hits:     hits,
		HitTotal: row.HitTotal,
		Error:    row.Error,
	}
	if row.TotalTargets > 0 || row.TotalPocs > 0 || row.TotalScans > 0 || row.OOBStatus != "" {
		item.ScanInfo = &scanInfoItem{
			TotalTargets: row.TotalTargets,
			TotalPocs:    row.TotalPocs,
			TotalScans:   row.TotalScans,
			OOBEnabled:   row.OOBEnabled,
			OOBStatus:    row.OOBStatus,
		}
	}
	return item
}

// launchScan 是「提交一次扫描」的核心路径：解析目标与 PoC 范围、登记任务、
// 沉淀资产、登记通知状态并放行执行。
//
// Web 起扫与计划调度器共用这条路径，保证两个入口的扫描行为完全一致；差异只在
// 前端特有的 enable_stream 校验（调度器没有订阅者，不需要事件流）。
func launchScan(req ScanCreateRequest, origin scanOrigin) (string, ScanInitInfo, error) {
	targets, err := resolveScanTargets(req)
	if err != nil {
		return "", ScanInitInfo{}, err
	}

	pocPath, appendPocs, useIDs := resolveScanPocs(req)

	source := strings.TrimSpace(origin.Source)
	if source == "" {
		source = scanSourceManual
	}

	id := nextTaskID(getTaskManager())
	m := getTaskManager()
	t := &Task{
		ID:               id,
		Name:             strings.TrimSpace(req.TaskName),
		status:           TaskStarting,
		CreatedAt:        time.Now(),
		spec:             buildScanSpec(req, targets, pocPath, appendPocs, useIDs),
		targets:          targets,
		source:           source,
		scheduleID:       strings.TrimSpace(origin.ScheduleID),
		projectID:        strings.TrimSpace(req.ProjectID),
		dispatchID:       strings.TrimSpace(origin.DispatchID),
		originInstanceID: strings.TrimSpace(origin.OriginInstanceID),
		originName:       strings.TrimSpace(origin.OriginName),
	}
	m.mu.Lock()
	m.tasks[id] = t
	m.mu.Unlock()

	// 资产自动沉淀：这次扫了哪些目标就记进资产表（source=scan/project）。
	// 用户零维护——扫过的目标自然成为「资产」，失败只记日志，不影响扫描。
	recordScanTargets(id, req.ProjectID, targets)

	logScanStart(id, req, targets)
	// 登记任务与项目的归属，供台账按项目聚合与项目扫描历史使用。
	_ = sqlite.LinkTaskProject(id, req.ProjectID)
	// 登记通知状态，后续命中与收尾消息要按任务去重与限流。
	getNotifier().OnTaskStart(id, t.Name)
	publish(t, ScanEvent{Type: "status", Data: map[string]string{"status": "starting"}})
	startTask(m, t)
	// 起扫即落一条快照：扫描中途服务被重启时，这条记录仍能作为历史任务被看到。
	persistScanTask(t)

	// 引擎的真实汇总（total_pocs/total_scans/oob_status）要等子进程跑起来才知道，
	// 由 scan_info 事件补发；这里先返回本地已知的目标信息，让前端立刻可渲染。
	displayTargets := targets
	if len(displayTargets) > 5 {
		displayTargets = displayTargets[:5]
	}
	scanInfo := ScanInitInfo{
		TotalTargets: len(targets),
		Targets:      displayTargets,
		OOBEnabled:   req.EnableOOB,
	}
	return id, scanInfo, nil
}

// resolveScanTargets 决定本次扫描的目标。
//
// 选中项目时以「项目引用的资产」为唯一目标来源：请求里手输的目标不再参与本次扫描，
// 否则任务会被整体归属到项目，导致手输/残留目标被计入项目，进而污染项目资产与台账。
func resolveScanTargets(req ScanCreateRequest) ([]string, error) {
	if projectID := strings.TrimSpace(req.ProjectID); projectID != "" {
		if _, ok := findProject(projectID); !ok {
			return nil, errProjectNotFound
		}
		targets := make([]string, 0, 128)
		for _, t := range resolveProjectTargets(projectID) {
			if isValidAddress(t) {
				targets = append(targets, normalizeAddress(t))
			}
		}
		if len(targets) == 0 {
			return nil, errNoProjectTargets
		}
		return targets, nil
	}

	targets := make([]string, 0, 128)
	for _, t := range req.Targets {
		ts := strings.TrimSpace(t)
		if ts != "" {
			targets = append(targets, normalizeAddress(ts))
		}
	}
	if len(targets) == 0 {
		return nil, errNoValidTargets
	}
	return targets, nil
}

// resolveScanPocs 解析 PoC 范围：优先显式 poc_file，其次按 poc_ids 落成临时目录，
// 都没有时按 poc_source 追加 curated / my 目录。
func resolveScanPocs(req ScanCreateRequest) (pocPath string, appendPocs []string, useIDs bool) {
	pocPath = strings.TrimSpace(req.PocFile)

	if pocPath == "" {
		src := strings.ToLower(strings.TrimSpace(req.PocSource))
		home, _ := os.UserHomeDir()
		curatedDir := filepath.Join(home, ".config", "afrog", "pocs-curated")
		myDir := filepath.Join(home, ".config", "afrog", "pocs-my")
		switch src {
		case "curated":
			appendPocs = append(appendPocs, curatedDir)
		case "my":
			appendPocs = append(appendPocs, myDir)
		default:
			appendPocs = append(appendPocs, curatedDir, myDir)
		}
	}

	if len(req.PocIDs) > 0 {
		tmpDir, err := os.MkdirTemp("", "afrog-pocids-")
		if err == nil {
			created := 0
			for _, pid := range req.PocIDs {
				pid = strings.TrimSpace(pid)
				if pid == "" {
					continue
				}
				y, err := readPocYamlByID(pid)
				if err != nil || y == nil || len(y) == 0 {
					continue
				}
				if writeErr := os.WriteFile(filepath.Join(tmpDir, pid+".yaml"), y, 0o600); writeErr == nil {
					created++
				}
			}
			if created > 0 {
				pocPath = tmpDir
				useIDs = true
			}
		}
	}
	return pocPath, appendPocs, useIDs
}

// logScanStart 记录一次扫描的受理信息（含非默认参数），便于排查「到底按什么参数跑的」。
func logScanStart(id string, req ScanCreateRequest, targets []string) {
	var logParts []string = []string{"start scan accepted:"}
	logParts = append(logParts, fmt.Sprintf("taskId=%s", id))
	logParts = append(logParts, fmt.Sprintf("targets=%d", len(targets)))
	if req.TaskName != "" {
		logParts = append(logParts, fmt.Sprintf("task_name=%s", req.TaskName))
	}
	if req.PocFile != "" {
		logParts = append(logParts, fmt.Sprintf("poc_file=%s", req.PocFile))
	}
	if req.PocSource != "" {
		logParts = append(logParts, fmt.Sprintf("poc_source=%s", req.PocSource))
	}
	if len(req.PocIDs) > 0 {
		logParts = append(logParts, fmt.Sprintf("poc_ids=%d", len(req.PocIDs)))
	}
	if req.Search != "" {
		logParts = append(logParts, fmt.Sprintf("search=%s", req.Search))
	}
	if req.Severity != "" {
		logParts = append(logParts, fmt.Sprintf("severity=%s", req.Severity))
	}
	if req.Concurrency != 0 {
		logParts = append(logParts, fmt.Sprintf("concurrency=%d", req.Concurrency))
	}
	if req.RateLimit != 0 {
		logParts = append(logParts, fmt.Sprintf("rate_limit=%d", req.RateLimit))
	}
	if req.Timeout != 0 {
		logParts = append(logParts, fmt.Sprintf("timeout=%d", req.Timeout))
	}
	if req.Retries != 0 {
		logParts = append(logParts, fmt.Sprintf("retries=%d", req.Retries))
	}
	if req.MaxHostError != 0 {
		logParts = append(logParts, fmt.Sprintf("max_host_error=%d", req.MaxHostError))
	}
	if req.Proxy != "" {
		logParts = append(logParts, fmt.Sprintf("proxy=%s", req.Proxy))
	}
	if req.FollowRedirects {
		logParts = append(logParts, fmt.Sprintf("follow_redirects=%t", req.FollowRedirects))
	}
	if req.EnableOOB {
		logParts = append(logParts, fmt.Sprintf("enable_oob=%t", req.EnableOOB))
	}
	if req.OOB != "" {
		logParts = append(logParts, fmt.Sprintf("oob=%s", req.OOB))
	}
	if req.OOBKey != "" {
		logParts = append(logParts, fmt.Sprintf("oob_key=%s", req.OOBKey))
	}
	if req.OOBDomain != "" {
		logParts = append(logParts, fmt.Sprintf("oob_domain=%s", req.OOBDomain))
	}
	if req.OOBApiUrl != "" {
		logParts = append(logParts, fmt.Sprintf("oob_api_url=%s", req.OOBApiUrl))
	}
	if req.OOBHttpUrl != "" {
		logParts = append(logParts, fmt.Sprintf("oob_http_url=%s", req.OOBHttpUrl))
	}
	if req.PortScan || req.PortScanCompat {
		logParts = append(logParts, fmt.Sprintf("portscan=%t", req.PortScan || req.PortScanCompat))
	}
	if req.Ports != "" {
		logParts = append(logParts, fmt.Sprintf("ports=%s", req.Ports))
	}
	if req.WebProbe || req.WebFingerprint {
		logParts = append(logParts, fmt.Sprintf("webprobe=%t", req.WebProbe || req.WebFingerprint))
	}
	if req.SkipHostDisc {
		logParts = append(logParts, fmt.Sprintf("skip_host_discovery=%t", req.SkipHostDisc))
	}
	if len(req.Labels) > 0 {
		logParts = append(logParts, fmt.Sprintf("labels=%d", len(req.Labels)))
	}
	if req.EnableStream {
		logParts = append(logParts, fmt.Sprintf("enable_stream=%t", req.EnableStream))
	}
	if req.Smart {
		logParts = append(logParts, fmt.Sprintf("smart=%t", req.Smart))
	}
	gologger.Debug().Msg(strings.Join(logParts, " "))
}

func readPocYamlByID(id string) ([]byte, error) {
	return pocsrepo.ReadYamlByID(id)
}

func scanEventsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := strings.TrimSpace(vars["taskId"])
	if taskID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少任务ID"})
		return
	}
	m := getTaskManager()
	m.mu.Lock()
	t := m.tasks[taskID]
	m.mu.Unlock()
	if t == nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "任务不存在"})
		return
	}
	w.Header().Del("Content-Type")
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	fl, _ := w.(http.Flusher)
	bw := bufio.NewWriter(w)
	writeEvent := func(ev ScanEvent) {
		_, _ = bw.WriteString("event: ")
		_, _ = bw.WriteString(ev.Type)
		_, _ = bw.WriteString("\n")
		// 带序号的事件同时写下 id：浏览器重连时会自动带上 Last-Event-ID 续传。
		if ev.Seq > 0 {
			_, _ = bw.WriteString("id: ")
			_, _ = bw.WriteString(strconv.FormatUint(ev.Seq, 10))
			_, _ = bw.WriteString("\n")
		}
		b, _ := json.Marshal(ev.Data)
		_, _ = bw.WriteString("data: ")
		_, _ = bw.Write(b)
		_, _ = bw.WriteString("\n\n")
		_ = bw.Flush()
		if fl != nil {
			fl.Flush()
		}
	}
	_, _ = bw.WriteString("\n")
	_ = bw.Flush()
	if fl != nil {
		fl.Flush()
	}

	fromSeq, replay := subscriptionStart(r)
	// 先订阅再补发，保证「补发期间产生的新事件」不会漏：
	// 订阅注册与历史快照在同一把锁内完成，二者按 seq 天然有序。
	ch, history := addSubscriber(t, fromSeq, replay)
	defer removeSubscriber(t, ch)

	for _, ev := range history {
		writeEvent(ev)
	}

	current := t.Status()
	// 兜底补一条当前状态：历史里最后一条 status 可能已被窗口截断。
	writeEvent(ScanEvent{Type: "status", Data: map[string]string{"status": string(current)}})
	if current == TaskCompleted || current == TaskFailed || current == TaskCancelled {
		return
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			writeEvent(ev)
			if ev.Type == "status" {
				switch data := ev.Data.(type) {
				case map[string]string:
					s := strings.ToLower(strings.TrimSpace(data["status"]))
					if s == string(TaskCompleted) || s == string(TaskFailed) || s == string(TaskCancelled) {
						return
					}
				case map[string]interface{}:
					raw, _ := data["status"].(string)
					s := strings.ToLower(strings.TrimSpace(raw))
					if s == string(TaskCompleted) || s == string(TaskFailed) || s == string(TaskCancelled) {
						return
					}
				}
			}
		}
	}
}

// subscriptionStart 解析订阅起点：
//   - replay=1（前端补录一个非本页发起的任务时显式要求）→ 从头补发缓冲区内的事件；
//   - Last-Event-ID / last_seq（浏览器自动重连或客户端自报进度）→ 从该序号之后续传；
//   - 都没有 → 只订阅新事件，保持既有行为，避免与本地已有记录重复。
func subscriptionStart(r *http.Request) (uint64, bool) {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("replay"))) {
	case "1", "true":
		return 0, true
	}

	raw := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	if raw == "" {
		raw = strings.TrimSpace(r.URL.Query().Get("last_seq"))
	}
	if raw != "" {
		if n, err := strconv.ParseUint(raw, 10, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}

func scanStatusHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := strings.TrimSpace(vars["taskId"])
	if taskID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少任务ID"})
		return
	}
	m := getTaskManager()
	m.mu.Lock()
	t := m.tasks[taskID]
	m.mu.Unlock()
	if t == nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "任务不存在"})
		return
	}
	snap := progressSnapshot(t)
	resp := ScanStatusData{
		Status:     string(t.Status()),
		Progress:   snap,
		TaskID:     taskID,
		InstanceID: serverInstanceID,
		BaseURL:    serverBaseURL,
	}
	resp.Stats.CompletedScans = snap.Finished
	resp.Stats.TotalScans = snap.Total
	resp.Stats.FoundVulns = t.hitCount()
	resp.Error = t.errMessage()
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: resp})
}

// scanTargetsHandler 按需下发单个任务的完整目标清单。
//
// 列表接口刻意不带全量目标（见 scanListItem.Targets），只有「重跑」这类确实要
// 复用目标的动作才来取一次，避免每 10s 一次的轮询把上千个目标重发一遍。
func scanTargetsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}
	taskID := strings.TrimSpace(mux.Vars(r)["taskId"])
	if taskID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少任务ID"})
		return
	}
	targets, ok := lookupScanTargets(taskID)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "任务不存在"})
		return
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: map[string]interface{}{
		"targets":      targets,
		"target_total": len(targets),
	}})
}

// lookupScanTargets 依次从内存任务、远程影子记录、sqlite 历史快照里取目标清单。
// ok=false 表示三处都没有这个任务。
func lookupScanTargets(taskID string) ([]string, bool) {
	m := getTaskManager()
	m.mu.Lock()
	t := m.tasks[taskID]
	m.mu.Unlock()
	if t != nil {
		return append([]string{}, t.getTargets()...), true
	}
	if rt := getRemoteTask(taskID); rt != nil {
		rt.mu.Lock()
		defer rt.mu.Unlock()
		return append([]string{}, rt.Targets...), true
	}
	row, err := sqlite.SelectScanTask(taskID)
	if err != nil {
		gologger.Debug().Msgf("读取任务目标失败: taskID=%s err=%v", taskID, err)
		return nil, false
	}
	if row == nil {
		return nil, false
	}
	return append([]string{}, row.Targets...), true
}

// 暂停任务
func scanPauseHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		gologger.Debug().Str("path", r.URL.Path).Msg("pause failed: method not allowed")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}
	vars := mux.Vars(r)
	taskID := strings.TrimSpace(vars["taskId"])
	if taskID == "" {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Debug().Str("path", r.URL.Path).Msg("pause failed: missing taskId")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少任务ID"})
		return
	}
	m := getTaskManager()
	m.mu.Lock()
	t := m.tasks[taskID]
	m.mu.Unlock()
	if t == nil {
		w.WriteHeader(http.StatusNotFound)
		gologger.Debug().Str("taskId", taskID).Msg("pause failed: task not found")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "任务不存在"})
		return
	}
	// 暂停/继续作用在子进程上：排队中（还没拉起子进程）与已结束的任务都没有
	// 可控制的进程，直接如实返回失败，避免前端显示一个假的「已暂停」。
	h := t.getHandle()
	if h == nil {
		w.WriteHeader(http.StatusConflict)
		gologger.Debug().Str("taskId", taskID).Msg("pause failed: task has no running process")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "任务尚未开始或已结束，无法暂停"})
		return
	}
	if err := h.Pause(); err != nil {
		w.WriteHeader(http.StatusConflict)
		gologger.Debug().Str("taskId", taskID).Str("error", err.Error()).Msg("pause failed")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: pauseErrorMessage(err, "暂停")})
		return
	}
	t.setStatus(TaskPaused)
	gologger.Debug().Str("taskId", taskID).Msg("pause succeeded: process suspended")
	publish(t, ScanEvent{Type: "status", Data: map[string]string{"status": string(TaskPaused)}})
	persistScanTask(t)
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "paused", Data: map[string]bool{"paused": true}})
}

// 恢复任务
func scanResumeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		gologger.Debug().Str("path", r.URL.Path).Msg("resume failed: method not allowed")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}
	vars := mux.Vars(r)
	taskID := strings.TrimSpace(vars["taskId"])
	if taskID == "" {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Debug().Str("path", r.URL.Path).Msg("resume failed: missing taskId")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少任务ID"})
		return
	}
	m := getTaskManager()
	m.mu.Lock()
	t := m.tasks[taskID]
	m.mu.Unlock()
	if t == nil {
		w.WriteHeader(http.StatusNotFound)
		gologger.Debug().Str("taskId", taskID).Msg("resume failed: task not found")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "任务不存在"})
		return
	}
	h := t.getHandle()
	if h == nil {
		w.WriteHeader(http.StatusConflict)
		gologger.Debug().Str("taskId", taskID).Msg("resume failed: task has no running process")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "任务尚未开始或已结束，无法继续"})
		return
	}
	if err := h.Resume(); err != nil {
		w.WriteHeader(http.StatusConflict)
		gologger.Debug().Str("taskId", taskID).Str("error", err.Error()).Msg("resume failed")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: pauseErrorMessage(err, "继续")})
		return
	}
	t.setStatus(TaskRunning)
	gologger.Debug().Str("taskId", taskID).Msg("resume succeeded: process resumed")
	publish(t, ScanEvent{Type: "status", Data: map[string]string{"status": string(TaskRunning)}})
	persistScanTask(t)
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "resumed", Data: map[string]bool{"resumed": true}})
}

// pauseErrorMessage 把执行器的暂停/继续错误翻译成给用户看的话术。
func pauseErrorMessage(err error, action string) string {
	switch {
	case errors.Is(err, executor.ErrPauseUnsupported):
		return "当前平台不支持" + action
	case errors.Is(err, executor.ErrAlreadyDone):
		return "任务已结束，无法" + action
	default:
		return action + "失败：" + err.Error()
	}
}

func scanStopHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		gologger.Debug().Str("path", r.URL.Path).Msg("stop failed: method not allowed")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}
	vars := mux.Vars(r)
	taskID := strings.TrimSpace(vars["taskId"])
	if taskID == "" {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Debug().Str("path", r.URL.Path).Msg("stop failed: missing taskId")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少任务ID"})
		return
	}
	if ok, msg := stopTaskByID(taskID); !ok {
		w.WriteHeader(http.StatusNotFound)
		gologger.Debug().Str("taskId", taskID).Msg("stop failed: task not found")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: msg})
		return
	}
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "stopped", Data: map[string]bool{"stopped": true}})
}

func calcRate(start time.Time, completed int64) int {
	secs := time.Since(start).Seconds()
	if secs <= 0 {
		return 0
	}
	return int(float64(completed) / secs)
}
