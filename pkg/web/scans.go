package web

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/scanstream"
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

type ScanEvent struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
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

	// spec 是本次扫描的规格快照，排队到真正执行时由 runScanTask 使用。
	spec *executor.Spec
	// targets 保留原始目标列表，scan_info 事件只展示前 5 个。
	targets []string

	mu        sync.Mutex
	status    TaskStatus
	startTime time.Time
	handle    executor.Handle
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

func nextTaskID(m *TaskManager) string {
	d := time.Now().Format("20060102")
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seqByDate[d]++
	return fmt.Sprintf("%s-%05d", d, m.seqByDate[d])
}

func publish(t *Task, ev ScanEvent) {
	t.mu.Lock()
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

func addSubscriber(t *Task) chan ScanEvent {
	ch := make(chan ScanEvent, 256)
	t.mu.Lock()
	if t.Subscribers == nil {
		t.Subscribers = make(map[chan ScanEvent]struct{})
	}
	t.Subscribers[ch] = struct{}{}
	t.mu.Unlock()
	return ch
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

	targets := make([]string, 0, 128)
	for _, t := range req.Targets {
		ts := strings.TrimSpace(t)
		if ts != "" {
			targets = append(targets, normalizeAddress(ts))
		}
	}
	if req.AssetSetID != "" {
		path, _, _, err := assetFilePathFromID(req.AssetSetID)
		if err == nil {
			lines, _ := readLines(path)
			for _, line := range lines {
				if isValidAddress(line) {
					targets = append(targets, normalizeAddress(line))
				}
			}
		}
	}
	if len(targets) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Debug().Str("path", r.URL.Path).Msg("start scan failed: no valid targets")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少有效扫描目标"})
		return
	}

	pocPath := strings.TrimSpace(req.PocFile)
	var appendPocs []string

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

	useIDs := false
	if len(req.PocIDs) > 0 {
		tmpDir, err := os.MkdirTemp("", "afrog-pocids-")
		if err == nil {
			created := 0
			for _, id := range req.PocIDs {
				id = strings.TrimSpace(id)
				if id == "" {
					continue
				}
				y, err := readPocYamlByID(id)
				if err != nil || y == nil || len(y) == 0 {
					continue
				}
				if writeErr := os.WriteFile(filepath.Join(tmpDir, id+".yaml"), y, 0o600); writeErr == nil {
					created++
				}
			}
			if created > 0 {
				pocPath = tmpDir
				useIDs = true
			}
		}
	}

	taskID := nextTaskID(getTaskManager())

	m := getTaskManager()
	id := taskID
	t := &Task{
		ID:        id,
		Name:      strings.TrimSpace(req.TaskName),
		status:    TaskStarting,
		CreatedAt: time.Now(),
		spec:      buildScanSpec(req, targets, pocPath, appendPocs, useIDs),
		targets:   targets,
	}
	m.mu.Lock()
	m.tasks[id] = t
	m.mu.Unlock()

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
	if req.AssetSetID != "" {
		logParts = append(logParts, fmt.Sprintf("asset_set_id=%s", req.AssetSetID))
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
	publish(t, ScanEvent{Type: "status", Data: map[string]string{"status": "starting"}})
	startTask(m, t)

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

	current := t.Status()
	writeEvent(ScanEvent{Type: "status", Data: map[string]string{"status": string(current)}})
	if current == TaskCompleted || current == TaskFailed || current == TaskCancelled {
		return
	}

	ch := addSubscriber(t)
	defer removeSubscriber(t, ch)
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
	m := getTaskManager()
	m.mu.Lock()
	t := m.tasks[taskID]
	m.mu.Unlock()
	if t == nil {
		w.WriteHeader(http.StatusNotFound)
		gologger.Debug().Str("taskId", taskID).Msg("stop failed: task not found")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "任务不存在"})
		return
	}
	// 先结束子进程（SIGTERM → 宽限期 → SIGKILL），再收尾任务。
	if h := t.getHandle(); h != nil {
		if err := h.Cancel(); err != nil && !errors.Is(err, executor.ErrAlreadyDone) {
			gologger.Debug().Str("taskId", taskID).Str("error", err.Error()).Msg("stop: cancel process failed")
		} else {
			gologger.Debug().Str("taskId", taskID).Msg("stop succeeded: process terminated")
		}
	}
	t.setStatus(TaskCancelled)
	finalizeTask(m, t, TaskCancelled)
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "stopped", Data: map[string]bool{"stopped": true}})
}

func calcRate(start time.Time, completed int64) int {
	secs := time.Since(start).Seconds()
	if secs <= 0 {
		return 0
	}
	return int(float64(completed) / secs)
}
