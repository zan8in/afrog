package web

import (
	"bufio"
	"context"
	"encoding/json"
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
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/sdk"
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
	Scanner       *sdk.Scanner
	SeverityStats map[string]int
	Subscribers   map[chan ScanEvent]struct{}

	mu        sync.Mutex
	status    TaskStatus
	startTime time.Time

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

	// Subscribe before starting the scan so that no event is missed.
	resultCh := t.Scanner.ResultStream()
	portCh := t.Scanner.PortStream()
	hostCh := t.Scanner.HostStream()
	webProbeCh := t.Scanner.WebProbeStream()
	phaseCh := t.Scanner.ProgressStream()
	scanInfoCh := t.Scanner.ScanInfoStream()

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			if resultCh == nil && portCh == nil && hostCh == nil && webProbeCh == nil && phaseCh == nil && scanInfoCh == nil {
				if t.Status() != TaskCancelled {
					finalizeTask(m, t, TaskCompleted)
				}
				return
			}
			select {
			case r, ok := <-resultCh:
				if !ok {
					resultCh = nil
					continue
				}
				sev := strings.ToLower(r.Severity)
				if t.SeverityStats == nil {
					t.SeverityStats = make(map[string]int)
				}
				t.SeverityStats[sev]++
				publish(t, ScanEvent{Type: "result", Data: map[string]interface{}{
					"target":   r.FullTarget,
					"severity": r.Severity,
					"poc": map[string]string{
						"id":   r.PocID,
						"name": r.PocName,
					},
					"message": fmt.Sprintf("命中 %s", r.Severity),
					"ts":      time.Now().UnixMilli(),
				}})
			case pr, ok := <-portCh:
				if !ok {
					portCh = nil
					continue
				}
				publish(t, ScanEvent{Type: "port", Data: map[string]interface{}{
					"host": pr.Host,
					"port": pr.Port,
					"ts":   time.Now().UnixMilli(),
				}})
			case hr, ok := <-hostCh:
				if !ok {
					hostCh = nil
					continue
				}
				publish(t, ScanEvent{Type: "host", Data: map[string]interface{}{
					"host": hr.Host,
					"ts":   time.Now().UnixMilli(),
				}})
			case wp, ok := <-webProbeCh:
				if !ok {
					webProbeCh = nil
					continue
				}
				publish(t, ScanEvent{Type: "webprobe", Data: map[string]interface{}{
					"url":        wp.URL,
					"title":      wp.Title,
					"server":     wp.Server,
					"powered_by": wp.PoweredBy,
					"ts":         time.Now().UnixMilli(),
				}})
			case pp, ok := <-phaseCh:
				if !ok {
					phaseCh = nil
					continue
				}
				publish(t, ScanEvent{Type: "phase_progress", Data: map[string]interface{}{
					"phase":    pp.Phase,
					"status":   pp.Status,
					"finished": pp.Finished,
					"total":    pp.Total,
					"percent":  pp.Percent,
					"ts":       time.Now().UnixMilli(),
				}})
			case si, ok := <-scanInfoCh:
				if !ok {
					scanInfoCh = nil
					continue
				}
				displayTargets := si.Targets
				if len(displayTargets) > 5 {
					displayTargets = displayTargets[:5]
				}
				publish(t, ScanEvent{Type: "scan_info", Data: map[string]interface{}{
					"total_targets": si.TotalTargets,
					"total_pocs":    si.TotalPocs,
					"total_scans":   si.TotalScans,
					"targets":       displayTargets,
					"oob_enabled":   si.OOBEnabled,
					"oob_status":    si.OOBStatus,
					"ts":            time.Now().UnixMilli(),
				}})
			case <-ticker.C:
				st := t.Scanner.Stats()
				prog := t.Scanner.Progress()
				publish(t, ScanEvent{Type: "progress", Data: map[string]interface{}{
					"percent":   int(prog + 0.5),
					"finished":  int(st.CompletedScans),
					"total":     st.TotalScans,
					"rate":      calcRate(t.started(), st.CompletedScans),
					"elapsedMs": time.Since(t.started()).Milliseconds(),
				}})
			}
		}
	}()
	_ = t.Scanner.Start(context.Background())
}

func finalizeTask(m *TaskManager, t *Task, status TaskStatus) {
	if t.finalized.Swap(true) {
		return
	}
	t.setStatus(status)
	if t.Scanner != nil {
		st := t.Scanner.Stats()
		prog := t.Scanner.Progress()
		publish(t, ScanEvent{Type: "progress", Data: map[string]interface{}{
			"percent":   int(prog + 0.5),
			"finished":  int(st.CompletedScans),
			"total":     st.TotalScans,
			"rate":      calcRate(t.started(), st.CompletedScans),
			"elapsedMs": time.Since(t.started()).Milliseconds(),
		}})
		oobEnabled, oobStatus := t.Scanner.OOBStatus()
		publish(t, ScanEvent{Type: "scan_info", Data: map[string]interface{}{
			"total_targets": st.TotalTargets,
			"total_pocs":    st.TotalPocs,
			"total_scans":   st.TotalScans,
			"oob_enabled":   oobEnabled,
			"oob_status":    oobStatus,
			"ts":            time.Now().UnixMilli(),
		}})
	}
	publish(t, ScanEvent{Type: "status", Data: map[string]string{"status": string(status)}})

	// Release the scanner's background goroutines. Without this a long-running
	// server accumulates one engine and one OOB poller per finished task.
	if t.Scanner != nil {
		_ = t.Scanner.Close()
	}

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

func persistHit(taskID string, r *result.Result) error {
	_, err := sqlite.InsertResultWithTaskID(r, taskID)
	return err
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

	sdkOpts := []sdk.Option{
		sdk.WithTargets(targets...),
		sdk.WithPocPaths(pocPath),
		sdk.WithPocPathsOnly(),
		// Persist the engine-level result so that the stored request and
		// response keep the exact shape the reports and UI expect.
		sdk.WithRawResultHandler(func(r *result.Result) {
			_ = persistHit(taskID, r)
		}),
	}
	if len(appendPocs) > 0 {
		sdkOpts = append(sdkOpts, sdk.WithPocPaths(appendPocs...))
	}
	if !useIDs {
		sdkOpts = append(sdkOpts,
			sdk.WithSearch(strings.TrimSpace(req.Search)),
			sdk.WithSeverity(strings.TrimSpace(req.Severity)),
		)
	}
	if req.Concurrency > 0 {
		sdkOpts = append(sdkOpts, sdk.WithConcurrency(req.Concurrency))
	}
	if req.RateLimit > 0 {
		sdkOpts = append(sdkOpts, sdk.WithRateLimit(req.RateLimit))
	}
	if req.Timeout > 0 {
		sdkOpts = append(sdkOpts, sdk.WithTimeout(req.Timeout))
	}
	if req.Retries > 0 {
		sdkOpts = append(sdkOpts, sdk.WithRetries(req.Retries))
	}
	if req.MaxHostError > 0 {
		sdkOpts = append(sdkOpts, sdk.WithMaxHostError(req.MaxHostError))
	}
	if v := strings.TrimSpace(req.Proxy); v != "" {
		sdkOpts = append(sdkOpts, sdk.WithProxy(v))
	}
	if req.Smart {
		sdkOpts = append(sdkOpts, sdk.WithSmartConcurrency())
	}
	if req.EnableOOB {
		sdkOpts = append(sdkOpts, sdk.WithOOB(sdk.OOBOptions{
			Adapter: strings.TrimSpace(req.OOB),
			Key:     strings.TrimSpace(req.OOBKey),
			Domain:  strings.TrimSpace(req.OOBDomain),
			ApiURL:  strings.TrimSpace(req.OOBApiUrl),
			HttpURL: strings.TrimSpace(req.OOBHttpUrl),
		}))
	}
	if req.PortScan || req.PortScanCompat {
		sdkOpts = append(sdkOpts, sdk.WithPortScan(sdk.PortScanOptions{
			Ports:         strings.TrimSpace(req.Ports),
			SkipDiscovery: req.SkipHostDisc,
		}))
	}
	if req.WebProbe || req.WebFingerprint {
		sdkOpts = append(sdkOpts, sdk.WithWebProbe())
	}

	scanner, err := sdk.New(context.Background(), sdkOpts...)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Debug().Str("path", r.URL.Path).Str("error", err.Error()).Msg("start scan failed: create scanner error")
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
		return
	}

	m := getTaskManager()
	id := taskID
	t := &Task{ID: id, Name: strings.TrimSpace(req.TaskName), status: TaskStarting, Scanner: scanner, CreatedAt: time.Now()}
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

	// 获取扫描初始化信息
	stats := scanner.Stats()
	oobEnabled, oobStatus := scanner.OOBStatus()

	// 获取扫描目标（截取前5个用于展示，与CLI保持一致）
	displayTargets := []string{}

	count := len(targets)
	if count > 5 {
		displayTargets = targets[:5]
	} else {
		displayTargets = targets
	}

	scanInfo := ScanInitInfo{
		TotalTargets: stats.TotalTargets,
		TotalPocs:    stats.TotalPocs,
		TotalScans:   stats.TotalScans,
		Targets:      displayTargets,
		OOBEnabled:   oobEnabled,
		OOBStatus:    oobStatus,
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
	st := t.Scanner.Stats()
	resp := ScanStatusData{
		Status: string(t.Status()),
		Progress: ScanProgressData{
			Percent:   int(t.Scanner.Progress() + 0.5),
			Finished:  int(st.CompletedScans),
			Total:     st.TotalScans,
			Rate:      calcRate(t.started(), st.CompletedScans),
			ElapsedMs: time.Since(t.started()).Milliseconds(),
		},
		TaskID:     taskID,
		InstanceID: serverInstanceID,
		BaseURL:    serverBaseURL,
	}
	resp.Stats.CompletedScans = int(st.CompletedScans)
	resp.Stats.TotalScans = st.TotalScans
	resp.Stats.FoundVulns = int(st.FoundVulns)
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
	t.Scanner.Pause()
	t.setStatus(TaskPaused)
	if t.Scanner.IsPaused() {
		gologger.Debug().Str("taskId", taskID).Msg("pause succeeded: engine gated")
	} else {
		gologger.Debug().Str("taskId", taskID).Msg("pause uncertain: engine not gated")
	}
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
	t.Scanner.Resume()
	t.setStatus(TaskRunning)
	if !t.Scanner.IsPaused() {
		gologger.Debug().Str("taskId", taskID).Msg("resume succeeded: engine released")
	} else {
		gologger.Debug().Str("taskId", taskID).Msg("resume uncertain: engine still gated")
	}
	publish(t, ScanEvent{Type: "status", Data: map[string]string{"status": string(TaskRunning)}})
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "resumed", Data: map[string]bool{"resumed": true}})
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
	t.Scanner.Stop()
	if t.Scanner.IsStopping() {
		gologger.Debug().Str("taskId", taskID).Msg("stop succeeded: context cancelled")
	} else {
		gologger.Debug().Str("taskId", taskID).Msg("stop uncertain: cancel flag not set")
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
