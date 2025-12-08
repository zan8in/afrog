package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	afrog "github.com/zan8in/afrog/v3"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/result"
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

type ScanEvent struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type Task struct {
	ID            string
	Name          string
	CreatedAt     time.Time
	Status        TaskStatus
	Scanner       *afrog.SDKScanner
	SeverityStats map[string]int
	Subscribers   map[chan []byte]struct{}
	mu            sync.Mutex
	startTime     time.Time
	lastProgress  time.Time
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
	b, _ := json.Marshal(ev)
	line := append(b, '\n')
	t.mu.Lock()
	for ch := range t.Subscribers {
		select {
		case ch <- line:
		default:
		}
	}
	t.mu.Unlock()
}

func addSubscriber(t *Task) chan []byte {
	ch := make(chan []byte, 256)
	t.mu.Lock()
	if t.Subscribers == nil {
		t.Subscribers = make(map[chan []byte]struct{})
	}
	t.Subscribers[ch] = struct{}{}
	t.mu.Unlock()
	return ch
}

func removeSubscriber(t *Task, ch chan []byte) {
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
		publish(t, ScanEvent{Type: "state", Data: map[string]string{"status": "starting"}})
		return
	}
	m.running++
	m.mu.Unlock()

	t.Status = TaskRunning
	t.startTime = time.Now()
	publish(t, ScanEvent{Type: "state", Data: map[string]string{"status": "running"}})

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case r, ok := <-t.Scanner.ResultChan:
				if !ok {
					finalizeTask(m, t, TaskCompleted)
					return
				}
				sev := strings.ToLower(r.PocInfo.Info.Severity)
				if t.SeverityStats == nil {
					t.SeverityStats = make(map[string]int)
				}
				t.SeverityStats[sev]++
				_ = persistHit(t.ID, r)
				publish(t, ScanEvent{Type: "hit", Data: map[string]interface{}{
					"target":   r.Target,
					"severity": r.PocInfo.Info.Severity,
					"poc": map[string]string{
						"id":   r.PocInfo.Id,
						"name": r.PocInfo.Info.Name,
					},
					"message": fmt.Sprintf("命中 %s", r.PocInfo.Info.Severity),
					"ts":      time.Now().UnixMilli(),
				}})
			case <-ticker.C:
				st := t.Scanner.GetStats()
				prog := t.Scanner.GetProgress()
				publish(t, ScanEvent{Type: "progress", Data: map[string]interface{}{
					"percent":   int(prog + 0.5),
					"finished":  int(st.CompletedScans),
					"total":     st.TotalScans,
					"rate":      calcRate(t.startTime, st.CompletedScans),
					"elapsedMs": time.Since(t.startTime).Milliseconds(),
				}})
			}
		}
	}()
	_ = t.Scanner.RunAsync()
}

func finalizeTask(m *TaskManager, t *Task, status TaskStatus) {
	t.Status = status
	publish(t, ScanEvent{Type: "state", Data: map[string]string{"status": string(status)}})
	m.mu.Lock()
	if m.running > 0 {
		m.running--
	}
	var nextID string
	if len(m.queue) > 0 {
		nextID = m.queue[0]
		m.queue = m.queue[1:]
	}
	m.mu.Unlock()
	if nextID != "" {
		if nt, ok := m.tasks[nextID]; ok {
			startTask(m, nt)
		}
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
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}

	var req ScanCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "无效的JSON格式"})
		return
	}
	if !req.EnableStream {
		w.WriteHeader(http.StatusBadRequest)
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
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "缺少有效扫描目标"})
		return
	}

	pocPath := strings.TrimSpace(req.PocFile)
	if pocPath == "" {
		src := strings.ToLower(strings.TrimSpace(req.PocSource))
		switch src {
		case "curated":
			home, _ := os.UserHomeDir()
			pocPath = filepath.Join(home, ".config", "afrog", "pocs-curated")
		case "my":
			home, _ := os.UserHomeDir()
			pocPath = filepath.Join(home, ".config", "afrog", "pocs-my")
		default:
			abs, _ := filepath.Abs("pocs/afrog-pocs")
			pocPath = abs
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

	sdkOpts := afrog.NewSDKOptions()
	sdkOpts.Targets = targets
	sdkOpts.PocFile = pocPath
	if useIDs {
		sdkOpts.Search = ""
		sdkOpts.Severity = ""
	} else {
		sdkOpts.Search = strings.TrimSpace(req.Search)
		sdkOpts.Severity = strings.TrimSpace(req.Severity)
	}
	if req.Concurrency > 0 {
		sdkOpts.Concurrency = req.Concurrency
	}
	if req.RateLimit > 0 {
		sdkOpts.RateLimit = req.RateLimit
	}
	if req.Timeout > 0 {
		sdkOpts.Timeout = req.Timeout
	}
	if req.Retries >= 0 {
		sdkOpts.Retries = req.Retries
	}
	if req.MaxHostError > 0 {
		sdkOpts.MaxHostError = req.MaxHostError
	}
	if strings.TrimSpace(req.Proxy) != "" {
		sdkOpts.Proxy = strings.TrimSpace(req.Proxy)
	}
	sdkOpts.EnableOOB = req.EnableOOB
	sdkOpts.OOB = strings.TrimSpace(req.OOB)
	sdkOpts.OOBKey = strings.TrimSpace(req.OOBKey)
	sdkOpts.OOBDomain = strings.TrimSpace(req.OOBDomain)
	sdkOpts.OOBApiUrl = strings.TrimSpace(req.OOBApiUrl)
	sdkOpts.OOBHttpUrl = strings.TrimSpace(req.OOBHttpUrl)
	sdkOpts.EnableStream = true

	scanner, err := afrog.NewSDKScanner(sdkOpts)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
		return
	}

	m := getTaskManager()
	id := nextTaskID(m)
	t := &Task{ID: id, Name: strings.TrimSpace(req.TaskName), Status: TaskStarting, Scanner: scanner, CreatedAt: time.Now()}
	m.mu.Lock()
	m.tasks[id] = t
	m.mu.Unlock()

	publish(t, ScanEvent{Type: "state", Data: map[string]string{"status": "starting"}})
	startTask(m, t)

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "created", Data: map[string]string{"taskId": id}})
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
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	fl, _ := w.(http.Flusher)
	ch := addSubscriber(t)
	defer removeSubscriber(t, ch)
	bw := bufio.NewWriter(w)
	_, _ = bw.WriteString("\n")
	_ = bw.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case line, ok := <-ch:
			if !ok {
				return
			}
			_, _ = bw.Write(line)
			_ = bw.Flush()
			if fl != nil {
				fl.Flush()
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
	st := t.Scanner.GetStats()
	resp := ScanStatusData{
		Status: string(t.Status),
		Progress: ScanProgressData{
			Percent:   int(t.Scanner.GetProgress() + 0.5),
			Finished:  int(st.CompletedScans),
			Total:     st.TotalScans,
			Rate:      calcRate(t.startTime, st.CompletedScans),
			ElapsedMs: time.Since(t.startTime).Milliseconds(),
		},
	}
	resp.Stats.CompletedScans = int(st.CompletedScans)
	resp.Stats.TotalScans = st.TotalScans
	resp.Stats.FoundVulns = int(st.FoundVulns)
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: resp})
}

func scanStopHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持POST方法"})
		return
	}
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
	t.Scanner.Stop()
	t.Status = TaskCancelled
	finalizeTask(m, t, TaskCancelled)
	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "stopped", Data: map[string]bool{"stopped": true}})
}

func calcRate(start time.Time, completed int32) int {
	secs := time.Since(start).Seconds()
	if secs <= 0 {
		return 0
	}
	return int(float64(completed) / secs)
}

// 使用 SDKScanner 自带的统计，已在 scanStatus/progress 中读取
