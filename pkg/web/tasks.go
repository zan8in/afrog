package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
)

type TaskStatus string

const (
	StatusPending   TaskStatus = "pending"
	StatusRunning   TaskStatus = "running"
	StatusCompleted TaskStatus = "completed"
	StatusFailed    TaskStatus = "failed"
	StatusCanceled  TaskStatus = "canceled"
	StatusPaused    TaskStatus = "paused"
)

type TaskOptions struct {
	Timeout         int    `json:"timeout,omitempty"`
	FollowRedirects bool   `json:"follow_redirects,omitempty"`
	MaxRedirects    int    `json:"max_redirects,omitempty"`
	UserAgent       string `json:"user_agent,omitempty"`
	Concurrency     int    `json:"concurrency,omitempty"`
}

type Task struct {
	ID               string      `json:"task_id"`
	PocID            string      `json:"poc_id"`
	Targets          []string    `json:"targets"`
	Options          TaskOptions `json:"options"`
	Status           TaskStatus  `json:"status"`
	TotalTargets     int         `json:"total_targets"`
	CompletedTargets int         `json:"completed_targets"`
	CreatedAt        time.Time   `json:"created_at"`
	LastHeartbeat    time.Time   `json:"last_heartbeat"`
	Error            string      `json:"error,omitempty"`
}

type ResultItem struct {
	Target    string         `json:"target"`
	Success   bool           `json:"success"`
	Message   string         `json:"message"`
	Response  map[string]any `json:"response,omitempty"`
	Error     string         `json:"error,omitempty"`
	LatencyMs int            `json:"latency,omitempty"`
}

type SSEEvent struct {
	Type string      `json:"type"` // "status" | "progress" | "result" | "ended" | "error" | "heartbeat"
	Data interface{} `json:"data"`
}

type subscriber chan SSEEvent

type TaskManager struct {
	mu          sync.RWMutex
	tasks       map[string]*Task
	results     map[string][]ResultItem
	subs        map[string]map[subscriber]struct{}
	queue       chan string
	workers     int
	storageRoot string
}

func NewTaskManager(storageRoot string, workers int) *TaskManager {
	if workers <= 0 {
		workers = 2
	}
	_ = os.MkdirAll(filepath.Join(storageRoot, "tasks"), 0o755)
	return &TaskManager{
		tasks:       make(map[string]*Task),
		results:     make(map[string][]ResultItem),
		subs:        make(map[string]map[subscriber]struct{}),
		queue:       make(chan string, 1024),
		workers:     workers,
		storageRoot: storageRoot,
	}
}

func (m *TaskManager) Start(ctx context.Context) {
	for i := 0; i < m.workers; i++ {
		go m.worker(ctx, i)
	}
}

func (m *TaskManager) worker(ctx context.Context, _ int) {
	for {
		select {
		case <-ctx.Done():
			return
		case taskID := <-m.queue:
			m.runTask(ctx, taskID)
		}
	}
}

func (m *TaskManager) CreateTask(pocID string, targets []string, options TaskOptions) (*Task, error) {
	if pocID == "" {
		return nil, errors.New("poc_id 不能为空")
	}
	if len(targets) == 0 {
		return nil, errors.New("targets 不能为空")
	}
	taskID := fmt.Sprintf("%d-%06d", time.Now().Unix(), rand.Intn(1000000))
	task := &Task{
		ID:               taskID,
		PocID:            pocID,
		Targets:          targets,
		Options:          options,
		Status:           StatusPending,
		TotalTargets:     len(targets),
		CompletedTargets: 0,
		CreatedAt:        time.Now(),
		LastHeartbeat:    time.Now(),
	}
	m.mu.Lock()
	m.tasks[taskID] = task
	m.mu.Unlock()
	m.persist(taskID)
	m.publish(taskID, SSEEvent{Type: "status", Data: task.Status})
	m.queue <- taskID
	return task, nil
}

func (m *TaskManager) GetTask(taskID string) (*Task, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tasks[taskID]
	if !ok {
		return nil, errors.New("task 不存在")
	}
	return t, nil
}

func (m *TaskManager) GetResults(taskID string) ([]ResultItem, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items, ok := m.results[taskID]
	if !ok {
		return nil, nil
	}
	return items, nil
}

func (m *TaskManager) Subscribe(taskID string) (subscriber, func()) {
	ch := make(subscriber, 256)
	m.mu.Lock()
	if _, ok := m.subs[taskID]; !ok {
		m.subs[taskID] = make(map[subscriber]struct{})
	}
	m.subs[taskID][ch] = struct{}{}
	m.mu.Unlock()
	cancel := func() {
		m.mu.Lock()
		if subs, ok := m.subs[taskID]; ok {
			delete(subs, ch)
			close(ch)
		}
		m.mu.Unlock()
	}
	return ch, cancel
}

func (m *TaskManager) publish(taskID string, evt SSEEvent) {
	m.mu.RLock()
	subs := m.subs[taskID]
	m.mu.RUnlock()
	for s := range subs {
		select {
		case s <- evt:
		default:
			// 丢弃慢订阅者
		}
	}
}

func (m *TaskManager) persist(taskID string) {
	m.mu.RLock()
	task := m.tasks[taskID]
	results := m.results[taskID]
	m.mu.RUnlock()
	if task == nil {
		return
	}
	snap := struct {
		Task    *Task        `json:"task"`
		Results []ResultItem `json:"results"`
	}{Task: task, Results: results}
	data, _ := json.MarshalIndent(snap, "", "  ")
	_ = os.WriteFile(m.snapshotPath(taskID), data, 0o644)
}

func (m *TaskManager) snapshotPath(taskID string) string {
	return filepath.Join(m.storageRoot, "tasks", taskID+".json")
}

func (m *TaskManager) runTask(ctx context.Context, taskID string) {
	m.mu.Lock()
	task := m.tasks[taskID]
	if task == nil {
		m.mu.Unlock()
		return
	}
	task.Status = StatusRunning
	task.LastHeartbeat = time.Now()
	m.mu.Unlock()
	m.publish(taskID, SSEEvent{Type: "status", Data: task.Status})
	m.persist(taskID)

	yamlContent, err := LoadPocContent(task.PocID)
	if err != nil || yamlContent == "" {
		m.mu.Lock()
		task.Status = StatusFailed
		task.Error = "根据 poc_id 读取 YAML 失败或为空"
		task.LastHeartbeat = time.Now()
		m.mu.Unlock()
		m.publish(taskID, SSEEvent{Type: "error", Data: task.Error})
		m.publish(taskID, SSEEvent{Type: "ended", Data: task.Status})
		m.persist(taskID)
		return
	}

	for _, tgt := range task.Targets {
		select {
		case <-ctx.Done():
			return
		default:
		}
		m.mu.RLock()
		st := task.Status
		m.mu.RUnlock()
		if st == StatusPaused {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if st == StatusCanceled {
			m.publish(taskID, SSEEvent{Type: "ended", Data: task.Status})
			m.persist(taskID)
			return
		}

		res := runPocOnce(yamlContent, tgt, task.Options)
		m.mu.Lock()
		task.CompletedTargets++
		task.LastHeartbeat = time.Now()
		m.results[taskID] = append(m.results[taskID], res)
		m.mu.Unlock()

		m.publish(taskID, SSEEvent{
			Type: "progress",
			Data: map[string]int{
				"completed_targets": task.CompletedTargets,
				"total_targets":     task.TotalTargets,
			},
		})
		m.publish(taskID, SSEEvent{Type: "result", Data: res})
		m.persist(taskID)
	}

	m.mu.Lock()
	task.Status = StatusCompleted
	task.LastHeartbeat = time.Now()
	m.mu.Unlock()
	m.publish(taskID, SSEEvent{Type: "status", Data: task.Status})
	m.publish(taskID, SSEEvent{Type: "ended", Data: task.Status})
	m.persist(taskID)
}

func runPocOnce(yaml string, target string, _ TaskOptions) ResultItem {
	start := time.Now()
	time.Sleep(time.Duration(300+rand.Intn(700)) * time.Millisecond)
	ok := rand.Intn(2) == 0
	msg := "ok"
	return ResultItem{
		Target:    target,
		Success:   ok,
		Message:   msg,
		LatencyMs: int(time.Since(start) / time.Millisecond),
	}
}

func (m *TaskManager) Cancel(taskID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.tasks[taskID]
	if t == nil {
		return errors.New("task 不存在")
	}
	t.Status = StatusCanceled
	m.publish(taskID, SSEEvent{Type: "status", Data: t.Status})
	m.persist(taskID)
	return nil
}

func (m *TaskManager) Pause(taskID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.tasks[taskID]
	if t == nil {
		return errors.New("task 不存在")
	}
	if t.Status == StatusRunning {
		t.Status = StatusPaused
		m.publish(taskID, SSEEvent{Type: "status", Data: t.Status})
		m.persist(taskID)
	}
	return nil
}

func (m *TaskManager) Resume(taskID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.tasks[taskID]
	if t == nil {
		return errors.New("task 不存在")
	}
	if t.Status == StatusPaused {
		t.Status = StatusRunning
		m.publish(taskID, SSEEvent{Type: "status", Data: t.Status})
		m.persist(taskID)
	}
	return nil
}

// LoadPocContent 使用仓库层从任意来源读取原始 YAML
func LoadPocContent(pocID string) (string, error) {
	bs, err := pocsrepo.ReadYamlByID(pocID)
	if err != nil {
		return "", err
	}
	return string(bs), nil
}

// 懒初始化任务管理器，避免修改 StartServer
var (
	taskOnce    sync.Once
	taskManager *TaskManager
)

func EnsureTaskManager() *TaskManager {
	taskOnce.Do(func() {
		taskManager = NewTaskManager("~/afrog-task", 2)
		ctx := context.Background()
		taskManager.Start(ctx)
	})
	return taskManager
}
