package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/gologger"
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
	PocID            string      `json:"poc_id"`  // 为了兼容旧接口，保留首个 POC 的 id
	PocIDs           []string    `json:"poc_ids"` // 新增：支持多个 POC
	Targets          []string    `json:"targets"`
	Options          TaskOptions `json:"options"`
	Status           TaskStatus  `json:"status"`
	TotalTargets     int         `json:"total_targets"`     // 目标×POC 的组合总数
	CompletedTargets int         `json:"completed_targets"` // 已完成组合数
	CreatedAt        time.Time   `json:"created_at"`
	LastHeartbeat    time.Time   `json:"last_heartbeat"`
	Error            string      `json:"error,omitempty"`

	cancel context.CancelFunc `json:"-"`
}

type ResultItem struct {
	Target    string         `json:"target"`
	PocID     string         `json:"poc_id"`
	Success   bool           `json:"success"`
	Message   string         `json:"message"`
	Response  map[string]any `json:"response,omitempty"`
	Error     string         `json:"error,omitempty"`
	LatencyMs int            `json:"latency,omitempty"`
	DbID      int64          `json:"db_id,omitempty"`
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
	gologger.Info().Msgf("TaskManager init: storage=%s workers=%d", storageRoot, workers)
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
	gologger.Info().Msgf("TaskManager started: workers=%d", m.workers)
}

func (m *TaskManager) worker(ctx context.Context, wid int) {
	for {
		select {
		case <-ctx.Done():
			gologger.Info().Msgf("TaskManager worker stopped: id=%d", wid)
			return
		case taskID := <-m.queue:
			gologger.Info().Msgf("TaskManager worker[%d] processing: task_id=%s", wid, taskID)
			m.runTask(ctx, taskID)
		}
	}
}

func (m *TaskManager) CreateTask(pocIDs []string, targets []string, options TaskOptions) (*Task, error) {
	if len(pocIDs) == 0 {
		return nil, errors.New("poc_ids 不能为空")
	}
	if len(targets) == 0 {
		return nil, errors.New("targets 不能为空")
	}
	taskID := fmt.Sprintf("%d-%06d", time.Now().Unix(), rand.Intn(1000000))
	task := &Task{
		ID:               taskID,
		PocID:            strings.TrimSpace(pocIDs[0]), // 兼容旧字段
		PocIDs:           pocIDs,
		Targets:          targets,
		Options:          options,
		Status:           StatusPending,
		TotalTargets:     len(targets) * len(pocIDs), // 目标×POC 的组合总数
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
	gologger.Info().Msgf("Task Created: task_id=%s poc_ids=%v targets=%v options=%+v total=%d", taskID, pocIDs, targets, options, task.TotalTargets)
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

// 扫描执行器注册：由外部（例如 afrog 包）注入真实扫描实现，避免 web 依赖 afrog 产生循环
type TaskScanInput struct {
	TaskID  string
	PocIDs  []string
	Targets []string
	Options TaskOptions
}

type TaskScanCallbacks struct {
	OnStatus   func(TaskStatus)
	OnProgress func(completed, total int)
	OnResult   func(ResultItem)
	OnError    func(string)
	OnEnded    func(TaskStatus)
}

var scanRunner func(ctx context.Context, in TaskScanInput, cb TaskScanCallbacks) error

func RegisterTaskScanRunner(r func(ctx context.Context, in TaskScanInput, cb TaskScanCallbacks) error) {
	scanRunner = r
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
	// 为取消提供独立的 task 级上下文
	taskCtx, cancel := context.WithCancel(ctx)
	task.cancel = cancel
	m.mu.Unlock()

	m.publish(taskID, SSEEvent{Type: "status", Data: task.Status})
	m.persist(taskID)
	gologger.Info().Msgf("RunTask Start: task_id=%s poc_ids=%v targets=%v total=%d", task.ID, task.PocIDs, task.Targets, task.TotalTargets)

	// 如果已注册真实扫描执行器，则使用它；否则回退到内置模拟执行
	if scanRunner != nil {
		gologger.Info().Msgf("RunTask: using external scanRunner for task_id=%s", task.ID)
		in := TaskScanInput{
			TaskID:  task.ID,
			PocIDs:  task.PocIDs,
			Targets: task.Targets,
			Options: task.Options,
		}
		err := scanRunner(taskCtx, in, TaskScanCallbacks{
			OnStatus: func(s TaskStatus) {
				m.mu.Lock()
				task.Status = s
				task.LastHeartbeat = time.Now()
				m.mu.Unlock()
				m.publish(taskID, SSEEvent{Type: "status", Data: s})
				m.persist(taskID)
				gologger.Info().Msgf("RunTask Status: task_id=%s status=%s", taskID, s)
			},
			OnProgress: func(completed, total int) {
				m.mu.Lock()
				task.CompletedTargets = completed
				// 保持 total 一致（可由外部自定义计算）
				if total > 0 {
					task.TotalTargets = total
				}
				task.LastHeartbeat = time.Now()
				m.mu.Unlock()
				m.publish(taskID, SSEEvent{
					Type: "progress",
					Data: map[string]int{
						"completed_targets": task.CompletedTargets,
						"total_targets":     task.TotalTargets,
					},
				})
				m.persist(taskID)
				gologger.Debug().Msgf("RunTask Progress: task_id=%s %d/%d", taskID, task.CompletedTargets, task.TotalTargets)
			},
			OnResult: func(res ResultItem) {
				// 外部可直接填充 DbID；若未填充，可后续调用 AttachTaskDbID 回填
				m.mu.Lock()
				task.LastHeartbeat = time.Now()
				m.results[taskID] = append(m.results[taskID], res)
				m.mu.Unlock()
				m.publish(taskID, SSEEvent{Type: "result", Data: res})
				m.persist(taskID)
				gologger.Info().Msgf("RunTask Result: task_id=%s target=%s poc_id=%s success=%v latency=%dms db_id=%d", taskID, res.Target, res.PocID, res.Success, res.LatencyMs, res.DbID)
			},
			OnError: func(msg string) {
				m.mu.Lock()
				task.Error = msg
				task.LastHeartbeat = time.Now()
				m.mu.Unlock()
				m.publish(taskID, SSEEvent{Type: "error", Data: msg})
				m.persist(taskID)
				gologger.Error().Msgf("RunTask Error: task_id=%s error=%s", taskID, msg)
			},
			OnEnded: func(s TaskStatus) {
				// 外部主动结束通知
				m.mu.Lock()
				task.Status = s
				task.LastHeartbeat = time.Now()
				m.mu.Unlock()
				m.publish(taskID, SSEEvent{Type: "status", Data: s})
				m.publish(taskID, SSEEvent{Type: "ended", Data: s})
				m.persist(taskID)
				gologger.Info().Msgf("RunTask Ended (external): task_id=%s status=%s", taskID, s)
			},
		})
		if err != nil {
			m.mu.Lock()
			task.Status = StatusFailed
			task.Error = fmt.Sprintf("扫描执行失败: %v", err)
			task.LastHeartbeat = time.Now()
			m.mu.Unlock()
			m.publish(taskID, SSEEvent{Type: "error", Data: task.Error})
			m.publish(taskID, SSEEvent{Type: "ended", Data: task.Status})
			m.persist(taskID)
			gologger.Error().Msgf("RunTask Failed: task_id=%s err=%v", taskID, err)
			return
		}
		// 若外部未调用 OnEnded，这里统一收尾（状态以最后一次回调为准）
		m.mu.Lock()
		if task.Status != StatusCanceled && task.Status != StatusFailed {
			task.Status = StatusCompleted
		}
		task.LastHeartbeat = time.Now()
		m.mu.Unlock()
		m.publish(taskID, SSEEvent{Type: "status", Data: task.Status})
		m.publish(taskID, SSEEvent{Type: "ended", Data: task.Status})
		m.persist(taskID)
		gologger.Info().Msgf("RunTask Completed: task_id=%s status=%s", taskID, task.Status)
		return
	}

	// 内置模拟执行（未注册真实扫描器时的降级逻辑）
	gologger.Info().Msgf("RunTask: fallback to simulated runner: task_id=%s", task.ID)
	for _, pocID := range task.PocIDs {
		yamlContent, err := LoadPocContent(pocID)
		if err != nil || yamlContent == "" {
			msg := fmt.Sprintf("根据 poc_id=%s 读取 YAML 失败或为空", pocID)
			m.publish(taskID, SSEEvent{Type: "error", Data: msg})
			gologger.Error().Msgf("SimRunner: load YAML failed: task_id=%s poc_id=%s err=%v", taskID, pocID, err)
			continue
		}
		for _, tgt := range task.Targets {
			select {
			case <-taskCtx.Done():
				// 任务被取消
				m.mu.Lock()
				task.Status = StatusCanceled
				task.LastHeartbeat = time.Now()
				m.mu.Unlock()
				m.publish(taskID, SSEEvent{Type: "status", Data: task.Status})
				m.publish(taskID, SSEEvent{Type: "ended", Data: task.Status})
				m.persist(taskID)
				gologger.Info().Msgf("SimRunner: canceled: task_id=%s", taskID)
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
				gologger.Info().Msgf("SimRunner: ended (canceled): task_id=%s", taskID)
				return
			}
			res := runPocOnce(yamlContent, pocID, tgt, task.Options)
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
			gologger.Info().Msgf("SimRunner Result: task_id=%s target=%s poc_id=%s success=%v latency=%dms", taskID, tgt, pocID, res.Success, res.LatencyMs)
		}
	}
	m.mu.Lock()
	task.Status = StatusCompleted
	task.LastHeartbeat = time.Now()
	m.mu.Unlock()
	m.publish(taskID, SSEEvent{Type: "status", Data: task.Status})
	m.publish(taskID, SSEEvent{Type: "ended", Data: task.Status})
	m.persist(taskID)
	gologger.Info().Msgf("SimRunner Completed: task_id=%s", taskID)
}

func runPocOnce(yaml string, pocID string, target string, _ TaskOptions) ResultItem {
	start := time.Now()
	time.Sleep(time.Duration(300+rand.Intn(700)) * time.Millisecond)
	ok := rand.Intn(2) == 0
	msg := "ok"
	return ResultItem{
		Target:    target,
		PocID:     pocID,
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
	// 通过取消上下文通知外部执行器停止
	if t.cancel != nil {
		t.cancel()
	}
	t.Status = StatusCanceled
	m.publish(taskID, SSEEvent{Type: "status", Data: t.Status})
	m.persist(taskID)
	gologger.Info().Msgf("Task Canceled: task_id=%s", taskID)
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
		gologger.Info().Msgf("Task Paused: task_id=%s", taskID)
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
		gologger.Info().Msgf("Task Resumed: task_id=%s", taskID)
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
		taskManager = NewTaskManager("~/afrog-task", 1)
		ctx := context.Background()
		taskManager.Start(ctx)
	})
	return taskManager
}

// AttachDbID 允许外部在写入 sqlite 后，回填对应任务结果项的数据库主键 id
func (m *TaskManager) AttachDbID(taskID string, pocID string, target string, dbID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := m.results[taskID]
	// 倒序尝试匹配最近的结果项
	for i := len(items) - 1; i >= 0; i-- {
		if items[i].PocID == pocID && items[i].Target == target && items[i].DbID == 0 {
			items[i].DbID = dbID
			m.results[taskID][i] = items[i]
			// 也可推送一个事件（可选）
			m.publish(taskID, SSEEvent{Type: "result_db_linked", Data: items[i]})
			m.persist(taskID)
			return nil
		}
	}
	return errors.New("未找到匹配的结果项，无法关联 db_id")
}

// AttachTaskDbID 便捷函数（懒单例）
func AttachTaskDbID(taskID string, pocID string, target string, dbID int64) error {
	return EnsureTaskManager().AttachDbID(taskID, pocID, target, dbID)
}

// 准备临时 POC 目录：将所选 POC 的 YAML 写入临时目录
func prepareTempPocsDir(pocIDs []string) (string, error) {
	dir, err := os.MkdirTemp("", "afrog-pocs-*")
	if err != nil {
		return "", err
	}
	wrote := 0
	for _, id := range pocIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		bs, err := pocsrepo.ReadYamlByID(id)
		if err != nil || len(bs) == 0 {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, id+".yaml"), bs, 0o644); err != nil {
			continue
		}
		wrote++
	}
	if wrote == 0 {
		_ = os.RemoveAll(dir)
		return "", errors.New("未能写入任何 POC YAML")
	}
	return dir, nil
}

// sqlite 初始化（惰性一次）
var sqliteOnce sync.Once

func ensureSqlite() {
	sqliteOnce.Do(func() {
		_ = sqlite.NewWebSqliteDB()
		_ = sqlite.InitX()
		gologger.Info().Msg("SQLite initialized for web tasks")
	})
}
