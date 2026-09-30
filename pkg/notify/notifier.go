package notify

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// sendTimeout 限定单次渠道发送的最长等待，避免网络挂住时占着 goroutine。
const sendTimeout = 15 * time.Second

// severityOrder 用于汇总消息里的级别展示顺序（高 → 低）。
var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// Sender 抽象「怎么把一条消息发给一个渠道」，便于测试替换。
type Sender func(ctx context.Context, ch Channel, msg Message) error

// TaskResult 是任务收尾时用于组装汇总消息的数据快照。
type TaskResult struct {
	TaskName string
	Targets  []string
	// Status 取 completed / failed / cancelled 等终态。
	Status     string
	Err        string
	Hits       int
	Scans      int
	Elapsed    time.Duration
	BySeverity map[string]int
}

// taskState 是单个任务的通知状态：去重集合与推送计数。
type taskState struct {
	name string
	seen map[string]struct{}
	// sent 是已实际推送的实时条数，suppressed 是超限被压掉的条数。
	sent       int
	suppressed int
}

// Notifier 负责把扫描事件按配置扇出到各个渠道。
//
// 配置常驻内存（由 Web 层在启动与保存后注入），热路径上不读磁盘。
type Notifier struct {
	mu     sync.Mutex
	cfg    Config
	tasks  map[string]*taskState
	sender Sender
	// log 保留最近的发送记录，让用户在界面上看到「发出去没有」。
	log *deliveryLog
	// projectOf 解析任务所属项目，供「按项目订阅」过滤使用。
	// notify 包不直接依赖数据库，由 Web 层注入。
	projectOf func(taskID string) string
}

func NewNotifier() *Notifier {
	return &Notifier{
		cfg:    DefaultConfig(),
		tasks:  make(map[string]*taskState),
		sender: sendChannel,
		log:    newDeliveryLog(),
	}
}

// SetConfig 替换运行中的配置。保存配置后由 Web 层调用。
func (n *Notifier) SetConfig(cfg Config) {
	n.mu.Lock()
	n.cfg = cfg
	n.mu.Unlock()
}

// SetProjectResolver 注入「任务 → 所属项目 ID」的查询函数，供按项目订阅过滤。
// 未注入时视为不做项目过滤，避免通知被静默吞掉。
func (n *Notifier) SetProjectResolver(fn func(taskID string) string) {
	n.mu.Lock()
	n.projectOf = fn
	n.mu.Unlock()
}

// projectAllowed 判断任务是否落在「按项目订阅」白名单内。
// 未配置白名单一律放行；配置了白名单但任务不属于任何项目，则不推送。
func projectAllowed(projectIDs []string, resolve func(string) string, taskID string) bool {
	if len(projectIDs) == 0 || resolve == nil {
		return true
	}
	pid := strings.TrimSpace(resolve(taskID))
	if pid == "" {
		return false
	}
	for _, want := range projectIDs {
		if want == pid {
			return true
		}
	}
	return false
}

// Config 返回当前配置快照。
func (n *Notifier) Config() Config {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.cfg
}

// OnTaskStart 登记任务名称，供后续命中消息与汇总消息使用。
func (n *Notifier) OnTaskStart(taskID, taskName string) {
	if strings.TrimSpace(taskID) == "" {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()

	if taskName == "" {
		taskName = taskID
	}
	n.tasks[taskID] = &taskState{name: taskName, seen: make(map[string]struct{})}
}

// Forget 释放任务状态。任务收尾后调用，避免 map 无界增长。
func (n *Notifier) Forget(taskID string) {
	n.mu.Lock()
	delete(n.tasks, taskID)
	n.mu.Unlock()
}

// OnHit 在命中达到阈值时实时推送。
//
// 两个防刷屏措施：同一「PoC + 目标」只推一次；单任务推送条数不超过配置上限，
// 超出的部分只计数，最终体现在汇总消息里。
func (n *Notifier) OnHit(taskID, severity, pocID, pocName, target string) {
	sev := strings.ToLower(strings.TrimSpace(severity))

	// 先做廉价的配置快照与过滤：总开关、事件、级别、项目白名单任一不满足
	// 就直接返回，不必进入临界区，也不必碰任务状态。
	// 项目归属要查库，所以放在锁外做，避免持锁等待 I/O。
	n.mu.Lock()
	cfg := n.cfg
	resolve := n.projectOf
	n.mu.Unlock()

	if !cfg.Enabled || !cfg.Events.VulnFound || !severityAtLeast(cfg.Severity, sev) {
		return
	}
	if !projectAllowed(cfg.ProjectIDs, resolve, taskID) {
		return
	}

	n.mu.Lock()
	st := n.tasks[taskID]
	if st == nil {
		n.mu.Unlock()
		return
	}

	key := pocID + "\x00" + target
	if _, dup := st.seen[key]; dup {
		n.mu.Unlock()
		return
	}
	st.seen[key] = struct{}{}

	if st.sent >= cfg.MaxPerTask {
		st.suppressed++
		n.mu.Unlock()
		return
	}
	st.sent++
	name := st.name
	n.mu.Unlock()

	n.dispatch(cfg, Message{
		Title: "afrog 发现漏洞",
		Level: sev,
		Lines: []string{
			fmt.Sprintf("任务：%s", name),
			fmt.Sprintf("级别：%s", strings.ToUpper(sev)),
			fmt.Sprintf("PoC：%s%s", pocID, pocNameSuffix(pocName)),
			fmt.Sprintf("目标：%s", target),
			fmt.Sprintf("时间：%s", time.Now().Format("2006-01-02 15:04:05")),
		},
		Extra: map[string]any{
			"event":     "vuln_found",
			"task_id":   taskID,
			"task_name": name,
			"severity":  sev,
			"poc_id":    pocID,
			"target":    target,
		},
	})
}

// OnTaskDone 在任务收尾时推送汇总，或在失败/终止时推送异常提醒。
func (n *Notifier) OnTaskDone(taskID string, res TaskResult) {
	n.mu.Lock()
	cfg := n.cfg
	resolve := n.projectOf
	st := n.tasks[taskID]
	sent, suppressed := 0, 0
	name := res.TaskName
	if st != nil {
		sent, suppressed = st.sent, st.suppressed
		if name == "" {
			name = st.name
		}
	}
	delete(n.tasks, taskID)
	n.mu.Unlock()

	if !cfg.Enabled {
		return
	}
	// 项目白名单：不在订阅范围内的任务只清理状态，不发消息。
	if !projectAllowed(cfg.ProjectIDs, resolve, taskID) {
		return
	}
	if name == "" {
		name = taskID
	}

	if res.Status == "completed" {
		if !cfg.Events.TaskCompleted {
			return
		}
		n.dispatch(cfg, completedMessage(taskID, name, res, sent, suppressed, cfg.MaxPerTask))
		return
	}

	if !cfg.Events.TaskFailed {
		return
	}
	n.dispatch(cfg, failedMessage(taskID, name, res))
}

// dispatch 异步扇出到全部启用渠道。发送失败只记发送记录与日志，绝不影响扫描。
func (n *Notifier) dispatch(cfg Config, msg Message) {
	channels := enabledChannels(cfg)
	if len(channels) == 0 {
		return
	}

	sender := n.sender
	go func() {
		ctx := context.Background()
		for _, ch := range channels {
			n.deliver(ctx, sender, ch, msg)
		}
	}()
}

// TestResult 是单个渠道的测试发送结果。
type TestResult struct {
	ChannelID   string `json:"channel_id"`
	ChannelName string `json:"channel_name"`
	OK          bool   `json:"ok"`
	Error       string `json:"error,omitempty"`
	Attempts    int    `json:"attempts"`
	DurationMS  int64  `json:"duration_ms"`
}

// Test 向指定渠道发送测试消息；channelID 为空时对全部启用渠道发送。
// 与正式通知不同，这里同步等待结果，调用方要的就是「通没通」。
func (n *Notifier) Test(ctx context.Context, channelID string) ([]TestResult, error) {
	n.mu.Lock()
	cfg := n.cfg
	sender := n.sender
	n.mu.Unlock()

	var targets []Channel
	if id := strings.TrimSpace(channelID); id != "" {
		for _, ch := range cfg.Channels {
			if ch.ID == id {
				targets = append(targets, ch)
				break
			}
		}
		if len(targets) == 0 {
			return nil, fmt.Errorf("channel not found: %s", id)
		}
	} else {
		targets = enabledChannels(cfg)
		if len(targets) == 0 {
			return nil, fmt.Errorf("no enabled channel to test")
		}
	}

	msg := Message{
		Title: "afrog 通知测试",
		Lines: []string{
			"这是一条测试消息，收到即表示渠道配置可用。",
			fmt.Sprintf("时间：%s", time.Now().Format(timeLayout)),
		},
		Extra: map[string]any{"event": "test"},
	}

	out := make([]TestResult, 0, len(targets))
	for _, ch := range targets {
		rec := n.deliver(ctx, sender, ch, msg)
		out = append(out, TestResult{
			ChannelID:   ch.ID,
			ChannelName: ch.Name,
			OK:          rec.OK,
			Error:       rec.Error,
			Attempts:    rec.Attempts,
			DurationMS:  rec.DurationMS,
		})
	}
	return out, nil
}

// enabledChannels 返回配置中已启用的渠道。
func enabledChannels(cfg Config) []Channel {
	out := make([]Channel, 0, len(cfg.Channels))
	for _, ch := range cfg.Channels {
		if ch.Enabled {
			out = append(out, ch)
		}
	}
	return out
}

// severityAtLeast 判断命中级别是否达到通知阈值。
func severityAtLeast(want []string, sev string) bool {
	for _, s := range want {
		if s == sev {
			return true
		}
	}
	return false
}

func pocNameSuffix(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return "（" + name + "）"
}

func completedMessage(taskID, name string, res TaskResult, sent, suppressed, limit int) Message {
	lines := []string{
		fmt.Sprintf("任务：%s", name),
		fmt.Sprintf("目标数：%d", len(res.Targets)),
		fmt.Sprintf("命中总数：%d", res.Hits),
	}
	for _, sev := range severityOrder {
		if c := res.BySeverity[sev]; c > 0 {
			lines = append(lines, fmt.Sprintf("%s：%d", strings.ToUpper(sev), c))
		}
	}
	if res.Scans > 0 {
		lines = append(lines, fmt.Sprintf("扫描量：约 %d 次", res.Scans))
	}
	if res.Elapsed > 0 {
		lines = append(lines, fmt.Sprintf("耗时：%s", formatDuration(res.Elapsed)))
	}
	if suppressed > 0 {
		lines = append(lines, fmt.Sprintf("实时推送已达上限 %d 条，另有 %d 条未单独推送", limit, suppressed))
	}
	lines = append(lines, fmt.Sprintf("时间：%s", time.Now().Format("2006-01-02 15:04:05")))

	return Message{
		Title: "afrog 扫描完成",
		Lines: lines,
		Extra: map[string]any{
			"event":       "task_completed",
			"task_id":     taskID,
			"task_name":   name,
			"status":      res.Status,
			"hits":        res.Hits,
			"targets":     len(res.Targets),
			"by_severity": res.BySeverity,
			"pushed_hits": sent,
			"suppressed":  suppressed,
		},
	}
}

func failedMessage(taskID, name string, res TaskResult) Message {
	lines := []string{
		fmt.Sprintf("任务：%s", name),
		fmt.Sprintf("状态：%s", statusLabel(res.Status)),
	}
	if res.Err != "" {
		lines = append(lines, fmt.Sprintf("错误：%s", res.Err))
	}
	if res.Hits > 0 {
		lines = append(lines, fmt.Sprintf("已命中：%d", res.Hits))
	}
	lines = append(lines, fmt.Sprintf("时间：%s", time.Now().Format("2006-01-02 15:04:05")))

	return Message{
		Title: "afrog 扫描异常",
		Level: "high",
		Lines: lines,
		Extra: map[string]any{
			"event":     "task_failed",
			"task_id":   taskID,
			"task_name": name,
			"status":    res.Status,
			"error":     res.Err,
		},
	}
}

func statusLabel(status string) string {
	switch status {
	case "failed":
		return "失败"
	case "cancelled":
		return "已终止"
	default:
		return status
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d 秒", int(d.Seconds()))
	}
	return fmt.Sprintf("%d 分 %d 秒", int(d.Minutes()), int(d.Seconds())%60)
}
