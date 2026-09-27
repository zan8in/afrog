// Package scantask 是控制面的任务层：受理扫描、维护任务生命周期、保存带 seq 的
// 事件缓冲并分发给订阅者。
//
// 它不关心传输：gRPC 的 StreamEvents 与 Web 的 SSE 都只是它的订阅者，因此两条路径
// 共用同一份任务状态与事件口径（见 docs/plan/afrog-grpc-protocol.md §4.3）。
package scantask

import (
	"errors"
	"time"

	"github.com/zan8in/afrog/v3/pkg/executor"
)

// Status 是任务状态，取值与协议文档 §5 的 StatusEvent.status 一致。
type Status string

const (
	StatusQueued    Status = "queued"
	StatusStarting  Status = "starting"
	StatusRunning   Status = "running"
	StatusPaused    Status = "paused"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// Active 表示任务尚未结束（仍占用并发名额，可能还能被控制）。
func (s Status) Active() bool {
	switch s {
	case StatusQueued, StatusStarting, StatusRunning, StatusPaused:
		return true
	}
	return false
}

// Terminal 表示任务已结束。
func (s Status) Terminal() bool {
	switch s {
	case StatusCompleted, StatusFailed, StatusCancelled:
		return true
	}
	return false
}

// Action 是控制动作。
type Action int

const (
	ActionPause Action = iota
	ActionResume
	ActionCancel
)

func (a Action) String() string {
	switch a {
	case ActionPause:
		return "pause"
	case ActionResume:
		return "resume"
	case ActionCancel:
		return "cancel"
	default:
		return "unknown"
	}
}

var (
	// ErrNoTargets 表示提交时没有有效目标。
	ErrNoTargets = errors.New("scantask: no targets")
	// ErrTaskNotFound 表示任务不存在。
	ErrTaskNotFound = errors.New("scantask: task not found")
	// ErrNoProcess 表示任务既没有可控制的子进程（排队中或已结束）。
	ErrNoProcess = errors.New("scantask: task has no controllable process")
	// ErrSlowSubscriber 表示订阅者消费太慢、事件已被丢弃并主动断开；
	// 客户端应带上 last_seq 重连以补齐（协议文档 §5.1）。
	ErrSlowSubscriber = errors.New("scantask: subscriber too slow, connection closed")
)

// 默认值。
const (
	DefaultMaxRunning   = 6
	DefaultEventBuffer  = 5000
	subChannelSlack     = 32
	defaultNodeName     = "local"
	defaultIDTimeFormat = "20060102"
)

// Options 配置 Manager。Executor 必填，其余留空取默认值。
type Options struct {
	// Executor 真正负责跑扫描。
	Executor executor.Executor
	// Node 是本控制面的节点名，写入事件信封，默认 "local"。
	Node string
	// MaxRunning 是并发上限，<=0 用 DefaultMaxRunning。
	MaxRunning int
	// EventBuffer 是每个任务保留的事件条数上限，<=0 用 DefaultEventBuffer。
	EventBuffer int
	// IDGenerator 生成任务 ID，默认「日期-五位序号」。
	IDGenerator func() string
	// Now 便于测试注入时间，默认 time.Now。
	Now func() time.Time
	// OnTaskFinished 可选：任务收尾后回调（用于落库、通知等）。
	OnTaskFinished func(*Snapshot)
}

func (o Options) node() string {
	if o.Node != "" {
		return o.Node
	}
	return defaultNodeName
}

func (o Options) maxRunning() int {
	if o.MaxRunning > 0 {
		return o.MaxRunning
	}
	return DefaultMaxRunning
}

func (o Options) eventBuffer() int {
	if o.EventBuffer > 0 {
		return o.EventBuffer
	}
	return DefaultEventBuffer
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Progress 是任务级进度，口径与协议文档 §5.2 一致：
// total 取引擎下发的任务数（与命令行 tasks= 同源），finished 取实际执行数。
type Progress struct {
	Percent   int
	Finished  int64
	Total     int64
	Rate      int
	ElapsedMs int64
}

// Snapshot 是任务在某一时刻的完整状态快照，可自由跨 goroutine 传递。
type Snapshot struct {
	ID        string
	Name      string
	Node      string
	Status    Status
	Targets   []string
	CreatedAt time.Time
	StartedAt time.Time
	EndedAt   time.Time

	Progress Progress
	// ScanInfo 是引擎上报的前置汇总，可能为 nil（还没开始执行）。
	ScanInfo ScanInfo
	// Summary 是收尾汇总，可能为 nil。
	Summary *Summary

	// Hits 是按严重级别统计的命中数。
	Hits map[string]int
	// HitTotal 是命中总数。
	HitTotal int
	// Pausable 如实反映当前平台与任务状态是否允许暂停。
	Pausable bool
	// Error 是失败原因，正常任务为空。
	Error string

	// LastSeq 是已产生事件的最大 seq。
	LastSeq uint64
	// BufferedFrom 是事件缓冲中最小事件的 seq，缓冲为空时为 0。
	BufferedFrom uint64
	// Truncated 表示更早的事件已因窗口限制被丢弃，客户端只能靠状态与结果补齐。
	Truncated bool
}

// ScanInfo 是引擎上报的前置汇总（对应 scan_info 事件）。
// 单独定义一份是为了让调用方不必依赖 scanstream 包。
type ScanInfo struct {
	TotalTargets int
	TotalPocs    int
	TotalScans   int
	OOBEnabled   bool
	OOBStatus    string
}

// Summary 是任务收尾汇总（对应 done 事件）。
type Summary struct {
	Executed   int64
	Found      int64
	BySeverity map[string]int64
	ElapsedMs  int64
}
