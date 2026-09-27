// Package executor 提供扫描执行器抽象与本地进程实现。
//
// 本地进程执行器通过 os.Executable() 拉起自身子进程执行扫描，解析子进程 stdout
// 的 NDJSON 事件流（见 pkg/scanstream），从而与未来的远程节点执行器共用同一套事件模型。
// 这样做的关键收益是彻底规避 pkg/sdk 里的进程级全局状态（HTTP 客户端、限速器、
// 协议探测缓存），并发任务之间不会互相污染参数。
package executor

import (
	"context"
	"errors"

	"github.com/zan8in/afrog/v3/pkg/scanstream"
)

// Executor 提交扫描任务并返回可控制的句柄。
type Executor interface {
	Start(ctx context.Context, taskID string, spec *Spec) (Handle, error)
}

// Handle 是一个正在执行的扫描任务。
type Handle interface {
	// Events 返回子进程 stdout 解析出的统一事件流，子进程 stdout 读完后关闭。
	Events() <-chan *scanstream.Event

	// Pause 暂停任务。Windows 上不支持，返回 ErrPauseUnsupported。
	Pause() error
	// Resume 继续任务。Windows 上不支持，返回 ErrPauseUnsupported。
	Resume() error
	// Cancel 终止任务：先发 SIGTERM，超过 KillGrace 未退出再 SIGKILL。
	Cancel() error

	// Done 在子进程退出且 stdout 已读完时关闭。
	Done() <-chan struct{}
	// Err 返回非零退出码对应的错误，正常结束为 nil。
	Err() error
	// PID 返回子进程 PID。
	PID() int
}

var (
	// ErrPauseUnsupported 表示当前平台不支持暂停/继续（Windows）。
	ErrPauseUnsupported = errors.New("executor: pause/resume is not supported on this platform")
	// ErrAlreadyDone 表示对已结束的任务执行控制操作。
	ErrAlreadyDone = errors.New("executor: task already finished")
	// ErrBinaryNotFound 表示找不到可执行的 afrog 二进制。
	ErrBinaryNotFound = errors.New("executor: afrog binary not found")
)
