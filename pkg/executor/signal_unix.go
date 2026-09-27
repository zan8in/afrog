//go:build !windows

package executor

import (
	"os"
	"syscall"
)

// PauseSupported 报告当前平台是否支持暂停/继续。Unix 用信号实现，支持。
const PauseSupported = true

// pauseProcess 用 SIGSTOP 暂停进程。SIGSTOP 不可被进程忽略。
func pauseProcess(p *os.Process) error {
	return p.Signal(syscall.SIGSTOP)
}

// resumeProcess 用 SIGCONT 唤醒被 SIGSTOP 暂停的进程。
func resumeProcess(p *os.Process) error {
	return p.Signal(syscall.SIGCONT)
}

// terminateProcess 发送 SIGTERM，给子进程留出收尾机会。
func terminateProcess(p *os.Process) error {
	return p.Signal(syscall.SIGTERM)
}
