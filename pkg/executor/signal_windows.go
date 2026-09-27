//go:build windows

package executor

import "os"

// PauseSupported 报告当前平台是否支持暂停/继续。Windows 不支持。
const PauseSupported = false

// Windows 不支持 SIGSTOP/SIGCONT 语义的暂停，如实上报不支持。
func pauseProcess(p *os.Process) error { return ErrPauseUnsupported }

func resumeProcess(p *os.Process) error { return ErrPauseUnsupported }

// Windows 没有 SIGTERM，只能直接结束进程。
func terminateProcess(p *os.Process) error { return p.Kill() }
