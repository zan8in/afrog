//go:build windows

package portscan

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// Windows 没有 RLIMIT_NOFILE：句柄数由内核按内存等资源动态限制，没有可读、可提的
// 进程级上限。因此这里放弃「启动预算」与「自动提升」，只保留「错误归因」这一层——
// 借助运行时返回的 WSA 错误码判断是本机资源耗尽而非目标丢包，让 scan.go 能据此告警
// 并收缩在飞并发。这也正好回答了「windows 如何处理」：不是不处理，而是换一种信号。

// fdScanBudget 在 Windows 上没有可读的上限，返回 0 表示「保持用户配置的并发」。
func fdScanBudget() int { return 0 }

// raiseFDLimit 在 Windows 上无可提升的上限（SetHandleCount 在现代 Windows 上是
// 空操作），静默返回未提升。
func raiseFDLimit() (uint64, bool) { return 0, false }

// isFDExhausted 判断错误是否为本机句柄/资源耗尽。
//   - WSAEMFILE(10024)：进程打开的套接字句柄已达上限。
//   - WSAENOBUFS(10055)：Winsock 内部缓冲区耗尽，通常是并发连接过多。
//   - ERROR_TOO_MANY_OPEN_FILES(4)：底层文件句柄耗尽。
func isFDExhausted(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, windows.WSAEMFILE) ||
		errors.Is(err, windows.WSAENOBUFS) ||
		errors.Is(err, syscall.Errno(windows.ERROR_TOO_MANY_OPEN_FILES))
}

// fdAdvice 给出 Windows 下的处置建议。Windows 没有可抬的句柄上限，唯一能做的就是
// 降并发，所以不能照搬 Unix 的「raise ulimit -n」。
func fdAdvice() string { return "lower -prate (no open-file limit to raise on Windows)" }
