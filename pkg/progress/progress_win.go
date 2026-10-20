//go:build windows

package progress

import (
	"os"

	"golang.org/x/sys/windows"
)

func init() {
	enableVirtualTerminalProcessing(os.Stdout)
	enableVirtualTerminalProcessing(os.Stderr)
}

// enableVirtualTerminalProcessing 让控制台按 ANSI 转义序列渲染。
// stdout 与 stderr 是两个独立的控制台句柄，端口扫描的进度行写的是 stderr，只处理
// stdout 会让进度条在 Windows 上显示成转义残留。
func enableVirtualTerminalProcessing(f *os.File) {
	handle := windows.Handle(f.Fd())

	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return
	}
	_ = windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}
