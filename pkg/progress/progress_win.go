//go:build windows

package progress

import (
	"os"

	"golang.org/x/sys/windows"
)

func init() {
	enableVirtualTerminalProcessing()
}

func enableVirtualTerminalProcessing() {
	handle := windows.Handle(os.Stdout.Fd())

	var mode uint32
	windows.GetConsoleMode(handle, &mode)
	windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}
