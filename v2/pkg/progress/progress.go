package progress

import (
	"runtime"
	"strings"
)

func init() {
	if runtime.GOOS == "windows" {
		enableVirtualTerminalProcessing()
	}
}

// 进度条
func CreateProgressBar(progress, length int, filled, empty rune) string {
	filledCount := progress * length / 100
	emptyCount := length - filledCount
	bar := strings.Repeat(string(filled), filledCount) + strings.Repeat(string(empty), emptyCount)
	return bar
}
