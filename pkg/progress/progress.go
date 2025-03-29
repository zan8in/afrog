package progress

import (
	"os"
	"runtime"
	"strings"
)

// CreateProgressBar 示例用法：
// Unicode终端：CreateProgressBar(50, 20, '▉', '░') → "▉▉▉▉▉▉▉▉▉▉░░░░░░░░░░"
// ASCII终端：  CreateProgressBar(50, 20, '▉', '░') → "##########----------"

// GetProgressBar 示例效果：
// Unicode终端：GetProgressBar(30, 20) → "━━━━━━╺─────────────"
// ASCII终端：  GetProgressBar(30, 20) → "======>-------------"

// 检测Unicode支持
func isUnicodeSupported() bool {
	// Windows系统检测是否在Windows Terminal中运行
	if runtime.GOOS == "windows" {
		return os.Getenv("WT_SESSION") != ""
	}
	// Unix系统检测TERM环境变量
	return strings.Contains(os.Getenv("TERM"), "xterm") ||
		strings.Contains(os.Getenv("TERM"), "256color")
}

// CreateProgressBar 创建兼容终端的进度条
func CreateProgressBar(progress, length int, filled, empty rune) string {
	// 自动替换不兼容字符
	if !isUnicodeSupported() {
		switch filled {
		case '▉', '█':
			filled = '#'
		case '░', '▒':
			empty = '-'
		}
	}

	filledCount := progress * length / 100
	if filledCount > length {
		filledCount = length
	}
	emptyCount := length - filledCount

	return strings.Repeat(string(filled), filledCount) +
		strings.Repeat(string(empty), emptyCount)
}

// GetProgressBar 获取带指示箭头的进度条
func GetProgressBar(progress, width int) string {
	// 自动宽度处理
	if width == 0 {
		width = 50
	}

	// 动态选择符号
	filledChar, arrowChar, emptyChar := "=", ">", "-"
	if isUnicodeSupported() {
		filledChar = "━"
		arrowChar = "╺"
		emptyChar = "─"
	}

	barLength := progress * width / 100
	if barLength > width {
		barLength = width
	}

	// 构建进度条
	var progressBar strings.Builder
	if barLength > 0 {
		progressBar.WriteString(strings.Repeat(filledChar, barLength))
	}
	if barLength < width {
		progressBar.WriteString(arrowChar)
		remaining := width - barLength - 1 // 扣除箭头占位
		if remaining > 0 {
			progressBar.WriteString(strings.Repeat(emptyChar, remaining))
		}
	} else {
		progressBar.WriteString(filledChar) // 100%时用完整字符
	}

	return progressBar.String()
}
