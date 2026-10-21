package progress

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
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

// RenderLine 渲染一行统一的进度输出，三个阶段（端口扫描 / Web 探测 / 漏洞扫描）共用：
//
//	PORT-SCAN [━━━━╺─────] 12% (400/3200) 210/s ETA 13s
//	VULN-SCAN [━━╺───────]  9% (1543/16220) 15/s ETA 16m15s found=2
//
// stage 固定占 9 字符，与阶段日志的 `%-9s | %-9s |` 对齐；tail 交给调用方补充
// 阶段特有的信息（如 found=）。total <= 0 表示没有可统计的任务，返回空串。
func RenderLine(stage string, percent int, current, total int64, elapsed time.Duration, tail string) string {
	if total <= 0 {
		return ""
	}
	if current < 0 {
		current = 0
	}
	if current > total {
		current = total
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	// 只有"已用多久"信息量太低，补上每秒速率与预计剩余时间，用户才能判断还要等多久。
	rate := 0.0
	if sec := elapsed.Seconds(); sec >= 1 {
		rate = float64(current) / sec
	}
	eta := "--"
	if rate > 0 && current < total {
		eta = time.Duration(float64(total-current) / rate * float64(time.Second)).Round(time.Second).String()
	}

	return fmt.Sprintf("%-9s [%s] %d%% (%d/%d) %.0f/s ETA %s%s",
		stage, GetProgressBar(percent, 0), percent, current, total, rate, eta, tail)
}
