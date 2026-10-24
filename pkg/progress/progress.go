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
	// 箭头占用 1 格：进度未满时先画箭头再补空格，满格时箭头位置也由实心格填满，
	// 两种情况的总宽都严格等于 width，避免 100% 时进度条凭空多出一格。
	if barLength < width {
		progressBar.WriteString(arrowChar)
		remaining := width - barLength - 1
		if remaining > 0 {
			progressBar.WriteString(strings.Repeat(emptyChar, remaining))
		}
	}

	return progressBar.String()
}

// RenderLine 渲染一行统一的进度输出，三个阶段（端口扫描 / Web 探测 / 漏洞扫描）共用：
//
//	port-scan [━━━━╺─────]  12% · 400/3200 · 210/s · ETA 13s
//	vuln-scan [━━╺───────]   9% · 1543/16220 · 15/s · ETA 16m15s · found=2
//
// stage 是小写阶段名（见 utils.StageXxx），固定占 9 字符与运维行对齐；行首缩进 4 格，
// 与结果行的序号列对齐，使整屏输出成为一个网格。字段之间用 ` · ` 分隔，与结果行同一套语言。
// tail 交给调用方补充阶段特有信息（如 ` · found=2`）。
// 跑满时不再输出 ETA：剩余时间已经恒为 0，留着只是噪音。
// total <= 0 表示没有可统计的任务，返回空串。
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
	fields := []string{
		fmt.Sprintf("%3d%%", percent),
		fmt.Sprintf("%d/%d", current, total),
		fmt.Sprintf("%.0f/s", rate),
	}
	// 未跑满才谈得上「还要多久」；跑满后 ETA 恒为 0，属纯噪音。
	if current < total {
		eta := "--"
		if rate > 0 {
			eta = time.Duration(float64(total-current) / rate * float64(time.Second)).Round(time.Second).String()
		}
		fields = append(fields, "ETA "+eta)
	}

	return fmt.Sprintf("%-9s [%s] %s%s", stage, GetProgressBar(percent, 0), strings.Join(fields, " · "), tail)
}
