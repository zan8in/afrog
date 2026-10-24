package progress

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/term"
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

// 进度条宽度。取不到终端宽度（非 TTY、重定向到文件）时用 defaultBarWidth，
// 否则按整行剩余空间自适应：进度条一旦折行，\r\033[2K 只能清掉最后一行，
// 上面那半行会永远留在屏幕上，界面就花了。
const (
	defaultBarWidth = 24
	minBarWidth     = 12
	maxBarWidth     = 50
)

// stageColumnWidth 是阶段名（port-scan / web-probe / vuln-scan）固定占用的列数。
const stageColumnWidth = 9

// terminalWidth 返回终端列数；取不到（非 TTY、管道、重定向）时返回 0。
func terminalWidth() int {
	if w, _, err := term.GetSize(int(os.Stderr.Fd())); err == nil && w > 0 {
		return w
	}
	return 0
}

// FitBarWidth 在已知「进度条以外」的固定列数时，算出既不折行又尽量长的进度条宽度。
func FitBarWidth(overhead int) int {
	w := terminalWidth()
	if w <= 0 {
		return defaultBarWidth
	}
	width := w - overhead - 1 // 留 1 列余量，避免正好压满触发终端自动换行
	if width > maxBarWidth {
		width = maxBarWidth
	}
	if width < minBarWidth {
		width = minBarWidth
	}
	return width
}

// GetProgressBar 获取带指示箭头的进度条
func GetProgressBar(progress, width int) string {
	// 自动宽度处理
	if width == 0 {
		width = defaultBarWidth
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
//	port-scan [━━━━╺─────]  12% 400/3200 1m30s 210/s
//	vuln-scan [━━╺───────]   9% 1543/16220 3m20s 15/s found=2
//
// stage 是小写阶段名（见 utils.StageXxx），固定占 9 字符与运维行对齐；行首不再有缩进，
// 与结果行同样从第 0 列起排。字段之间用单个空格分隔，与结果行、运维行同一套语言。
// tail 交给调用方补充阶段特有信息（如 ` found=2`）。
// 进度条宽度按终端剩余空间自适应（见 FitBarWidth），保证整行始终占一屏宽不折行。
// 只展示已发生的事实（已用时间、实测速率），不推算剩余时间：剩余量依赖
// 「剩余任务速度与已完成部分一致」的假设，扫描起步阶段样本少时给出的 ETA
// 往往离谱（实测出现过 374h57m59s），用户拿百分比和耗时自己估更准。
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

	// 只给事实：进度、计数、已用时间、实测速率。剩余时间由用户自行估算。
	rate := 0.0
	if sec := elapsed.Seconds(); sec >= 1 {
		rate = float64(current) / sec
	}
	fields := []string{
		fmt.Sprintf("%3d%%", percent),
		fmt.Sprintf("%d/%d", current, total),
		elapsed.Round(time.Second).String(),
		fmt.Sprintf("%.0f/s", rate),
	}

	fieldText := strings.Join(fields, " ")
	// 进度条宽度按终端剩余空间自适应，整行恰好占一屏宽：
	// stage(stageColumnWidth) + 空格 + [bar] + 空格 + fieldText + tail。
	overhead := stageColumnWidth + 1 + 2 + 1 + len(fieldText) + len(tail)
	return fmt.Sprintf("%-*s [%s] %s%s", stageColumnWidth, stage, GetProgressBar(percent, FitBarWidth(overhead)), fieldText, tail)
}
