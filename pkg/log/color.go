package log

import (
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/gookit/color"
	"github.com/zan8in/afrog/v3/pkg/utils"
)

var (
	EnableColor = true
)

type Color struct {
	Info      func(a ...any) string
	Low       func(a ...any) string
	Midium    func(a ...any) string
	High      func(a ...any) string
	Critical  func(a ...any) string
	Unkown    func(a ...any) string
	Vulner    func(a ...any) string
	Time      func(a ...any) string
	Title     func(a ...any) string
	Banner    func(a ...any) string
	Bold      func(a ...any) string
	Red       func(a ...any) string
	Green     func(a ...any) string
	Extractor func(a ...any) string
}

var LogColor *Color

func init() {
	detectTerminal()

	if LogColor == nil {
		LogColor = NewColor()
	}
}

// 检测终端颜色支持
func detectTerminal() {
	// Windows 特殊处理
	if runtime.GOOS == "windows" {
		// 检查是否是 Windows Terminal 或 ANSICON
		_, wt := os.LookupEnv("WT_SESSION")
		_, ansi := os.LookupEnv("ANSICON")
		EnableColor = wt || ansi
	} else {
		// Unix 系统检查是否是 TTY
		fi, _ := os.Stdout.Stat()
		EnableColor = (fi.Mode() & os.ModeCharDevice) != 0
	}
}

// 基础颜色函数
func colorize(code int, s string) string {
	if !EnableColor {
		return s
	}
	return "\033[" + strconv.Itoa(code) + "m" + s + "\033[0m"
}

// 预定义颜色
func Black(s string) string   { return colorize(30, s) }
func Red(s string) string     { return colorize(31, s) }
func Green(s string) string   { return colorize(32, s) }
func Yellow(s string) string  { return colorize(33, s) }
func Blue(s string) string    { return colorize(34, s) }
func Magenta(s string) string { return colorize(35, s) }
func Cyan(s string) string    { return colorize(36, s) }
func White(s string) string   { return colorize(37, s) }

// 亮色系
func BrightBlack(s string) string   { return colorize(90, s) }
func BrightRed(s string) string     { return colorize(91, s) }
func BrightGreen(s string) string   { return colorize(92, s) }
func BrightYellow(s string) string  { return colorize(93, s) }
func BrightBlue(s string) string    { return colorize(94, s) }
func BrightMagenta(s string) string { return colorize(95, s) }
func BrightCyan(s string) string    { return colorize(96, s) }
func BrightWhite(s string) string   { return colorize(97, s) }

// 特殊样式
func Bold(s string) string      { return colorize(1, s) }
func Dim(s string) string       { return colorize(2, s) }
func Italic(s string) string    { return colorize(3, s) }
func Underline(s string) string { return colorize(4, s) }

func NewColor() *Color {
	return &Color{
		Info:      color.HiCyan.Render,
		Low:       color.FgCyan.Render,
		Midium:    color.FgYellow.Render,
		High:      color.FgLightRed.Render,
		Critical:  color.RGB(180, 84, 255).Sprint,
		Unkown:    color.BgDefault.Render,
		Vulner:    color.FgLightGreen.Render,
		Time:      color.Gray.Render,
		Title:     color.FgLightBlue.Render,
		Banner:    color.FgLightGreen.Render,
		Bold:      color.Bold.Render,
		Red:       color.FgLightRed.Render,
		Green:     color.FgLightGreen.Render,
		Extractor: color.Yellow.Render,
	}
}

func (c *Color) GetColor(level string, log string) string {
	level = strings.ToLower(level)
	switch utils.SeverityMap[level] {
	case utils.INFO:
		return c.Info(log)
	case utils.LOW:
		return c.Low(log)
	case utils.MEDIUM:
		return c.Midium(log)
	case utils.HIGH:
		return c.High(log)
	case utils.CRITICAL:
		return c.Critical(log)
	case utils.UNKOWN:
		return c.Unkown(log)
	default:
		if level == "time" {
			return c.Low(log)
		} else if level == "RED" {
			return c.Red(log)
		} else {
			return c.Vulner(log)
		}
	}
}
