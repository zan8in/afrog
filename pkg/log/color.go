package log

import (
	"fmt"
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
	Vulner    func(a ...any) string
	Time      func(a ...any) string
	Title     func(a ...any) string
	Red       func(a ...any) string
	Green     func(a ...any) string
	Extractor func(a ...any) string
	DarkGray  func(a ...any) string
}

var LogColor *Color

func init() {
	if LogColor == nil {
		LogColor = NewColor()
	}
}

func NewColor() *Color {
	return &Color{
		Info:      wrapRender(color.FgLightBlue.Render),
		Low:       wrapRender(color.Cyan.Render),
		Midium:    wrapRender(color.Yellow.Render),
		High:      wrapRender(color.LightRed.Render),
		Critical:  wrapRender(color.FgLightMagenta.Render),
		Vulner:    wrapRender(color.FgLightGreen.Render),
		Time:      wrapRender(color.Gray.Render),
		Title:     wrapRender(color.FgLightBlue.Render),
		Red:       wrapRender(color.FgLightRed.Render),
		Green:     wrapRender(color.FgLightGreen.Render),
		Extractor: wrapRender(color.Yellow.Render),
		DarkGray:  wrapRender(color.FgDarkGray.Render),
	}
}

func wrapRender(render func(a ...any) string) func(a ...any) string {
	return func(a ...any) string {
		if !EnableColor {
			return fmt.Sprint(a...)
		}
		return render(a...)
	}
}

// StatusCode 按 HTTP 状态码类别着色：2xx 绿、3xx 青、4xx 黄、5xx 红，
// 让一屏结果里不同健康度的目标靠颜色即可分辨；非标准码用深灰。
func (c *Color) StatusCode(code int) string {
	s := strconv.Itoa(code)
	if !EnableColor {
		return s
	}
	switch code / 100 {
	case 2:
		return c.Green(s)
	case 3:
		return c.Low(s)
	case 4:
		return c.Midium(s)
	case 5:
		return c.Red(s)
	default:
		return c.DarkGray(s)
	}
}

func (c *Color) GetColor(level string, log string) string {
	if !EnableColor {
		return log
	}
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
