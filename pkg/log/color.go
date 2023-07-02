package log

import (
	"strings"

	"github.com/gookit/color"
	"github.com/zan8in/afrog/pkg/utils"
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
	Banner    func(a ...any) string
	Bold      func(a ...any) string
	Red       func(a ...any) string
	Green     func(a ...any) string
	Extractor func(a ...any) string
}

var LogColor *Color

func init() {
	if LogColor == nil {
		LogColor = NewColor()
	}
}

func NewColor() *Color {
	return &Color{
		Info:      color.HiCyan.Render,
		Low:       color.FgCyan.Render,
		Midium:    color.FgYellow.Render,
		High:      color.FgLightRed.Render,
		Critical:  color.RGB(180, 84, 255).Sprint,
		Vulner:    color.FgLightGreen.Render,
		Time:      color.Gray.Render,
		Title:     color.FgLightBlue.Render,
		Banner:    color.FgLightGreen.Render,
		Bold:      color.Bold.Render,
		Red:       color.FgLightRed.Render,
		Green:     color.FgLightGreen.Render,
		Extractor: color.FgMagenta.Render,
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
