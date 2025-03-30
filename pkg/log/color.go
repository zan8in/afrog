package log

import (
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
		Info:      color.FgDarkGray.Render,
		Low:       color.Cyan.Render,
		Midium:    color.Yellow.Render,
		High:      color.LightRed.Render,
		Critical:  color.FgLightMagenta.Render,
		Vulner:    color.FgLightGreen.Render,
		Time:      color.Gray.Render,
		Title:     color.FgLightBlue.Render,
		Red:       color.FgLightRed.Render,
		Green:     color.FgLightGreen.Render,
		Extractor: color.Yellow.Render,
		DarkGray:  color.FgDarkGray.Render,
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
