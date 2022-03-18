package log

import (
	"strings"

	"github.com/gookit/color"
	"github.com/zan8in/afrog/pkg/utils"
)

type Color struct {
	Info     func(a ...interface{}) string
	Low      func(a ...interface{}) string
	Midium   func(a ...interface{}) string
	High     func(a ...interface{}) string
	Critical func(a ...interface{}) string
	Vulner   func(a ...interface{}) string
	Time     func(a ...interface{}) string
}

func NewColor() *Color {
	return &Color{
		Info:     color.FgBlue.Render,
		Low:      color.FgCyan.Render,
		Midium:   color.FgYellow.Render,
		High:     color.FgLightRed.Render,
		Critical: color.FgRed.Render,
		Vulner:   color.FgLightGreen.Render,
		Time:     color.FgCyan.Render,
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
		} else {
			return c.Vulner(log)
		}
	}
}
