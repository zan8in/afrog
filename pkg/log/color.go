package log

import (
	"strings"

	"github.com/fatih/color"
	"github.com/zan8in/afrog/pkg/utils"
)

func GetColor(level string, log string) string {
	var result string
	level = strings.ToLower(level)
	switch utils.SeverityMap[level] {
	case utils.INFO:
		result = color.BlueString(log)
	case utils.LOW:
		result = color.CyanString(log)
	case utils.MEDIUM:
		result = color.YellowString(log)
	case utils.HIGH:
		result = color.RedString(log)
	case utils.CRITICAL:
		result = color.RedString(log)
	default:
		result = color.HiGreenString(log)
	}
	if level == "time" {
		result = color.HiCyanString(log)
	}
	return result
}
