package progress

import (
	"strings"
)

// 进度条
func CreateProgressBar(progress, length int, filled, empty rune) string {
	filledCount := progress * length / 100
	emptyCount := length - filledCount
	bar := strings.Repeat(string(filled), filledCount) + strings.Repeat(string(empty), emptyCount)
	return bar
}

// 进度条2
func GetProgressBar(progress, width int) string {
	if width == 0 {
		width = 50
	}
	barLength := progress * width / 100
	progressBar := strings.Repeat("=", barLength)
	progressBar += ">"
	progressBar += strings.Repeat("-", width-barLength)
	return progressBar
}
