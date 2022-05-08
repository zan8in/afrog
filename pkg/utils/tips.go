package utils

import "math/rand"

var (
	tips = []string{
		"不以物喜，不以己悲！",
		"美丽人生，享受生活！- life is fantastic. enjoy life.",
		"坚持，是一种品格！",
		"知己知彼，百战不殆",
		"挖漏洞是一种缘分，漏洞就在那边，你若没挖到就说明你们暂时无缘。",
	}
)

func GetRandomTips() string {
	return tips[rand.Intn(len(tips))]
}
