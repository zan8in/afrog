package utils

import (
	"math/rand"
	"time"
)

var (
	tips = []string{
		// "现在 PoC 内置在程序里，~/afrog-pocs 仍保留，使用 --up 命令获取最新 PoC",
		// "现在会自动生成报告，也支持 -o 自定义报告名",
		// "Fingerprint 功能是先访问一遍 Targets，获取 Title 和 Web 指纹，不想扫描 Fingerprint，使用 --nf 命令",
		// "afrog -t http://example.com",
		// "afrog -T urls.txt",
		// "afrog -T urls.txt -o result.html",
		// "afrog -t http://example.com -P ./testing/poc-test.yaml",
		// "afrog -t http://example.com -P ./testing/",
		// "服务器后台运行，使用 -silent 命令，避免(实时显示扫描进度)脏数据污染 nohup 文件",
		// "不想看到 TIPS, 使用 --nt 命令",
		// "不想看到实时扫描进度，使用 -silent 命令",
		// "-o 会覆盖相同文件名的报告",
		"为你写诗",
		"不以物喜，不以己悲",
		"美丽人生，享受生活",
		"坚持，是一种品格",
		"知己知彼，百战不殆",
		"上坡要努力，下坡要开心",
		"挖漏洞是一种缘分，漏洞就在那边，你若没挖到就说明你们暂时无缘",
		"命里有时终须有，命里无时莫强求",
		// "这个BUG半小时后改完，开发者重新定义了半小时",
	}
)

func GetRandomTips() string {
	rand.Seed(time.Now().UnixNano())
	return tips[rand.Intn(len(tips))]
}
