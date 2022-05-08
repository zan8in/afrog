package utils

import (
	"math/rand"
	"time"
)

var (
	tips = []string{
		"现在 PoC 内置在编译后的程序里，~/afrog-pocs 仍保留，作用是实时同步最新的 PoC",
		"现在会自动生成报告，也支持 -o 自定义报告名",
		"Fingerprint 功能是先访问一遍 Targets，获取 Title 和 Web 指纹",
		"afrog -t http://example.com",
		"afrog -T urls.txt",
		"afrog -T urls.txt -o result.html",
		"afrog -t http://example.com -P ./testing/poc-test.yaml",
		"afrog -t http://example.com -P ./testing/",
		"服务器后台运行，建议使用 -s 命令，避免(实时显示扫描进度)脏数据污染 nohup 文件",
		"禁止显示 TIPS, 使用 --nt 命令",
		"禁止扫描 Fingerprint，使用 --nf 命令",
		"禁止实时扫描进度，使用 -s 命令",
		"-o 会覆盖相同文件名的报告",
		"不以物喜，不以己悲！",
		"美丽人生，享受生活！- life is fantastic. enjoy life.",
		"坚持，是一种品格！",
		"知己知彼，百战不殆",
		"挖漏洞是一种缘分，漏洞就在那边，你若没挖到就说明你们暂时无缘。",
	}
)

func GetRandomTips() string {
	rand.Seed(time.Now().UnixNano())
	return tips[rand.Intn(len(tips))]
}
