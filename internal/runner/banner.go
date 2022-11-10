package runner

import (
	"fmt"

	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/utils"
)

func ShowBanner() string {
	return log.LogColor.Bold("afrog ") + log.LogColor.Banner("等待的男孩")
}

func ShowUsage() string {
	return "\nUSAGE:\n   afrog -t example.com -o result.html\n   afrog -T urls.txt -o result.html\n   afrog -T urls.txt -s -o result.html\n   afrog -t example.com -P ./pocs/poc-test.yaml -o result.html\n   afrog -t example.com -P ./pocs/ -o result.html\n"
}

func ShowTips() string {
	return "\nTIPS:\n   " + utils.GetRandomTips() + "\n"
}

func ShowBanner2(afrogLatestversion string) {
	title := "NAME:\n   " + ShowBanner() + " - v" + config.Version
	old := ""
	if utils.Compare(afrogLatestversion, ">", config.Version) {
		old = " (" + log.LogColor.High(afrogLatestversion) + ")"
		old += log.LogColor.Title(" -> https://github.com/zan8in/afrog/releases/tag/v" + afrogLatestversion)
	}
	fmt.Println(title + old + "\n")
}
