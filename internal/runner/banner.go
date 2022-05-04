package runner

import (
	"fmt"

	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/utils"
)

func ShowBanner() string {
	return "afrog"
}

func ShowUsage() string {
	return "\nUSAGE:\n   afrog -t example.com -o result.html\n   afrog -T urls.txt -o result.html\n   afrog -T urls.txt -s -o result.html\n   afrog -t example.com -P ./pocs/poc-test.yaml -o result.html\n   afrog -t example.com -P ./pocs/ -o result.html\n"
}

func ShowBanner2(afrogLatestversion string) {
	title := "NAME:\n   " + log.LogColor.Banner(ShowBanner()) + " - v" + config.Version
	old := ""
	if utils.Compare(afrogLatestversion, ">", config.Version) {
		old = log.LogColor.High(" (outdated)")
		old += log.LogColor.Title(" --> https://github.com/zan8in/afrog/releases/tag/v" + afrogLatestversion)
	}
	fmt.Println(title + old + "\n")
}
