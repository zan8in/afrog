package runner

import (
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/upgrade"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/gologger"
)

func ShowBanner() {
	gologger.Print().Msgf("\n|||\tA F R O G\t|||\t%s\n\n", config.Version)
}

func ShowBanner2(upgrade *upgrade.Upgrade) {
	messageStr := ""
	if utils.Compare(upgrade.LastestAfrogVersion, ">", config.Version) {
		messageStr = " (" + log.LogColor.Red(upgrade.LastestAfrogVersion) + ")"
	} else {
		messageStr = " (" + log.LogColor.Green("latest") + ")"
	}
	gologger.Print().Msgf("Using afrog Engine %s%s", config.Version, messageStr)

	messageStr2 := ""
	if utils.Compare(upgrade.LastestVersion, ">", upgrade.CurrVersion) {
		messageStr2 = " (" + log.LogColor.Red(upgrade.LastestVersion) + ")"
	} else {
		messageStr2 = " (" + log.LogColor.Green("latest") + ")"
	}
	gologger.Print().Msgf("Using afrog-pocs %s%s", upgrade.CurrVersion, messageStr2)
}
