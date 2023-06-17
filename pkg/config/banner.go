package config

import (
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/upgrade"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/gologger"
)

const Version = "2.5.5"

func ShowBanner(u *upgrade.Upgrade) {
	gologger.Print().Msgf("\n|\tA F R O G\t>\t%s\t-\t%s\n\n", EngineV(u), PocV(u))
}

func EngineV(u *upgrade.Upgrade) string {
	if utils.Compare(u.LastestAfrogVersion, ">", Version) {
		return Version + " (" + log.LogColor.Red("outdated") + ")" + " > " + log.LogColor.Red(u.LastestAfrogVersion)
	}
	return Version
}

func PocV(u *upgrade.Upgrade) string {
	if utils.Compare(u.LastestVersion, ">", u.CurrVersion) {
		return u.CurrVersion + " > " + log.LogColor.Red(u.LastestVersion)
	}
	return u.CurrVersion
}

func ShowUpgradeBanner(upgrade *upgrade.Upgrade) {
	messageStr := ""
	if utils.Compare(upgrade.LastestAfrogVersion, ">", Version) {
		messageStr = " (" + log.LogColor.Red(upgrade.LastestAfrogVersion) + ")"
	} else {
		messageStr = " (" + log.LogColor.Green("latest") + ")"
	}
	gologger.Print().Msgf("Using afrog Engine %s%s", Version, messageStr)

	messageStr2 := ""
	if utils.Compare(upgrade.LastestVersion, ">", upgrade.CurrVersion) {
		messageStr2 = " (" + log.LogColor.Red(upgrade.LastestVersion) + ")"
	} else {
		messageStr2 = " (" + log.LogColor.Green("latest") + ")"
	}
	gologger.Print().Msgf("Using afrog-pocs %s%s", upgrade.CurrVersion, messageStr2)
}
