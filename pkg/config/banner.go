package config

import (
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/gologger"
)

const Version = "2.6.1"

func ShowBanner(u *AfrogUpdate) {
	gologger.Print().Msgf("\n|\tA F 🐸 O G\t|\t%s/%s\n\n", EngineV(u), PocV(u))
}

func EngineV(u *AfrogUpdate) string {
	if utils.Compare(u.LastestAfrogVersion, ">", Version) {
		return Version + " (" + log.LogColor.Red("outdated") + ")" + " > " + log.LogColor.Red(u.LastestAfrogVersion)
	}
	return Version
}

func PocV(u *AfrogUpdate) string {
	if utils.Compare(u.LastestVersion, ">", u.CurrVersion) {
		return u.CurrVersion + " > " + log.LogColor.Red(u.LastestVersion)
	}
	return u.CurrVersion
}

func ShowUpgradeBanner(au *AfrogUpdate) {
	messageStr := ""
	if utils.Compare(au.LastestAfrogVersion, ">", Version) {
		messageStr = " (" + log.LogColor.Red(au.LastestAfrogVersion) + ")"
	} else {
		messageStr = " (" + log.LogColor.Green("latest") + ")"
	}
	gologger.Print().Msgf("Using afrog Engine %s%s", Version, messageStr)

	messageStr2 := ""
	if utils.Compare(au.LastestVersion, ">", au.CurrVersion) {
		messageStr2 = " (" + log.LogColor.Red(au.LastestVersion) + ")"
	} else {
		messageStr2 = " (" + log.LogColor.Green("latest") + ")"
	}
	gologger.Print().Msgf("Using afrog-pocs %s%s", au.CurrVersion, messageStr2)
}
