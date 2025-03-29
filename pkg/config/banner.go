package config

import (
	"fmt"

	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/utils"
)

const Version = "3.1.6"

func InitBanner() {
	fmt.Printf("\r\n|\tA F 🐸 O G\t|")
}
func ShowBanner(u *AfrogUpdate) {
	InitBanner()
	fmt.Printf("\r\t\t\t\t%s/%s\t|\t%s\n\n", EngineV(u), PocV(u), "Ne Zha 2")
}

func ShowVersion() {
	fmt.Printf("afrog Version %s\n", Version)
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
