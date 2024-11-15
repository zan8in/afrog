package config

import (
	"fmt"
	"time"

	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
)

const Version = "3.1.2"

func InitBanner() {
	fmt.Printf("\r\n|\tA F 🐸 O G\t|")
}
func ShowBanner(u *AfrogUpdate) {
	InitBanner()
	fmt.Printf("\r\t\t\t\t%s/%s\t|\t%s\n\n", EngineV(u), PocV(u), "Dream a dream for you")
}

func BannerAnimate(u *AfrogUpdate) {
	animationChars := []rune{'|', '\\', '-', '/'}

	for i := 0; i < 1000; i++ {
		for _, char := range animationChars {
			fmt.Printf("\r%c\tA F 🐸 O G\t%c", char, char)
			fmt.Printf("\r\t\t\t\t%s/%s\t%c\t%s", EngineV(u), PocV(u), char, "Dream a dream for you")
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func ShowVersion() {
	fmt.Printf("\r\nafrog Version %s\n\n", Version)
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
