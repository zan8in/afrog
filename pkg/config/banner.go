package config

import (
	"fmt"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/utils"
)

const (
	Version     = "3.1.6"
	ProjectName = "afrog"
	Codename    = "Ne Zha II"
)

func InitBanner() {
	fmt.Printf("\n%s/%s | %s | %s",
		ProjectName,
		Version,
		"Security Toolkit",
		Codename,
	)
}

func ShowBanner(u *AfrogUpdate) {
	InitBanner()
	fmt.Printf("\n%s | %s%s\n",
		fmt.Sprintf("core:%s", EngineV(u)),
		fmt.Sprintf("poc:%s", PocV(u)),
		updateIndicator(u),
	)
	fmt.Println("─", strings.Repeat("─", 58), "─")
}

func ShowVersion() {
	fmt.Printf("%s v%s (%s)\n", ProjectName, Version, Codename)
}

func EngineV(u *AfrogUpdate) string {
	if utils.Compare(u.LastestAfrogVersion, ">", Version) {
		return Version + log.LogColor.Red("↑")
	}
	return Version + log.LogColor.Info("✓")
}

func PocV(u *AfrogUpdate) string {
	if utils.Compare(u.LastestVersion, ">", u.CurrVersion) {
		return u.CurrVersion + log.LogColor.Red("↑")
	}
	return u.CurrVersion
}

func updateIndicator(u *AfrogUpdate) string {
	if utils.Compare(u.LastestAfrogVersion, ">", Version) ||
		utils.Compare(u.LastestVersion, ">", u.CurrVersion) {
		return log.LogColor.Info(" [update available]")
	}
	return ""
}
