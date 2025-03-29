// pkg/config/banner.go
package config

import (
	"fmt"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/utils"
)

const (
	Version     = "3.1.7"
	ProjectName = "Afrog"
	Codename    = "Ne Zha II"
	LineWidth   = 56
)

var (
	updateSymbol string
	okSymbol     string
	warnSymbol   string
	errorSymbol  string
)

func GetOkSymbol() string {
	return okSymbol
}

func GetErrorSymbol() string {
	return errorSymbol
}

func initSymbols() {
	if utils.IsUnicodeSupported() {
		updateSymbol = "↑"
		okSymbol = "✓"
		warnSymbol = "!"
		errorSymbol = "✖"
	} else {
		updateSymbol = "^"
		okSymbol = "√"
		warnSymbol = "!"
		errorSymbol = "X"
	}
}

func ShowBanner(u *AfrogUpdate, oobStatus string) {
	initSymbols()

	// 第一行标题
	title := fmt.Sprintf("%s/%s | %s | %s",
		log.Blue(ProjectName),
		log.Cyan(Version),
		log.Yellow("Security Toolkit"),
		log.Magenta(Codename),
	)
	fmt.Println("\n" + title)

	// 分隔线
	PrintSeparator()

	// 核心信息行
	PrintStatusLine(
		log.Blue(okSymbol),
		"Core:",
		EngineV(u),
		"",
	)

	// POC信息行
	pocLine := PocV(u)
	if utils.Compare(u.LastestVersion, ">", u.CurrVersion) {
		pocLine += " " + log.Yellow("(update available)")
	}
	PrintStatusLine(
		log.Blue(okSymbol),
		"POC: ",
		pocLine,
		"",
	)
}

func PrintSeparator() {
	fmt.Println(log.Dim(strings.Repeat("═", LineWidth)))
}

func PrintStatusLine(symbol, label, value, note string) {
	fmt.Printf("[%s] %-6s %-18s %s\n", symbol, label, value, note)
}

func EngineV(u *AfrogUpdate) string {
	version := Version
	if utils.Compare(u.LastestAfrogVersion, ">", Version) {
		return version + log.Red(updateSymbol) + log.Dim(" (up to date)")
	}
	return log.Green(version)
}

func PocV(u *AfrogUpdate) string {
	base := u.CurrVersion
	if utils.Compare(u.LastestVersion, ">", u.CurrVersion) {
		return fmt.Sprintf("%s → %s", base, log.Red(u.LastestVersion))
	}
	return log.Green(base)
}
