// pkg/config/banner.go
package config

import (
	"fmt"
	"strings"

	"github.com/gookit/color"
	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/utils"
)

const (
	Version     = "3.2.2"
	ProjectName = "Afrog"
	Codename    = "Life is fantastic. Enjoy life."
	LineWidth   = 56
)

var (
	updateSymbol string
	okSymbol     string
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
		errorSymbol = "✖"
	} else {
		updateSymbol = "^"
		okSymbol = "√"
		errorSymbol = "X"
	}
}

func ShowBanner(u *AfrogUpdate, oobStatus string) {
	initSymbols()

	// 第一行标题
	title := fmt.Sprintf("%s/%s | %s | %s",
		color.FgLightBlue.Render(ProjectName),
		Version,
		color.FgYellow.Render("Security Toolkit"),
		color.FgLightMagenta.Render(Codename),
	)
	fmt.Println("\n" + title)

	// 分隔线
	PrintSeparator()

	// 核心信息行
	PrintStatusLine(
		log.LogColor.Low(okSymbol),
		"Core:",
		EngineV(u),
		"",
	)

	// POC信息行
	pocLine := PocV(u)
	if utils.Compare(u.LastestVersion, ">", u.CurrVersion) {
		pocLine += " " + log.LogColor.Extractor("(update available)")
	}
	PrintStatusLine(
		log.LogColor.Low(okSymbol),
		"POC: ",
		pocLine,
		"",
	)
}

func ShowVersion() {
	fmt.Printf("%s %s\n", ProjectName, Version)
}

func PrintSeparator() {
	fmt.Println(log.LogColor.DarkGray(strings.Repeat("═", LineWidth)))
}

func PrintStatusLine(symbol, label, value, note string) {
	fmt.Printf("[%s] %-6s %-18s %s\n", symbol, label, value, note)
}

func EngineV(u *AfrogUpdate) string {
	version := Version
	if utils.Compare(u.LastestAfrogVersion, ">", Version) {
		return version + log.LogColor.Red(updateSymbol) + log.LogColor.DarkGray(" (up to date)")
	}
	return log.LogColor.Green(version)
}

func PocV(u *AfrogUpdate) string {
	base := u.CurrVersion
	if utils.Compare(u.LastestVersion, ">", u.CurrVersion) {
		return fmt.Sprintf("%s → %s", base, log.LogColor.Red(u.LastestVersion))
	}
	return log.LogColor.Green(base)
}
