// pkg/config/banner.go
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gookit/color"
	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/utils"
)

const (
	Version     = "3.3.6"
	ProjectName = "Afrog"
	Codename    = "Lightweight, Fast, and Direct to the Flaw."
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

func ShowBanner(u *AfrogUpdate, curated *Curated) {
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
	PrintStatusLine(log.LogColor.Low(okSymbol), "POC: ", pocLine, "")

	count, lastErr := curatedStats()
	planetLink := log.LogColor.Extractor("https://t.zsxq.com/lV66x")
	symbol := log.LogColor.Low(okSymbol)
	value := fmt.Sprintf("%d/pocs", count)
	extra := ""
	if !curatedEnabled(curated) {
		extra = log.LogColor.DarkGray("(off)")
	} else {
		errMsg := strings.TrimSpace(lastErr)
		if errMsg != "" {
			symbol = log.LogColor.Red(errorSymbol)
			extra = log.LogColor.Red("update failed: " + truncateError(errMsg))
		}
	}
	line := value + " " + planetLink
	if strings.TrimSpace(extra) != "" {
		line = value + " " + extra + " " + planetLink
	}
	PrintStatusLine(symbol, "Cur:", line, "")
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

func curatedEnabled(cur *Curated) bool {
	if cur == nil {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(cur.Enabled))
	if mode == "" {
		mode = "auto"
	}
	return mode != "off" && mode != "false" && mode != "0"
}

func curatedStats() (int, string) {
	items, err := pocsrepo.ListMeta(pocsrepo.ListOptions{Source: "curated"})
	if err != nil {
		return 0, readCuratedLastError()
	}
	return len(items), readCuratedLastError()
}

func readCuratedLastError() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	path := filepath.Join(home, ".config", "afrog", "curated-state.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var state struct {
		LastError string `json:"last_error"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return ""
	}
	return strings.TrimSpace(state.LastError)
}

func truncateError(msg string) string {
	if msg == "" {
		return ""
	}
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	if len(msg) > 80 {
		return msg[:77] + "..."
	}
	return msg
}
