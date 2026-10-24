// pkg/config/banner.go
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/utils"
)

const (
	Version     = "3.5.8"
	ProjectName = "Afrog"
)

// ShowBanner 打印极简启动头：一行品牌与版本，一行资源版本。
// 去掉了分隔线与重复的状态符号，扫描输出从下一行直接开始，不再用装饰抢注意力。
func ShowBanner(u *AfrogUpdate, curated *Curated) {
	sep := log.LogColor.DarkGray(" · ")

	head := "  " + log.LogColor.Info(strings.ToLower(ProjectName)) + " " +
		log.LogColor.DarkGray(Version) + sep + log.LogColor.DarkGray("security toolkit")

	tpl := log.LogColor.Green(u.CurrVersion)
	if utils.Compare(u.LastestVersion, ">", u.CurrVersion) {
		tpl += " " + log.LogColor.Red("→ "+u.LastestVersion)
	}

	count, lastErr := curatedStats()
	cur := log.LogColor.Green(fmt.Sprintf("%d pocs", count))
	switch {
	case !curatedEnabled(curated):
		cur = log.LogColor.DarkGray(fmt.Sprintf("%d pocs", count))
	case strings.TrimSpace(lastErr) != "":
		cur = log.LogColor.Red("update failed")
	}

	res := "  " + log.LogColor.DarkGray("templates") + " " + tpl + sep +
		log.LogColor.DarkGray("curated") + " " + cur

	fmt.Println()
	fmt.Println(head)
	fmt.Println(res)
	fmt.Println()
}

func ShowVersion() {
	fmt.Printf("%s %s\n", ProjectName, Version)
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
