// pkg/config/banner.go
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/utils"
)

const ProjectName = "Afrog"

// Version 由构建流程注入，不再手改源码：
//   - 正式发布：GoReleaser 通过 -ldflags "-X .../pkg/config.Version={{ .Version }}"
//     注入，.Version 是去掉前导 v 的 tag；
//   - 本地构建：make build 不注入，由下面的 BuildInfo 兜底给出干净版本号。
//
// 两者都没注入时回落到 debug.ReadBuildInfo：go install 模块@版本 给出模块版本，
// Go 1.24 起的本地构建给出基于 git 的伪版本（如 3.5.10-0.20261101025247-74124edaf573+dirty）。
// 伪版本只保留前半段的版本号（3.5.10），避免启动横幅和 -version 输出一长串 commit/脏标记；
// 需要 commit 信息时查 git 记录即可。最终仍拿不到时回落到 "dev"。
//
// 注意：链接器的 -X 只能改写「未初始化或初始化为常量」的字符串变量，所以这里必须声明为零值，
// 再由 init 兜底填充；若写成 var Version = versionFromBuildInfo()，-X 会静默失效。
var Version string

func init() {
	if Version == "" {
		Version = versionFromBuildInfo()
	}
}

func versionFromBuildInfo() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return "dev"
	}
	v := cleanVersion(strings.TrimPrefix(strings.TrimSpace(info.Main.Version), "v"))
	if v == "" || v == "(devel)" {
		return "dev"
	}
	return v
}

// pseudoVersionRe 匹配 Go 伪版本的提交后缀，如 -0.20261101025247-74124edaf573。
var pseudoVersionRe = regexp.MustCompile(`-0\.\d{14}-[0-9a-f]+`)

// cleanVersion 去掉构建元数据（+dirty/+incompatible）和伪版本后缀，只保留版本号本身。
func cleanVersion(v string) string {
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if loc := pseudoVersionRe.FindStringIndex(v); loc != nil {
		v = v[:loc[0]]
	}
	return v
}

// ShowBanner 打印极简启动头：一行品牌与版本，一行资源版本。
// 两行都从第 0 列顶格起排（不再有行首缩进），与后续结果行、运维行同一列口径；
// 去掉了分隔线与重复的状态符号，扫描输出从下一行直接开始，不再用装饰抢注意力。
func ShowBanner(u *AfrogUpdate, curated *Curated) {
	sep := log.LogColor.DarkGray(" · ")

	head := log.LogColor.Info(strings.ToLower(ProjectName)) + " " +
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

	res := log.LogColor.DarkGray("pocs") + " " + tpl + sep +
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
