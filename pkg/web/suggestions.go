package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/guard"
	"github.com/zan8in/gologger"
)

// 建议清单的参数。这些值刻意保守：建议是给人看的，不是越堆越多越好。
const (
	suggestionSampleLimit = 8
	suggestionScanTargets = 20
	suggestionStaleDays   = 30
)

// suggestionAction 描述「点了之后做什么」。
//
// kind=scan 时带上可直接起扫的目标；kind=link 时给出去哪看的路径。
// 前端不为每种建议写一套分支：扫描走既有的 stashScanTargets，链接走 goto。
type suggestionAction struct {
	Kind    string   `json:"kind"`
	Label   string   `json:"label"`
	Targets []string `json:"targets,omitempty"`
	Href    string   `json:"href,omitempty"`
}

// suggestion 是一条「下一步该做什么」。
type suggestion struct {
	ID       string           `json:"id"`
	Severity string           `json:"severity"`
	Title    string           `json:"title"`
	Detail   string           `json:"detail"`
	Count    int64            `json:"count"`
	Samples  []string         `json:"samples"`
	Action   suggestionAction `json:"action"`
}

type suggestionsResponse struct {
	Items []suggestion      `json:"items"`
	Guard guard.SummaryView `json:"guard"`
}

func suggestionsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "OK",
		Data:    suggestionsResponse{Items: buildSuggestions(), Guard: guard.Summary()},
	})
}

// buildSuggestions 由既有数据推导「下一步」，全部是确定性规则，不调用模型。
//
// 四条规则的共同点：都能直接落到一个动作（起扫或去看某个面板），
// 不产出「建议多关注安全」这类无法执行的废话。
func buildSuggestions() []suggestion {
	items := make([]suggestion, 0, 4)

	// 1. 从未被扫描、也从未出现在被动流量里的资产：最直接的补扫清单。
	if total, uncovered := selectNeverScannedAssets(suggestionScanTargets); total > 0 {
		targets := make([]string, 0, len(uncovered))
		for _, a := range uncovered {
			targets = append(targets, a.Address)
		}
		items = append(items, suggestion{
			ID:       "unscanned-assets",
			Severity: "high",
			Title:    fmt.Sprintf("%d 个资产从未被扫描过", total),
			Detail:   "资产库里有记录，但既没有主动扫描轨迹，也没有出现在被动流量里。可以按下列目标起一次扫描，或让业务流量经过被动代理。",
			Count:    int64(total),
			Samples:  firstN(targets, suggestionSampleLimit),
			Action: suggestionAction{
				Kind:    "scan",
				Label:   "扫描这些资产",
				Targets: targets,
			},
		})
	}

	// 2. 覆盖空洞：有流量，但每个检测器都只产出过「跳过」。
	if hosts, total, err := sqlite.SelectCoverageGapHosts(suggestionSampleLimit); err != nil {
		gologger.Debug().Msgf("读取覆盖空洞失败: %v", err)
	} else if total > 0 {
		items = append(items, suggestion{
			ID:       "coverage-gap",
			Severity: "medium",
			Title:    fmt.Sprintf("%d 个主机存在覆盖空洞", total),
			Detail:   "这些主机有被动流量，但所有检测器都只产生过「跳过」。常见原因是接口没有参数、响应体过小，或目标落在扫描范围之外。",
			Count:    total,
			Samples:  firstN(hosts, suggestionSampleLimit),
			Action: suggestionAction{
				Kind:  "link",
				Label: "查看覆盖度明细",
				Href:  "/passive",
			},
		})
	}

	// 3. 陈旧资产：扫过但太久没复测。
	if assets, total, err := sqlite.SelectStaleAssets(suggestionStaleDays, suggestionScanTargets); err != nil {
		gologger.Debug().Msgf("读取陈旧资产失败: %v", err)
	} else if total > 0 {
		targets := scannableTargets(assets)
		if len(targets) > 0 {
			items = append(items, suggestion{
				ID:       "stale-assets",
				Severity: "medium",
				Title:    fmt.Sprintf("%d 个资产超过 %d 天未复测", total, suggestionStaleDays),
				Detail:   "漏洞会随版本更新重新出现。建议对这批资产做一次复测，确认此前的修复没有回退。",
				Count:    total,
				Samples:  firstN(targets, suggestionSampleLimit),
				Action: suggestionAction{
					Kind:    "scan",
					Label:   "复测这些资产",
					Targets: targets,
				},
			})
		}
	}

	// 4. 未入台账的被动命中：已经确认过，但还没进报告。
	if briefs, total, err := sqlite.SelectUnpromotedPassiveFindings(suggestionSampleLimit); err != nil {
		gologger.Debug().Msgf("读取未入台账命中失败: %v", err)
	} else if total > 0 {
		samples := make([]string, 0, len(briefs))
		for _, b := range briefs {
			samples = append(samples, b.Title+" · "+b.Target)
		}
		items = append(items, suggestion{
			ID:       "unpromoted-findings",
			Severity: "medium",
			Title:    fmt.Sprintf("%d 条被动命中尚未进入台账", total),
			Detail:   "这些命中已经通过零误报门控，但还没有出现在报告里。确认无误后提升为台账记录。",
			Count:    total,
			Samples:  firstN(samples, suggestionSampleLimit),
			Action: suggestionAction{
				Kind:  "link",
				Label: "去被动命中页处理",
				Href:  "/passive",
			},
		})
	}

	return items
}

// selectNeverScannedAssets 返回「从未主动扫描、也从未被被动覆盖」的资产。
//
// 与「陈旧资产」严格互斥：后者要求 last_scan_at 非空，避免同一目标被两条建议
// 重复点名，让清单失去可执行性。
func selectNeverScannedAssets(limit int) (int, []uncoveredAsset) {
	covered, err := sqlite.SelectCoverageHosts("")
	if err != nil {
		gologger.Debug().Msgf("读取已覆盖资产失败: %v", err)
		return 0, nil
	}
	assets, err := sqlite.SelectAssetsForCoverage("")
	if err != nil {
		gologger.Debug().Msgf("读取资产失败: %v", err)
		return 0, nil
	}

	out := make([]uncoveredAsset, 0, limit)
	count := 0
	seen := make(map[string]struct{}, len(assets))
	for _, a := range assets {
		if strings.TrimSpace(a.LastScanAt) != "" {
			continue
		}
		// 脏资产（如把端口 "21" 存成域名）不参与建议：一键起扫必然失败。
		if !sqlite.IsScannableAddress(a.Address) {
			continue
		}
		host := coverageHostOfAsset(a.Address, a.Type)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		if _, ok := covered[host]; ok {
			continue
		}
		count++
		if len(out) < limit {
			out = append(out, uncoveredAsset{ID: a.ID, Address: a.Address, Type: a.Type, Host: host})
		}
	}
	return count, out
}

// scannableTargets 只保留可执行的目标地址：脏资产（把端口存成主机之类的）
// 一旦进入动作按钮，用户点一次就失败一次，比不给建议更糟。
func scannableTargets(assets []sqlite.CoverageAsset) []string {
	out := make([]string, 0, len(assets))
	for _, a := range assets {
		if sqlite.IsScannableAddress(a.Address) {
			out = append(out, a.Address)
		}
	}
	return out
}

// firstN 取前 n 个非空字符串，供样例展示。
func firstN(in []string, n int) []string {
	out := make([]string, 0, n)
	for _, v := range in {
		if v == "" {
			continue
		}
		out = append(out, v)
		if len(out) >= n {
			break
		}
	}
	return out
}
