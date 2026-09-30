package web

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/gologger"
)

// navBadges 是左侧菜单 badge 的计数快照。
//
// 「今日新增」「待确认数」是绝对计数；PoC 两个字段给的是总量，
// 前端与本地记录的基线相减，得到用户意义上的「新增数」。
type navBadges struct {
	// ReportsToday 是今日入库的命中行数（漏洞报告菜单「今日新增」）。
	ReportsToday int64 `json:"reports_today"`
	// LedgerPending 是台账中待确认的条目数（漏洞台账菜单）。
	LedgerPending int64 `json:"ledger_pending"`
	// PocsTotal 是全部 PoC 数（含内置 / curated / my，已按 ID 去重）。
	PocsTotal int `json:"pocs_total"`
	// CuratedPocsTotal 是本地 curated PoC 数。
	CuratedPocsTotal int `json:"curated_pocs_total"`
}

// navBadgeTTL 是 badge 快照的缓存时长。
//
// 两个计数都很重：PoC 总量要遍历目录并解析 YAML，台账待确认数要在
// 全表聚合视图上再过滤一次。它们又只是「角标」级别的信息，
// 因此统一做短 TTL 缓存，把成本压到每分钟最多一次。
const navBadgeTTL = 30 * time.Second

var navBadgeCache struct {
	mu   sync.Mutex
	data navBadges
	at   time.Time
}

// invalidateNavBadgeCache 让下一次请求重新计算。PoC 库发生变化时调用。
func invalidateNavBadgeCache() {
	navBadgeCache.mu.Lock()
	navBadgeCache.at = time.Time{}
	navBadgeCache.mu.Unlock()
}

// currentNavBadges 汇总菜单 badge 计数，带短 TTL 缓存。
//
// 各计数相互独立：单项出错只记为 0 并留下告警，不拖垮整个角标接口。
func currentNavBadges() navBadges {
	navBadgeCache.mu.Lock()
	defer navBadgeCache.mu.Unlock()

	if !navBadgeCache.at.IsZero() && time.Since(navBadgeCache.at) < navBadgeTTL {
		return navBadgeCache.data
	}

	var out navBadges

	// created 存的是本地时间字符串，这里用同样的本地格式取当天零点。
	today := time.Now().Format("2006-01-02") + " 00:00:00"
	if n, err := sqlite.CountResultsSince(today); err != nil {
		gologger.Warning().Msgf("nav badges: count today results failed: %v", err)
	} else {
		out.ReportsToday = n
	}

	if n, err := sqlite.CountLedgerPending(); err != nil {
		gologger.Warning().Msgf("nav badges: count pending ledger failed: %v", err)
	} else {
		out.LedgerPending = n
	}

	if items, err := pocsrepo.ListMeta(pocsrepo.ListOptions{Source: "all"}); err != nil {
		gologger.Warning().Msgf("nav badges: list pocs failed: %v", err)
	} else {
		out.PocsTotal = len(items)
	}
	// 复用 /curated/status 的 30s 缓存，避免重复遍历 curated 目录。
	out.CuratedPocsTotal = curatedPocCount()

	navBadgeCache.data = out
	navBadgeCache.at = time.Now()
	return out
}

// navBadgesHandler 返回左侧菜单 badge 的计数快照。所有登录用户可用。
func navBadgesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "仅支持GET方法"})
		return
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: currentNavBadges()})
}
