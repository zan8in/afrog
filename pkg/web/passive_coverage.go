package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/passive"
	"github.com/zan8in/gologger"
)

// 覆盖度刷盘参数。
//
// 覆盖度是逐请求产生的信号，直接写库会把 SQLite 打成瓶颈，所以先在内存里按
// (项目, 资产, 检测器) 聚合，再批量落库。阈值同时看条数与时间：条数控制写放大，
// 时间保证低流量场景下数据不会长时间只存在于内存。
const (
	coverageFlushBatch = 256
	coverageFlushEvery = 3 * time.Second
	// maxCoverageBuckets 是内存聚合表的上限。正常情况下每次刷盘都会清空，
	// 只有数据库持续写失败时才会堆积；超过上限就整体丢弃并记错误，
	// 宁可少一段覆盖度，也不让被动链路因为落库问题而吃满内存。
	maxCoverageBuckets = 20000
	// uncoveredAssetLimit 是「从未被被动流量覆盖」返回的资产条数上限。
	uncoveredAssetLimit = 50
)

type coverageKey struct {
	projectID string
	host      string
	detector  string
}

type coverageBucket struct {
	state       passive.CoverageState
	reason      string
	samples     int64
	hits        int64
	skipped     int64
	errors      int64
	lastVerdict passive.TrafficVerdict
	firstSeen   time.Time
	lastSeen    time.Time
}

// passiveCoverageStore 是覆盖度台账的内存聚合层。
type passiveCoverageStore struct {
	mu sync.Mutex
	// projectID 在启动时固定：覆盖度与命中一样按项目隔离，不随请求变化。
	projectID string
	// detectors 是本次运行启用的检测器/提取器名单，用于把代理层的「整条跳过」
	// 展开成每个检测器的一行——代理层不知道检测器，只有这里知道。
	detectors []string
	buckets   map[coverageKey]*coverageBucket
	pending   int
	lastFlush time.Time
	flushed   int64
	lastErr   string
}

var passiveCoverage = &passiveCoverageStore{}

// reset 在一次启动时重建聚合状态。历史数据保留在库里，这里只清内存。
func (s *passiveCoverageStore) reset(projectID string, detectors []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.projectID = projectID
	s.detectors = append([]string(nil), detectors...)
	s.buckets = make(map[coverageKey]*coverageBucket)
	s.pending = 0
	s.lastFlush = time.Now()
	s.flushed = 0
	s.lastErr = ""
}

// coverageStateRank 与 SQL 侧的优先级保持一致：hit > tested > error > skipped。
func coverageStateRank(st passive.CoverageState) int {
	switch st {
	case passive.CoverageHit:
		return 3
	case passive.CoverageTested:
		return 2
	case passive.CoverageError:
		return 1
	default:
		return 0
	}
}

// observe 接收引擎上报的覆盖度信号。
func (s *passiveCoverageStore) observe(sig passive.CoverageSignal) {
	if strings.TrimSpace(sig.Target) == "" || strings.TrimSpace(sig.Detector) == "" {
		return
	}
	s.mu.Lock()
	needFlush := s.observeLocked(sig)
	s.mu.Unlock()
	if needFlush {
		if err := s.flush(); err != nil {
			gologger.Debug().Msgf("覆盖度刷盘失败: %v", err)
		}
	}
}

func (s *passiveCoverageStore) observeLocked(sig passive.CoverageSignal) bool {
	if s.buckets == nil {
		s.buckets = make(map[coverageKey]*coverageBucket)
	}
	if sig.At.IsZero() {
		sig.At = time.Now()
	}
	k := coverageKey{projectID: s.projectID, host: strings.ToLower(sig.Target), detector: sig.Detector}
	b := s.buckets[k]
	if b == nil {
		b = &coverageBucket{state: sig.State, firstSeen: sig.At}
		s.buckets[k] = b
	}
	if b.firstSeen.IsZero() {
		b.firstSeen = sig.At
	}

	b.samples++
	switch sig.State {
	case passive.CoverageHit:
		b.hits++
	case passive.CoverageSkipped:
		b.skipped++
	case passive.CoverageError:
		b.errors++
	}
	if coverageStateRank(sig.State) >= coverageStateRank(b.state) {
		b.state = sig.State
		if strings.TrimSpace(sig.Reason) != "" {
			b.reason = sig.Reason
		}
	}
	if sig.Verdict != "" {
		b.lastVerdict = sig.Verdict
	}
	if sig.At.After(b.lastSeen) {
		b.lastSeen = sig.At
	}

	s.pending++
	if s.pending >= coverageFlushBatch || time.Since(s.lastFlush) >= coverageFlushEvery {
		return true
	}
	return false
}

// observeProxySkip 处理代理层直接放过的流量。
//
// 这类流量（范围外、非幂等方法、二进制静态资源）进不了调度层，因此引擎不会
// 为它产生覆盖度信号。但它们恰恰是「为什么这块没测」的重要答案，必须补上：
// 展开成每个已启用检测器的一行 skipped，原因沿用代理层给出的可读文案。
func (s *passiveCoverageStore) observeProxySkip(ev passive.TrafficEvent) {
	switch ev.Verdict {
	case passive.VerdictSkippedMethod, passive.VerdictSkippedScope,
		passive.VerdictSkippedPath, passive.VerdictSkippedStatic:
	default:
		return
	}
	host := coverageHostFromURL(ev.URL)
	if host == "" {
		return
	}

	s.mu.Lock()
	detectors := append([]string(nil), s.detectors...)
	s.mu.Unlock()

	for _, d := range detectors {
		s.observe(passive.CoverageSignal{
			Target:   host,
			Detector: d,
			State:    passive.CoverageSkipped,
			Reason:   ev.Reason,
			Verdict:  ev.Verdict,
			At:       ev.Time,
		})
	}
}

// flush 把内存里的聚合结果写入数据库。成功后清空内存，失败保留待下次重试。
func (s *passiveCoverageStore) flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.buckets) == 0 {
		s.pending = 0
		s.lastFlush = time.Now()
		return nil
	}

	rows := make([]sqlite.PassiveCoverage, 0, len(s.buckets))
	for k, b := range s.buckets {
		rows = append(rows, sqlite.PassiveCoverage{
			ProjectID:   k.projectID,
			Host:        k.host,
			Detector:    k.detector,
			State:       string(b.state),
			Reason:      b.reason,
			Samples:     b.samples,
			Hits:        b.hits,
			Skipped:     b.skipped,
			Errors:      b.errors,
			LastVerdict: string(b.lastVerdict),
			FirstSeen:   b.firstSeen.Format("2006-01-02 15:04:05"),
			LastSeen:    b.lastSeen.Format("2006-01-02 15:04:05"),
		})
	}

	if err := sqlite.UpsertPassiveCoverage(rows); err != nil {
		s.lastErr = err.Error()
		if len(s.buckets) > maxCoverageBuckets {
			s.buckets = make(map[coverageKey]*coverageBucket)
			s.pending = 0
		}
		return err
	}

	s.flushed += int64(len(rows))
	s.buckets = make(map[coverageKey]*coverageBucket)
	s.pending = 0
	s.lastFlush = time.Now()
	s.lastErr = ""
	return nil
}

// snapshot 返回聚合层的可观测信息，供诊断接口使用。
func (s *passiveCoverageStore) snapshot() (pending int, flushed int64, lastErr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending, s.flushed, s.lastErr
}

// resolveAssetIDForHost 把命中的 authority 锚定到资产库里的资产。
//
// 命中频率很低（只有确认命中才调用），因此不走缓存：先由 SQL 做前缀粗筛，
// 再用与覆盖度同一个归一化函数精确比对，避免 a.example 误匹配 a.example.evil.com。
//
// 先按项目找，找不到再退回全局：资产表按地址全局唯一，而项目与资产的关联
// 是可选的整理动作；若只查项目内，未关联项目的老资产会让血缘整条断掉。
func resolveAssetIDForHost(projectID, host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	if id := matchAssetID(projectID, host); id != "" {
		return id
	}
	if strings.TrimSpace(projectID) == "" {
		return ""
	}
	return matchAssetID("", host)
}

// matchAssetID 在给定作用域内做精确匹配。
func matchAssetID(projectID, host string) string {
	candidates, err := sqlite.SelectAssetCandidatesByHost(projectID, host)
	if err != nil {
		return ""
	}
	for _, a := range candidates {
		if coverageHostOfAsset(a.Address, a.Type) == host {
			return a.ID
		}
	}
	return ""
}

// coverageHostFromURL 从 URL 提取 authority；失败返回空串。
func coverageHostFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Host)
}

// coverageHostOfAsset 把资产地址归一成与覆盖度一致的 authority 口径。
//
// 只处理能一一对应的类型：cidr 无法映射到单个 authority，返回空串由调用方忽略。
func coverageHostOfAsset(addr, typ string) string {
	addr = strings.TrimSpace(strings.ToLower(addr))
	if addr == "" {
		return ""
	}
	if typ == "url" || strings.Contains(addr, "://") {
		u, err := url.Parse(addr)
		if err != nil || u.Host == "" {
			return ""
		}
		host := strings.ToLower(u.Host)
		// 默认端口与「不带端口」视为同一台资产，否则 https://a.example 与
		// a.example:443 会各算一次，未覆盖清单里出现重复项。
		switch {
		case u.Scheme == "http" && strings.HasSuffix(host, ":80"):
			host = strings.TrimSuffix(host, ":80")
		case u.Scheme == "https" && strings.HasSuffix(host, ":443"):
			host = strings.TrimSuffix(host, ":443")
		}
		return host
	}
	if typ == "cidr" {
		return ""
	}
	return addr
}

// passiveCoverageHandler 返回覆盖度台账、整体分布与「从未被覆盖」的资产。
func passiveCoverageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 先把内存里的聚合结果落盘，保证页面看到的是最新数据。
	flushErr := passiveCoverage.flush()

	q := r.URL.Query()
	page := atoiParam(q.Get("page"), 1)
	if page <= 0 {
		page = 1
	}
	pageSize := atoiParam(q.Get("page_size"), 50)
	if pageSize <= 0 {
		pageSize = 50
	}

	flt := sqlite.PassiveCoverageFilter{
		Detector: strings.TrimSpace(q.Get("detector")),
		Keyword:  strings.TrimSpace(q.Get("keyword")),
		Page:     page,
		PageSize: pageSize,
	}
	if v := strings.TrimSpace(q.Get("project_id")); v != "" {
		flt.ProjectID = v
	}
	if v := strings.TrimSpace(q.Get("state")); v != "" {
		flt.State = strings.Split(v, ",")
	}

	items, total, err := sqlite.SelectPassiveCoverage(flt)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "覆盖度查询失败"})
		return
	}
	summary, err := sqlite.SelectPassiveCoverageSummary(flt.ProjectID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "覆盖度汇总失败"})
		return
	}

	uncoveredCount, uncoveredItems := selectUncoveredAssets(flt.ProjectID, uncoveredAssetLimit)

	_, flushed, lastErr := passiveCoverage.snapshot()
	if flushErr != nil {
		lastErr = flushErr.Error()
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: map[string]any{
		"items":     items,
		"total":     total,
		"page":      flt.Page,
		"page_size": flt.PageSize,
		"summary":   summary,
		"uncovered": map[string]any{
			"count": uncoveredCount,
			"items": uncoveredItems,
		},
		"flushed":    flushed,
		"last_error": lastErr,
	}})
}

// selectUncoveredAssets 计算「资产进了库、但从未被被动流量覆盖」的清单。
//
// 它回答的是与覆盖度矩阵相反的问题：矩阵看「测过的那些为什么没结论」，
// 这里看「哪些资产压根没出现过」。两者合起来才是完整的查漏视图。
func selectUncoveredAssets(projectID string, limit int) (int, []uncoveredAsset) {
	covered, err := sqlite.SelectCoverageHosts(projectID)
	if err != nil {
		return 0, []uncoveredAsset{}
	}
	assets, err := sqlite.SelectAssetsForCoverage(projectID)
	if err != nil {
		return 0, []uncoveredAsset{}
	}

	out := make([]uncoveredAsset, 0, limit)
	count := 0
	seen := make(map[string]struct{}, len(assets))
	for _, a := range assets {
		// 与建议侧同口径：把端口误存成主机这类脏资产不是可执行目标，
		// 列在「未覆盖」里只会让人反复点一个必定失败的目标。
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

// uncoveredAsset 是未覆盖资产清单的一行。
type uncoveredAsset struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Type    string `json:"type"`
	Host    string `json:"host"`
}
