package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/passive"
	"github.com/zan8in/afrog/v3/pkg/passive/proxy"
)

// passiveTrafficLimit 是实时流量环形缓冲的容量。
//
// 只保留最近若干条，不落库：被动扫描的选择是「仅存命中」，这里满足的是
// 「看得见过程」。500 条约等于十几次完整页面加载，足够定位问题又不占内存。
const passiveTrafficLimit = 500

// passiveDiagErrorLimit 是诊断页保留的异常条数。
const passiveDiagErrorLimit = 50

// passiveDiagError 是一条可展示的异常记录。
type passiveDiagError struct {
	Time   time.Time `json:"time"`
	Scope  string    `json:"scope"`
	Detail string    `json:"detail"`
}

// passiveTrafficLog 是"为什么没检测"的唯一事实来源。
type passiveTrafficLog struct {
	mu     sync.Mutex
	items  []passive.TrafficEvent
	next   int
	counts map[passive.TrafficVerdict]uint64
	errs   []passiveDiagError
}

var passiveTraffic = &passiveTrafficLog{}

// reset 在一次启动时清空历史，避免上一次运行的结论误导本次排查。
func (l *passiveTrafficLog) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.items = nil
	l.next = 0
	l.counts = nil
	l.errs = nil
}

func (l *passiveTrafficLog) add(ev passive.TrafficEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.counts == nil {
		l.counts = make(map[passive.TrafficVerdict]uint64, 8)
	}
	l.counts[ev.Verdict]++

	if len(l.items) < passiveTrafficLimit {
		l.items = append(l.items, ev)
		return
	}
	l.items[l.next] = ev
	l.next = (l.next + 1) % passiveTrafficLimit
}

// recordError 记录一条异常。scope 用「proxy / engine / detector:<name> / server」区分来源。
func (l *passiveTrafficLog) recordError(scope string, err error) {
	if err == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errs = append(l.errs, passiveDiagError{Time: time.Now(), Scope: scope, Detail: err.Error()})
	if len(l.errs) > passiveDiagErrorLimit {
		l.errs = l.errs[len(l.errs)-passiveDiagErrorLimit:]
	}
}

// passiveTrafficCounts 是按结论分类的累计计数。
//
// 与 Engine.Stats 的区别：Stats 数的是「调度层发生了什么」，这里数的是
// 「每条流量最终被判成什么」，包含代理层直接放过的静态资源。
type passiveTrafficCounts struct {
	Total         uint64 `json:"total"`
	SkippedStatic uint64 `json:"skipped_static"`
	SkippedMethod uint64 `json:"skipped_method"`
	SkippedPath   uint64 `json:"skipped_path"`
	// SkippedScope 是被使用者设定的扫描范围（Host 白/黑名单、路径排除）挡下的流量数。
	// 与静态资源跳过分开：这些请求本可检测，是使用者主动让它不扫的。
	SkippedScope uint64 `json:"skipped_scope"`
	// Dropped 是门控入口队列满而丢弃的流量数：这些请求连「要不要检测」都还没判过。
	Dropped uint64 `json:"dropped"`
	// DroppedDetect 是已确认需要检测、却因检测队列满而未检测的流量数。
	// 与 Dropped 分开：这一项直接对应漏报风险，混在一起会让使用者低估损失。
	DroppedDetect uint64 `json:"dropped_detect"`
	NoInterest    uint64 `json:"no_interest"`
	// KnownClean 是「注入点在有效期内已判定无注入、跳过重复重放」的流量数。
	// 它衡量的正是短期记忆省下的昂贵重放量，与 NoInterest（不具备检测条件）不同：
	// 这些请求本可以检测，只是结论已被缓存。
	KnownClean uint64 `json:"known_clean"`
	NoFinding  uint64 `json:"no_finding"`
	Finding    uint64 `json:"finding"`
	// Duplicate 是「检出但被去重拦下」的流量数。与 Finding 分开计数：
	// 前者代表已经报过，后者才是本次真正新增，混在一起会让使用者误以为
	// 命中在涨、列表却不动。
	Duplicate uint64 `json:"duplicate"`
	Error     uint64 `json:"error"`
}

func (l *passiveTrafficLog) snapshot(limit int, verdict string) ([]passive.TrafficEvent, passiveTrafficCounts) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var counts passiveTrafficCounts
	for v, n := range l.counts {
		counts.Total += n
		switch v {
		case passive.VerdictSkippedStatic:
			counts.SkippedStatic = n
		case passive.VerdictSkippedMethod:
			counts.SkippedMethod = n
		case passive.VerdictSkippedPath:
			counts.SkippedPath = n
		case passive.VerdictSkippedScope:
			counts.SkippedScope = n
		case passive.VerdictDropped:
			counts.Dropped = n
		case passive.VerdictDroppedDetect:
			counts.DroppedDetect = n
		case passive.VerdictNoInterest:
			counts.NoInterest = n
		case passive.VerdictKnownClean:
			counts.KnownClean = n
		case passive.VerdictNoFinding:
			counts.NoFinding = n
		case passive.VerdictFinding:
			counts.Finding = n
		case passive.VerdictDuplicate:
			counts.Duplicate = n
		case passive.VerdictError:
			counts.Error = n
		}
	}

	if limit <= 0 || limit > passiveTrafficLimit {
		limit = passiveTrafficLimit
	}
	out := make([]passive.TrafficEvent, 0, limit)

	n := len(l.items)
	if n == 0 {
		return out, counts
	}
	// 从最新往回取。缓冲区未满时 next 恒为 0，此时最新一条在末尾。
	oldest := 0
	if n >= passiveTrafficLimit {
		oldest = l.next
	}
	for i := 0; i < n && len(out) < limit; i++ {
		idx := (oldest - 1 - i + passiveTrafficLimit*n) % n
		ev := l.items[idx]
		if verdict != "" && string(ev.Verdict) != verdict {
			continue
		}
		out = append(out, ev)
	}
	return out, counts
}

func (l *passiveTrafficLog) diagnosticsErrors() []passiveDiagError {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]passiveDiagError, len(l.errs))
	copy(out, l.errs)
	// 最新的在前，便于直接阅读。
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// -----------------------
// 观测接口
// -----------------------

func passiveTrafficHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	q := r.URL.Query()
	limit := atoiParam(q.Get("limit"), 200)
	items, counts := passiveTraffic.snapshot(limit, strings.TrimSpace(q.Get("verdict")))

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: map[string]any{
		"items":    items,
		"counts":   counts,
		"capacity": passiveTrafficLimit,
	}})
}

// passiveCAView 描述根证书的当前状态，回答「CA 配好了吗」。
type passiveCAView struct {
	Dir         string `json:"dir"`
	CertPath    string `json:"cert_path"`
	Exists      bool   `json:"exists"`
	Subject     string `json:"subject,omitempty"`
	NotBefore   string `json:"not_before,omitempty"`
	NotAfter    string `json:"not_after,omitempty"`
	DaysLeft    int    `json:"days_left"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Download    string `json:"download"`
}

// passiveDiagnostics 是「一眼黑」的正面解法：把链路每一段的真实状态摊开。
type passiveDiagnostics struct {
	Running         bool          `json:"running"`
	Addr            string        `json:"addr"`
	StartedAt       string        `json:"started_at,omitempty"`
	UptimeSeconds   int64         `json:"uptime_seconds"`
	Upstream        string        `json:"upstream,omitempty"`
	Detectors       []string      `json:"detectors"`
	Workers         int           `json:"workers"`
	DetectWorkers   int           `json:"detect_workers"`
	QueueSize       int           `json:"queue_size"`
	MaxRPS          int           `json:"max_rps"`
	HostConcurrency int           `json:"host_concurrency"`
	Stats           passive.Stats `json:"stats"`
	// Drained 表示「进入调度的事务是否已全部处理完」：积压与在途都为 0。
	// 它是判断「这一轮流量是否已检测完毕」的唯一准确信号——不能用
	// stats.inspected 代替，那个只统计真正跑过检测器的事务。
	Drained    bool                 `json:"drained"`
	Counts     passiveTrafficCounts `json:"counts"`
	TrafficCap int                  `json:"traffic_capacity"`
	CA         passiveCAView        `json:"ca"`
	LastError  string               `json:"last_error,omitempty"`
	Errors     []passiveDiagError   `json:"errors"`
	Hints      []string             `json:"hints"`
}

func passiveDiagnosticsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	passiveRT.mu.Lock()
	running := passiveRT.server != nil
	cfg := passiveRT.cfg
	caDir := passiveRT.caDir
	startedAt := passiveRT.startedAt
	lastErr := passiveRT.lastErr
	engine := passiveRT.engine
	srv := passiveRT.server
	passiveRT.mu.Unlock()

	dg := passiveDiagnostics{
		Running:         running,
		Addr:            cfg.Addr(),
		Upstream:        cfg.Upstream,
		Detectors:       cfg.EnabledDetectors(),
		Workers:         cfg.WorkersOrDefault(),
		DetectWorkers:   cfg.DetectWorkersOrDefault(),
		QueueSize:       cfg.QueueSizeOrDefault(),
		MaxRPS:          cfg.MaxRPS,
		HostConcurrency: cfg.HostConcurrency,
		TrafficCap:      passiveTrafficLimit,
		LastError:       lastErr,
	}
	if running {
		if srv != nil {
			dg.Addr = srv.Addr()
		}
		dg.StartedAt = startedAt.Format(time.RFC3339)
		dg.UptimeSeconds = int64(time.Since(startedAt).Seconds())
	}
	if engine != nil {
		dg.Stats = engine.Stats()
		dg.Drained = engine.Drained()
	}
	_, dg.Counts = passiveTraffic.snapshot(1, "")
	dg.CA = passiveCAInfo(caDir)
	dg.Errors = passiveTraffic.diagnosticsErrors()
	dg.Hints = passiveHints(dg)
	if dg.Errors == nil {
		dg.Errors = []passiveDiagError{}
	}

	_ = json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "ok", Data: dg})
}

// passiveCAInfo 读取根证书并给出可直接判断的信息。
//
// 顺序上先取证书再判断文件是否存在：LoadOrCreateCA 在缺失时会生成，
// 这样「是否存在」与后面给出的主题/指纹描述的是同一张证书，不会自相矛盾。
func passiveCAInfo(caDir string) passiveCAView {
	certPath := proxy.CACertPath(caDir)
	view := passiveCAView{
		Dir:      caDir,
		CertPath: certPath,
		Download: "/api/passive/ca",
	}

	ca, err := proxy.LoadOrCreateCA(caDir)
	if err != nil || ca == nil || ca.Cert == nil {
		return view
	}
	if _, err := os.Stat(certPath); err == nil {
		view.Exists = true
	}
	sum := sha256.Sum256(ca.Cert.Raw)
	view.Subject = ca.Cert.Subject.String()
	view.NotBefore = ca.Cert.NotBefore.Format(time.RFC3339)
	view.NotAfter = ca.Cert.NotAfter.Format(time.RFC3339)
	view.DaysLeft = int(time.Until(ca.Cert.NotAfter).Hours() / 24)
	view.Fingerprint = hex.EncodeToString(sum[:])
	return view
}

// passiveHints 把「当前的数字」翻译成「下一步该做什么」。
//
// 这是整个可观测性改造的落点：使用者不需要理解 Submitted / Inspected 的区别，
// 只需要照着提示做。
func passiveHints(dg passiveDiagnostics) []string {
	hints := make([]string, 0, 6)

	if !dg.Running {
		hints = append(hints, "被动代理未启动：点击「启动」后才会监听并接收流量。")
		return hints
	}
	if dg.Counts.Total == 0 {
		hints = append(hints,
			"尚未看到任何流量：请确认 Burp / 浏览器已把上游代理指向 "+dg.Addr+"，HTTPS 站点还需先信任根证书。")
		return hints
	}
	if dg.Counts.SkippedStatic > 0 && dg.Stats.Submitted == 0 {
		hints = append(hints, "目前只看到静态资源（js/css/图片），这类请求不参与检测；请访问带参数的接口，例如 /api/user?id=1。")
	}
	if dg.Counts.SkippedScope > 0 {
		hints = append(hints,
			"有 "+strconv.FormatUint(dg.Counts.SkippedScope, 10)+
				" 条流量落在扫描范围之外（Host 白名单/黑名单或路径排除），已在代理层被放过；如果这些目标本该检测，请调整「设置」里的扫描范围。")
	}
	if dg.Stats.Submitted > 0 && dg.Stats.Inspected == 0 {
		hints = append(hints, "流量已进入调度但没有一条通过检测条件：在「实时流量」里看「原因」列，即可知道卡在哪一步。")
	}
	if dg.Stats.Inspected > 0 && dg.Stats.Detected == 0 {
		hints = append(hints, "检测已执行但无结论：SQLi 要求参数可注入且页面基线稳定，动态页面（带时间戳/随机 token）会被主动跳过。")
	}
	if dg.Counts.Dropped > 0 {
		hints = append(hints, "存在因门控队列满被丢弃的事务：这些请求连「要不要检测」都还没判过。可在「设置」里调大门控并发（workers）与队列容量。")
	}
	if dg.Counts.DroppedDetect > 0 {
		hints = append(hints,
			"有 "+strconv.FormatUint(dg.Counts.DroppedDetect, 10)+
				" 条已确认需要检测、却因检测能力饱和被丢弃：这是实打实的漏报风险，请在「设置」里调大「检测并发（detect_workers）」。")
	}
	if dg.Stats.SkippedKnown > 0 {
		hints = append(hints,
			"短期记忆已跳过 "+strconv.FormatUint(dg.Stats.SkippedKnown, 10)+
				" 条重复重放：同注入点在有效期内不再复测（命中永久、未命中 30 分钟），这是省流量的正常表现。")
	}
	if dg.QueueSize > 0 && dg.Stats.QueueDepth >= dg.QueueSize {
		hints = append(hints,
			"门控队列已打满（"+strconv.Itoa(dg.Stats.QueueDepth)+"/"+strconv.Itoa(dg.QueueSize)+
				"）：此刻到达的新流量会被直接丢弃，可在「设置」里调大门控并发（workers）。")
	}
	if !dg.Drained {
		hints = append(hints, "待检队列仍有积压或在途检测：这一轮流量尚未跑完，等「积压 / 处理中」都归零才代表检测完毕。")
	}
	if !dg.CA.Exists {
		hints = append(hints, "根证书尚未生成：启动被动扫描会自动生成，也可先下载 /api/passive/ca 安装。")
	} else if dg.CA.DaysLeft <= 0 {
		hints = append(hints, "根证书已过期：删除证书目录后重启被动扫描，会生成新证书并需要重新信任。")
	}
	if dg.Counts.Error > 0 || dg.LastError != "" {
		hints = append(hints, "存在异常记录：见下方异常列表，按来源（proxy / engine / detector）定位。")
	}
	hints = append(hints, "HTTPS 站点必须先信任根证书：浏览器访问任意 https 站点，证书签发者显示 afrog 即表示生效。")

	if len(hints) > 6 {
		hints = hints[:6]
	}
	return hints
}
