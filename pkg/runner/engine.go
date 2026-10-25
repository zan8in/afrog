package runner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"strconv"

	"github.com/zan8in/afrog/v3/pkg/config"
	db2 "github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/fingerprint"
	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/portscan"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/report"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/targets"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/afrog/v3/pkg/webscan"
	"github.com/zan8in/gologger"
	"github.com/zan8in/oobadapter/pkg/oobadapter"
)

var CheckerPool = sync.Pool{
	New: func() any {
		return &Checker{
			Options: &config.Options{},
			// OriginalRequest: &http.Request{},
			VariableMap: make(map[string]any),
			Result:      &result.Result{},
			CustomLib:   NewCustomLib(),
		}
	},
}

var titleExtractRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func keyFromTargetWithPath(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if !strings.Contains(target, "://") {
		host, port, err := net.SplitHostPort(target)
		if err == nil && host != "" && port != "" {
			return net.JoinHostPort(host, port)
		}
		return ""
	}
	u, err := url.Parse(target)
	if err != nil || u == nil {
		return ""
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return ""
	}
	port := strings.TrimSpace(u.Port())
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return ""
		}
	}
	base := net.JoinHostPort(host, port)
	path := strings.TrimSpace(u.EscapedPath())
	path = strings.TrimRight(path, "/")
	if path == "" || path == "/" {
		return base
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

// openPortsCollector 汇总端口扫描阶段的开放端口与指纹结论。
//
// 开放端口用于把 host:port 追加为后续扫描目标；指纹结论（service/TLS/confidence）
// 供 webProbe 复用：既用于过滤掉已确认的非 Web 端口，也用于直接按 TLS 事实构造 URL。
type openPortsCollector struct {
	mu      sync.Mutex
	open    map[string][]int
	results map[string]*portscan.ScanResult
}

func newOpenPortsCollector() *openPortsCollector {
	return &openPortsCollector{
		open:    make(map[string][]int),
		results: make(map[string]*portscan.ScanResult),
	}
}

// Add 登记一个开放端口。
func (c *openPortsCollector) Add(host string, port int) {
	c.mu.Lock()
	c.open[host] = append(c.open[host], port)
	c.mu.Unlock()
}

// AddResult 登记一个端口的完整指纹结论，同时把它计入开放端口。
func (c *openPortsCollector) AddResult(r *portscan.ScanResult) {
	if r == nil {
		return
	}
	key := net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
	c.mu.Lock()
	c.open[r.Host] = append(c.open[r.Host], r.Port)
	if _, ok := c.results[key]; !ok {
		c.results[key] = r
	}
	c.mu.Unlock()
}

// Result 返回 host:port 的指纹结论，没有记录时返回 nil。
func (c *openPortsCollector) Result(host string, port int) *portscan.ScanResult {
	if c == nil {
		return nil
	}
	key := net.JoinHostPort(host, strconv.Itoa(port))
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.results[key]
}

// FactFor 按 host:port 取指纹结论；格式不对或没有结论（未开 -ps、端口由用户直接指定）时返回 nil。
func (c *openPortsCollector) FactFor(hostPort string) *portscan.ScanResult {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(hostPort))
	if err != nil {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil
	}
	return c.Result(host, port)
}

// maxFaviconBytes 是抓取 favicon 时接受的最大体积，超过则视为非 favicon 直接丢弃。
const maxFaviconBytes = 1 << 20

// webProbeMaxRedirects 是 Web 探测最多跟随的跳转次数，与浏览器口径一致。
const webProbeMaxRedirects = 10

// redirectTraceKey 用于把跳转落点收集器塞进探测请求的 context。
//
// http.Client 的 CheckRedirect 是「客户端级」回调，一次探测要拿到自己的跳转链，
// 只能靠 context 把收集器带进去，否则并发探测下几个目标的链会搅在一起。
type redirectTraceKey struct{}

// redirectTrace 收集一次探测里每一次跳转的落点（不含初始 URL）。
type redirectTrace struct {
	mu   sync.Mutex
	urls []string
}

func (t *redirectTrace) add(u string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.urls = append(t.urls, u)
	t.mu.Unlock()
}

func (t *redirectTrace) result() []string {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.urls) == 0 {
		return nil
	}
	return append([]string(nil), t.urls...)
}

// webProbeTimeout 返回 Web 探测的单次请求超时（-w-timeout，默认 30s）。
//
// 与全局 -timeout 解耦：-timeout 是给漏洞 PoC 留出的长超时（默认 50s），
// 信息收集阶段跟着等 50 秒只会让扫描在最前面就卡住。
// 30s 是实测标定值：真实站点尾部延迟常超过 10s（本次回归即因 10s 过紧而整批探测失败），
// 而 30s 已能覆盖抖动、又明显短于 PoC 的 50s。
func (runner *Runner) webProbeTimeout() time.Duration {
	secs := 30
	if runner != nil && runner.options != nil && runner.options.WebProbeTimeout > 0 {
		secs = runner.options.WebProbeTimeout
	}
	return time.Duration(secs) * time.Second
}

// newWebProbeClient 构造 Web 探测专用的 HTTP 客户端。
//
// 不复用 PoC 扫描的 retryhttpclient：那里的重定向与 TLS 握手都封在 retryablehttp
// 连接池内部，拿不到跳转链与证书，而「站是谁签的、跳到了哪」恰恰是信息收集的产出。
// 自建客户端还让探测阶段拥有独立短超时，且一次请求就能带齐这三样，请求数仍是 1。
func newWebProbeClient(options *config.Options, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		// 扫描器语义：证书是否可信交给使用者判断，这里先把证书取回来。
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	if options != nil {
		if p := strings.TrimSpace(strings.Split(options.Proxy, ",")[0]); p != "" {
			if u, err := url.Parse(p); err == nil && u.Host != "" {
				transport.Proxy = http.ProxyURL(u)
			}
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if trace, ok := req.Context().Value(redirectTraceKey{}).(*redirectTrace); ok {
				trace.add(req.URL.String())
			}
			if len(via) >= webProbeMaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// applyWebProbeHeaders 把 CLI 的 -H 自定义头与默认 UA 加到探测请求上，
// 使探测请求的外发特征与 PoC 请求一致（否则 WAF 按 UA 就把探测挡了）。
func applyWebProbeHeaders(req *http.Request, options *config.Options) {
	if req == nil {
		return
	}
	if options != nil {
		for _, line := range options.Header {
			key, val, ok := strings.Cut(line, ":")
			key = strings.TrimSpace(key)
			if !ok || key == "" {
				continue
			}
			if strings.EqualFold(key, "Host") {
				req.Host = strings.TrimSpace(val)
				continue
			}
			req.Header.Set(key, strings.TrimSpace(val))
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", utils.RandomUA())
	}
}

// tlsInfoFromState 从一次 TLS 握手结果里提取证书摘要，没有证书时返回 nil。
func tlsInfoFromState(state *tls.ConnectionState) *TLSInfo {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil
	}
	leaf := state.PeerCertificates[0]
	subject := strings.TrimSpace(leaf.Subject.CommonName)
	if subject == "" {
		subject = leaf.Subject.String()
	}
	// 签发者取组织名（Let's Encrypt、DigiCert Inc…）比取 CN 更贴近「谁签的」这个问题。
	issuer := ""
	if len(leaf.Issuer.Organization) > 0 {
		issuer = strings.TrimSpace(leaf.Issuer.Organization[0])
	}
	if issuer == "" {
		issuer = strings.TrimSpace(leaf.Issuer.CommonName)
	}
	if issuer == "" {
		issuer = leaf.Issuer.String()
	}
	return &TLSInfo{
		Subject:  subject,
		Issuer:   issuer,
		NotAfter: leaf.NotAfter.Format("2006-01-02"),
		DNSNames: append([]string(nil), leaf.DNSNames...),
	}
}

// webProbeBodyLimit 返回探测时读取响应体的上限（字节），与 PoC 请求同口径。
func webProbeBodyLimit(options *config.Options) int64 {
	mb := 2
	if options != nil && options.MaxRespBodySize > 0 {
		mb = options.MaxRespBodySize
	}
	return int64(mb) << 20
}

// applyWebFingerprint 把 Web 指纹匹配结果写入探测元数据。
//
// Fingerprint 是给人与前端看的一行摘要：优先用识别出的技术栈，无命中时回落到
// Server 与 X-Powered-By 响应头，保证老行为不丢。
func applyWebFingerprint(meta *WebMeta, res webscan.Result) {
	if meta == nil {
		return
	}
	if len(res.Technologies) > 0 {
		meta.Technologies = make([]WebTech, 0, len(res.Technologies))
		for _, t := range res.Technologies {
			meta.Technologies = append(meta.Technologies, WebTech{
				Name:       t.Name,
				Version:    t.Version,
				Category:   t.Category,
				CPE:        t.CPE,
				Confidence: t.Confidence.String(),
				RuleID:     t.RuleID,
			})
		}
		meta.Confidence = res.Confidence.String()
	}
	// WAF/CDN 单独外露：它不属于站点自身的技术栈，混进指纹摘要会把
	// 「站点用什么」和「前面挡了什么」两件事搅在一起。cdn 与 waf 同属前置层，
	// 一并归到这里，否则 Cloudflare/Akamai 这类最常见的拦截层会漏掉。
	for _, t := range meta.Technologies {
		if !isFrontLayerCategory(t.Category) {
			continue
		}
		if name := strings.Join(strings.Fields(t.Name+" "+t.Version), " "); name != "" {
			meta.WAF = name
			break
		}
	}
	meta.FaviconHash = strings.TrimSpace(res.FaviconHash)
	fingerprint := webTechSummary(meta.Technologies)
	if fingerprint == "" {
		fingerprint = joinNonEmpty(meta.Server, meta.PoweredBy)
	}
	meta.Fingerprint = fingerprint
}

// webTechSummary 把识别出的技术栈渲染成一行摘要，如 "PHP 8.1, ThinkPHP 6.0"。
//
// WAF/CDN 不计入摘要：它们属于站点前面的拦截层，已经由 WAF 字段单独外露，
// 混进来只会让同一行里出现两遍 Cloudflare 之类的重复。
func webTechSummary(techs []WebTech) string {
	parts := make([]string, 0, len(techs))
	for _, t := range techs {
		name := strings.TrimSpace(t.Name)
		if name == "" || isFrontLayerCategory(t.Category) {
			continue
		}
		if v := strings.TrimSpace(t.Version); v != "" {
			name += " " + v
		}
		parts = append(parts, name)
	}
	return strings.Join(parts, ", ")
}

// webTechNames 返回识别出的技术名（不含 WAF/CDN），供报告做分布汇总。
// 与 webTechSummary 的区别：这里只要名字，不带版本、不做拼接。
func webTechNames(techs []WebTech) []string {
	names := make([]string, 0, len(techs))
	for _, t := range techs {
		if name := strings.TrimSpace(t.Name); name != "" && !isFrontLayerCategory(t.Category) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	return names
}

// isFrontLayerCategory 判断分类是否属于「站点前面的拦截层」（WAF/CDN）。
func isFrontLayerCategory(category string) bool {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "waf", "cdn":
		return true
	}
	return false
}

// webAssetSummary 把一批 Web 资产压成一行汇总，回答「这批目标整体是什么」。
//
// 单个结果行回答的是「这个 URL 是什么」；当目标是网段时，真正有价值的往往是分布：
// 多少个站挂在同一款中间件后面、多少站前面有 WAF/CDN、证书都是谁签的。
func webAssetSummary(metas []WebMeta) string {
	if len(metas) == 0 {
		return ""
	}
	servers := make(map[string]int, 4)
	wafs := make(map[string]int, 2)
	issuers := make(map[string]int, 2)
	https := 0
	for _, m := range metas {
		if p := serverProduct(m.Server); p != "" {
			servers[p]++
		}
		if w := strings.TrimSpace(m.WAF); w != "" {
			wafs[w]++
		}
		if m.TLS != nil {
			https++
			if iss := strings.TrimSpace(m.TLS.Issuer); iss != "" {
				issuers[iss]++
			}
		}
	}

	parts := make([]string, 0, 5)
	parts = append(parts, fmt.Sprintf("assets=%d", len(metas)))
	if https > 0 {
		parts = append(parts, fmt.Sprintf("https=%d", https))
	}
	if s := formatCounts(servers, webAssetSummaryTop); s != "" {
		parts = append(parts, "server: "+s)
	}
	if s := formatCounts(wafs, webAssetSummaryTop); s != "" {
		parts = append(parts, "waf: "+s)
	}
	if s := formatCounts(issuers, webAssetSummaryTop); s != "" {
		parts = append(parts, "tls: "+s)
	}
	return strings.Join(parts, " ")
}

// webAssetSummaryTop 限制汇总里每一类最多列出多少项，避免网段扫描时刷屏。
const webAssetSummaryTop = 3

// serverProduct 从 Server 响应头里取出产品名（去掉版本号），用于聚合分组。
// "nginx/1.25.3 (CentOS)" → "nginx"。
func serverProduct(server string) string {
	server = strings.ToLower(strings.TrimSpace(server))
	if server == "" {
		return ""
	}
	if i := strings.IndexAny(server, "/ "); i > 0 {
		server = server[:i]
	}
	return strings.TrimSpace(server)
}

// formatCounts 把计数表渲染成 "name(3), name(2)"：按次数降序、同次数按名称升序，
// 最多取 limit 项；limit <= 0 表示不限。
func formatCounts(counts map[string]int, limit int) string {
	if len(counts) == 0 {
		return ""
	}
	type entry struct {
		name  string
		count int
	}
	items := make([]entry, 0, len(counts))
	for name, count := range counts {
		items = append(items, entry{name: name, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].name < items[j].name
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	rendered := make([]string, 0, len(items))
	for _, it := range items {
		rendered = append(rendered, fmt.Sprintf("%s(%d)", it.name, it.count))
	}
	return strings.Join(rendered, ", ")
}

// webConfidenceLabel 把内部可信度枚举渲染成与端口结果行同一套词。
// 内部枚举（certain/probable）是给程序看的，直接打给用户属于黑话。
func webConfidenceLabel(confidence string) string {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "certain":
		return "verified"
	case "probable":
		return "likely"
	}
	return ""
}

// headerCoveredByTech 判断响应头里的产品是否已经出现在技术栈摘要中，
// 避免 `[Apache httpd 2.4.6] [server: Apache/2.4.6 (CentOS)]` 这类同义重复。
// 只比较产品名（斜杠/空格前的第一段），并忽略大小写与版本写法差异。
func headerCoveredByTech(techSummary, header string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return false
	}
	token := header
	if i := strings.IndexAny(token, "/ "); i > 0 {
		token = token[:i]
	}
	return strings.Contains(strings.ToLower(techSummary), strings.ToLower(token))
}

// webProbeScheme 依据端口指纹结论决定候选是否值得做 Web 探测，以及应采用的协议。
//
// 返回 ok 为 false 表示指纹已明确判定该端口不是 Web 服务，应跳过 HTTP 探测；
// scheme 为空表示没有可用指纹，调用方需要退回协议试探。
func webProbeScheme(fact *portscan.ScanResult) (scheme string, ok bool) {
	if fact == nil {
		return "", true
	}
	if fact.TLS {
		return "https", true
	}
	if fact.Service != "" && !portscan.IsWebService(fact.Service) {
		return "", false
	}
	return "http", true
}

// webProbeCandidateURL 在不发任何网络请求的前提下算出候选的最终 URL。
// 端口指纹给了 scheme、或用户直接写了带协议的 URL 时能算出来；裸主机名要先做协议
// 试探才知道是 http 还是 https，这时返回空串表示「暂时算不出来」。
func webProbeCandidateURL(raw, scheme string) string {
	raw = strings.TrimSpace(raw)
	switch {
	case scheme != "":
		return scheme + "://" + raw
	case strings.Contains(raw, "://"):
		return raw
	}
	return ""
}

// webProbeResumeKey 在不发包的前提下算出候选的断点 key；算不出来时返回空串。
//
// 能提前算出的有两种：
//   - 端口指纹给了 scheme，或用户直接写了带协议的 URL：最终 URL 就是它；
//   - 裸 host:port：最终 key 只取决于端口（协议是 http 还是 https 都归一成
//     host:port），所以不必先做协议试探。
//
// 只有裸主机名返回空——它的最终 key 落在 host:80 还是 host:443 取决于协议试探，
// 只能等工作协程拿到 URL 后再判。
func webProbeResumeKey(raw, scheme string) string {
	if u := webProbeCandidateURL(raw, scheme); u != "" {
		return fingerprint.KeyFromTarget(u)
	}
	return keyFromTargetWithPath(raw)
}

// webProbeSkipByPrior 用内置端口先验挡掉惯例上确定不是 Web 的端口（如 22/3306/6379，
// 以及 465/993/995 这类「TLS 但非 Web」的服务），避免默认开启 -w 后对这些端口盲发
// HTTP 请求。
//
// 只有「端口先验里登记了服务名且该服务不是 Web」才跳过：未登记的端口一律照试，
// 因为 Web 服务完全可能挂在任意端口上，先验只说明惯例、不构成事实。调用方在拿不到
// 指纹结论、或指纹的 TLS 标记会掩盖「非 Web」事实时，都可以用它做最后的把关。
func webProbeSkipByPrior(hostPort string) bool {
	_, portStr, err := net.SplitHostPort(strings.TrimSpace(hostPort))
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	service := portscan.PriorPortService(port)
	if service == "" {
		return false
	}
	return !portscan.IsWebService(service)
}

// webTargetAllowed 报告一个 host:port 是否值得交给 HTTP PoC 去打。
//
// 判据与 webProbe 的候选过滤完全同源，避免「探测阶段认定不是 Web、扫描阶段照样发 HTTP 请求」
// 这种口径漂移：指纹明确判定非 Web 服务时否掉；指纹缺失或 TLS 标记掩盖了「非 Web」事实时，
// 再用端口先验把 22/3306/6379 以及 465/993/995 这类服务挡掉。
//
// 唯一例外是指纹已正面判定为 Web 服务——Web 可能挂在任意端口上，先验只说明惯例。
// 既无指纹又无先验的端口一律放行。
func webTargetAllowed(hostPort string, fact *portscan.ScanResult) bool {
	if _, ok := webProbeScheme(fact); !ok {
		return false
	}
	if webProbeSkipByPrior(hostPort) && (fact == nil || !portscan.IsWebService(fact.Service)) {
		return false
	}
	return true
}

// toPortScanInfo 把 portscan 的识别结果转换成 config 层结构，供回调与事件流使用。
func toPortScanInfo(r *portscan.ScanResult) config.PortScanInfo {
	return config.PortScanInfo{
		Host:       r.Host,
		Port:       r.Port,
		State:      r.State.String(),
		Service:    r.Service,
		Product:    r.Product,
		Version:    r.Version,
		Device:     r.Device,
		Hostname:   r.Hostname,
		OS:         r.OS,
		CPE:        r.CPE,
		Info:       r.Info,
		TLS:        r.TLS,
		Confidence: r.Confidence.String(),
		Banner:     r.Banner,
		Extras:     r.Extras,
	}
}

// formatPortResult 渲染一行端口结果：`序号 [open] host:port  [service] [tls] [verified]`。
// 与 Web / 漏洞结果行共用同一套语法：序号 + 徽标 + 目标 + 方括号属性。
// 徽标取端口实际状态（open / closed / filtered），默认只有 open，开启 -ps-states 后
// 才有 closed / filtered 行。
func formatPortResult(r *portscan.ScanResult, seq int) string {
	// net.JoinHostPort 保证 IPv6 写成 [::1]:80，而不是拼接出无法解析的 ::1:80。
	target := net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
	attrs := make([]string, 0, 4)
	// 识别出的服务名是这一行的「主值」，用绿色强调；其余属性保持暗灰。
	if svc := strings.Join(strings.Fields(r.Service+" "+r.Product+" "+r.Version), " "); svc != "" {
		attrs = append(attrs, log.LogColor.Vulner(svc))
	}
	if r.TLS {
		attrs = append(attrs, log.Dim("tls"))
	}
	// 内部可信度枚举对用户不可读：verified/likely 才有意义，
	// 「仅端口开放未识别服务」与 unknown 属无信息状态，直接省略（避免出现 (port) 这类黑话）。
	switch r.Confidence {
	case portscan.ConfidenceCertain:
		attrs = append(attrs, log.Dim("verified"))
	case portscan.ConfidenceProbable:
		attrs = append(attrs, log.Dim("likely"))
	}
	return log.ResNum(seq, log.KindBadge(r.State.String()), target, attrs...)
}

func extractTitle(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	m := titleExtractRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	t := strings.TrimSpace(string(m[1]))
	if t == "" {
		return ""
	}
	// 部分站点把标题写成 HTML 实体（如 &#x4E2D;&#x7164;），浏览器会解码，这里同样解码后再归一化空白
	t = html.UnescapeString(t)
	t = strings.Join(strings.Fields(t), " ")
	return t
}

// installHostBreakerReporter 把 HTTP 熔断提示接到 CLI 输出上。
//
// 熔断会让一部分目标「不再被扫」，这必须显式可见：否则用户只看到速率变快，却不知道
// 有一批目标被跳过了。与端口扫描的拥塞告警同一口径——只在 -debug 下打一行，且先清掉
// 进度条残留；其余模式一律静默，避免污染结果行与 -json-stream。
func (runner *Runner) installHostBreakerReporter() {
	if runner == nil || runner.options == nil || !runner.options.Debug {
		retryhttpclient.SetHostBreakerReporter(nil)
		return
	}
	retryhttpclient.SetHostBreakerReporter(func(host string, until time.Time, failures int) {
		if runner.options.Silent {
			return
		}
		runner.clearProgressLine()
		gologger.Print().Msgf("%s", log.Op(log.LevelWarn, utils.StageVulnScan,
			"unreachable",
			host,
			fmt.Sprintf("failures=%d", failures),
			"cooldown="+time.Until(until).Truncate(time.Second).String(),
		))
	})
}

// installAutoReqLimitReporter 把自适应单目标限速的调整接到 CLI 输出上。
//
// 与熔断同理：限速被调低意味着扫描会变慢，用户有权知道原因。只在 -debug 下打一行，
// 恢复时用 [INF] 提示一次方向翻转。
func (runner *Runner) installAutoReqLimitReporter() {
	if runner == nil || runner.options == nil || !runner.options.Debug {
		retryhttpclient.SetAutoReqLimitReporter(nil)
		return
	}
	retryhttpclient.SetAutoReqLimitReporter(func(ev retryhttpclient.AutoReqLimitEvent) {
		if runner.options.Silent {
			return
		}
		attrs := []string{
			fmt.Sprintf("%d->%d", ev.OldRate, ev.NewRate),
			"fail=" + strconv.Itoa(ev.FailPct) + "%",
			"latency=" + ev.Latency.Truncate(time.Millisecond).String(),
			"baseline=" + ev.Baseline.Truncate(time.Millisecond).String(),
		}
		if ev.QueueWait > 0 {
			attrs = append(attrs, "queue="+ev.QueueWait.Truncate(time.Millisecond).String())
		}
		level, action := log.LevelWarn, "req-limit-down"
		if ev.Recovered {
			level, action = log.LevelInfo, "req-limit-up"
		} else {
			attrs = append(attrs, "reason="+ev.Reason)
		}
		runner.clearProgressLine()
		gologger.Print().Msgf("%s", log.Op(level, utils.StageVulnScan, append([]string{action}, attrs...)...))
	})
}

// clearProgressLine 在输出阶段日志/结果行之前清掉进度条所在行。
// 这些输出与进度条都写 stderr，不清行时两者会拼接在同一行上。
// -silent 下不渲染任何进度条，清行序列也就没有意义：旧终端会把 \033[2K
// 这类转义渲染成乱码，反而把结果行搅乱，所以此时直接跳过。
func (runner *Runner) clearProgressLine() {
	if runner == nil || runner.options == nil || runner.options.Silent {
		return
	}
	fmt.Fprint(os.Stderr, "\r\033[2K\r")
}

// webProbe 探测存活 Web 服务并返回可用的 URL 列表。
//
// facts 是端口扫描阶段的指纹结论（可为 nil，如未开启 -ps）：命中时用它跳过
// 已确认的非 Web 端口，并按 TLS 事实直接构造 http(s):// URL，省去协议试探请求。
func (runner *Runner) webProbe(ctx context.Context, idx *targets.TargetIndex, facts *openPortsCollector) []string {
	if runner == nil || idx == nil || runner.options == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	} else if ctx.Err() != nil {
		return nil
	}

	// matcher 是 Web 指纹引擎，加载失败只降级为「不识别技术栈」，不影响探测本身。
	matcher, err := webscan.LoadMatcher(runner.options.WebFingerprintDir)
	if err != nil {
		matcher = webscan.NewMatcher(nil)
		if !runner.options.Silent {
			gologger.Print().Msgf("%s", log.Op(log.LevelWarn, utils.StageWebProbe,
				"fingerprint rules unavailable", err.Error(), "tech detection disabled"))
		}
	}

	type candidate struct {
		raw string
		// scheme 非空表示协议已由端口指纹确定，无需再做协议试探。
		scheme string
		fact   *portscan.ScanResult
	}

	seen := make(map[string]struct{})
	candidates := make([]candidate, 0, len(idx.URLs)+len(idx.HostPorts)+len(idx.Hosts))
	add := func(raw, scheme string, fact *portscan.ScanResult) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		key := scheme + "\x00" + raw
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		candidates = append(candidates, candidate{raw: raw, scheme: scheme, fact: fact})
	}
	// 用户显式给出的 URL 自带协议，保持原样。
	for _, u := range idx.URLs {
		add(u, "", nil)
	}
	for _, hp := range idx.HostPorts {
		fact := facts.FactFor(hp)
		scheme, ok := webProbeScheme(fact)
		if !ok {
			continue
		}
		// 端口惯例上确定不是 Web 的候选要挡掉，避免误发 HTTP 请求。除开「没有端口
		// 扫描结论」的情形，这里还覆盖了 465/993/995 这类「TLS 但非 Web」的服务：
		// smtps/imaps/pop3s 的 tls:true 会让 webProbeScheme 提前判成 https，从而换来
		// 一堆 malformed HTTP status code 噪音。
		// 唯一的例外是指纹已正面判定为 Web 服务——Web 可能挂在任意端口上，先验只说明惯例。
		if webProbeSkipByPrior(hp) && (fact == nil || !portscan.IsWebService(fact.Service)) {
			continue
		}
		add(hp, scheme, fact)
	}
	// 裸主机名没有端口信息，无法与指纹结论关联，仍走协议试探。
	for _, h := range idx.Hosts {
		add(h, "", nil)
	}
	if len(candidates) == 0 {
		return nil
	}

	// 断点续传：上一轮已经探测出结论的目标直接复用结论，不再重复发包。
	// 结论必须整体灌回引擎（而非只记「探测过了」），否则 requires 门控会因指纹丢失
	// 把整批依赖指纹的 PoC 误跳过——那比重新探测一遍更糟。
	var resumed map[string]WebMeta
	if runner.ScanProgress != nil {
		resumed = runner.ScanProgress.ResumedWebProbes()
	}
	if len(resumed) > 0 {
		kept := candidates[:0]
		for _, c := range candidates {
			// 只有「不试探就能算出断点 key」的候选才能在这里预先剔除；
			// 裸主机名要走协议试探才知道最终 URL，留给工作协程在拿到 URL 后再判。
			if k := webProbeResumeKey(c.raw, c.scheme); k != "" {
				if _, ok := resumed[k]; ok {
					continue
				}
			}
			kept = append(kept, c)
		}
		candidates = kept
	}

	totalCandidates := len(candidates)
	var processed uint64
	var lastPercent int32 = -1
	webStart := time.Now()
	// 阶段边界行（started/completed）默认不打印：进度条已经标出当前阶段，
	// 这些行在常规输出里只是噪音；-debug 时恢复，便于对齐排查。
	if runner.options.Debug && !runner.options.SDKMode && !runner.options.Silent {
		runner.clearProgressLine()
		gologger.Print().Msgf("%s", log.Op(log.LevelInfo, utils.StageWebProbe, "started", fmt.Sprintf("candidates=%d", totalCandidates)))
	}
	if runner.options.OnPhaseProgress != nil {
		runner.options.OnPhaseProgress("webprobe", "running", 0, int64(totalCandidates), 0)
	}

	rate := runner.options.RateLimit
	if rate <= 0 {
		rate = 1
	}
	con := runner.options.Concurrency
	if con <= 0 {
		con = 1
	}

	interval := time.Second / time.Duration(rate)
	if interval <= 0 {
		// Web 探测默认开启后这条路径必然被执行：极高的限速会让 time.Second/rate
		// 截断为 0，而 time.NewTicker 在非正区间上会 panic。
		interval = time.Nanosecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	tasks := make(chan candidate, con*4)
	var wg sync.WaitGroup

	var mu sync.Mutex
	webURLs := make([]string, 0)
	webURLByKey := make(map[string]string)
	webMetaByKey := make(map[string]WebMeta)

	// 续传结论先灌进结果集：它们没有经过本轮 record()，但报告、资产汇总与 requires
	// 门控都必须看到它们。不重复打印存活行——上一轮已经打过，恢复时再刷一遍只是噪音。
	if len(resumed) > 0 {
		keys := make([]string, 0, len(resumed))
		for k := range resumed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			meta := resumed[k]
			if strings.TrimSpace(meta.URL) == "" {
				continue
			}
			webURLByKey[k] = meta.URL
			webMetaByKey[k] = meta
			webURLs = append(webURLs, meta.URL)
			runner.options.Targets.SetNum(meta.URL, ActiveTarget)
		}
	}

	record := func(urlStr string, meta WebMeta) {
		key := fingerprint.KeyFromTarget(urlStr)
		if key == "" {
			return
		}
		if runner.options != nil {
			runner.options.Targets.SetNum(urlStr, ActiveTarget)
		}
		mu.Lock()
		if _, ok := webURLByKey[key]; ok {
			mu.Unlock()
			return
		}
		webURLByKey[key] = urlStr
		webMetaByKey[key] = meta
		webURLs = append(webURLs, urlStr)
		mu.Unlock()
		// 本轮探测结论写回断点进度，供中断后 -resume 直接复用（含指纹与 WAF）。
		if runner.ScanProgress != nil {
			runner.ScanProgress.RecordWebProbe(key, meta)
		}
		if runner.OnWebProbe != nil {
			runner.OnWebProbe(meta)
		}
		// -silent 只表示「只要结果、不要装饰」，Web 存活行本身就是结果，
		// 与端口/漏洞结果行同一口径：照常打印（颜色已由 -silent 全局关掉）。
		if runner.options != nil && !runner.options.SDKMode {
			// 目标 URL 放最前：用户扫视时以目标为锚点，状态码只是它的属性，
			// 与漏洞结果行 `poc-id SEVERITY target` 的「主体在前」口径一致。
			// 不带编号：编号在并发探测下顺序并不稳定，端口/漏洞结果行也统一去掉了它。
			//
			// 技术栈、Server、X-Powered-By 三者并列输出：早先把它们合并进一个
			// Fingerprint 字段，命中 ThinkPHP 这类框架后 Apache 与 PHP 版本就被挤没了，
			// 而这几个字段恰恰是信息收集阶段最该一眼看到的东西。
			attrs := make([]string, 0, 9)
			if meta.Status > 0 {
				attrs = append(attrs, log.LogColor.StatusCode(meta.Status))
			}
			// 标题是 Web 资产最有用的一条事实，用浅蓝强调；缺失时降级为暗灰占位。
			if t := strings.TrimSpace(meta.Title); t != "" {
				attrs = append(attrs, log.LogColor.Title(utils.Str2UTF8(t)))
			} else {
				attrs = append(attrs, log.Dim("(no title)"))
			}
			techSummary := webTechSummary(meta.Technologies)
			if techSummary != "" {
				if label := webConfidenceLabel(meta.Confidence); label != "" {
					techSummary += " " + label
				}
				attrs = append(attrs, log.Dim(utils.Str2UTF8(techSummary)))
			}
			// 原始响应头只在指纹没认出来时才补打：认出来时再打一遍只是同义重复，
			// 而一旦没认出来，这两行往往就是用户判断「这是什么服务」的唯一线索。
			// WAF 名也算已覆盖：Cloudflare 已经由 waf 属性说清楚了。
			coveredBy := joinNonEmpty(techSummary, meta.WAF)
			if s := strings.TrimSpace(meta.Server); s != "" && !headerCoveredByTech(coveredBy, s) {
				attrs = append(attrs, log.Dim("server: "+utils.Str2UTF8(s)))
			}
			if p := strings.TrimSpace(meta.PoweredBy); p != "" && !headerCoveredByTech(coveredBy, p) {
				attrs = append(attrs, log.Dim("x-powered-by: "+utils.Str2UTF8(p)))
			}
			// WAF/CDN 与站点自身技术栈是两件事：前面挡了什么，直接影响后续能打成什么。
			if w := strings.TrimSpace(meta.WAF); w != "" {
				attrs = append(attrs, log.Dim("waf: "+utils.Str2UTF8(w)))
			}
			// 跳转链与最终落点：用户填的目标可能只是入口，真实站点在别处。
			if len(meta.Redirects) > 0 {
				chain := strings.Join(meta.Redirects, " → ")
				attrs = append(attrs, log.Dim("→ "+utils.Str2UTF8(chain)))
			}
			// 证书摘要回答「站是谁签的、什么时候过期」，是 https 目标的基础事实。
			if meta.TLS != nil {
				desc := strings.TrimSpace(meta.TLS.Subject)
				if iss := strings.TrimSpace(meta.TLS.Issuer); iss != "" {
					desc = joinNonEmpty(desc, iss)
				}
				if exp := strings.TrimSpace(meta.TLS.NotAfter); exp != "" {
					desc = joinNonEmpty(desc, "expires "+exp)
				}
				if desc != "" {
					attrs = append(attrs, log.Dim("tls: "+utils.Str2UTF8(desc)))
				}
			}
			// favicon 哈希是按图定位同一套站的稳定标识，抓到了就外露（未抓取时为空）。
			if h := strings.TrimSpace(meta.FaviconHash); h != "" {
				attrs = append(attrs, log.Dim("favicon: "+h))
			}

			// 结果行必须和端口扫描结果走同一条 stderr 通道：直写 stdout 时，只收 stderr 的
			// 终端里完全看不到这些行，而 -json-stream 的 stdout 只允许承载 NDJSON。
			// 打印前先清掉进度条所在行，否则结果行会与进度条互相覆盖。
			runner.clearProgressLine()
			gologger.Print().Msgf("%s", log.ResNum(int(atomic.AddUint32(&runner.webSeq, 1)), log.KindBadge("web"), urlStr, attrs...))
		}
	}

	// probeClient 是探测阶段的专用客户端：它决定了这一阶段的超时（-w-timeout）
	// 与「一次请求带齐状态码/标题/跳转链/TLS 证书」的能力。
	probeClient := newWebProbeClient(runner.options, runner.webProbeTimeout())
	bodyLimit := webProbeBodyLimit(runner.options)

	// webProbeFetch 是一次探测的网络层产出，供指纹匹配与元数据组装共用。
	type webProbeFetch struct {
		status  int
		headers map[string]string
		body    []byte
	}

	// fetchResponse 请求一次目标，拿到状态码、响应头、正文、跳转链与证书。
	// 返回 nil 表示服务端没有响应（用于判定存活）。
	fetchResponse := func(urlStr string) (WebMeta, *webProbeFetch) {
		meta := WebMeta{URL: urlStr}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
		if err != nil {
			return meta, nil
		}
		trace := &redirectTrace{}
		req = req.WithContext(context.WithValue(req.Context(), redirectTraceKey{}, trace))
		applyWebProbeHeaders(req, runner.options)

		resp, err := probeClient.Do(req)
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			return meta, nil
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))

		headers := make(map[string]string, len(resp.Header))
		for k, v := range resp.Header {
			headers[strings.ToLower(k)] = strings.Join(v, ";")
		}

		meta.Status = resp.StatusCode
		meta.Server = strings.TrimSpace(resp.Header.Get("Server"))
		meta.PoweredBy = strings.TrimSpace(resp.Header.Get("X-Powered-By"))
		meta.Title = extractTitle(body)
		meta.Redirects = trace.result()
		meta.TLS = tlsInfoFromState(resp.TLS)
		return meta, &webProbeFetch{status: resp.StatusCode, headers: headers, body: body}
	}

	// fetchFavicon 额外抓取 /favicon.ico，仅在调用方判定需要时调用（-w-favicon 或外置
	// 规则集含 favicon 规则）。
	fetchFavicon := func(urlStr string) []byte {
		u, err := url.Parse(urlStr)
		if err != nil {
			return nil
		}
		u.Path = "/favicon.ico"
		u.RawQuery = ""
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil
		}
		applyWebProbeHeaders(req, runner.options)
		resp, err := probeClient.Do(req)
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			return nil
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxFaviconBytes+1))
		if len(body) == 0 || len(body) > maxFaviconBytes {
			return nil
		}
		return body
	}

	for i := 0; i < con; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-runner.ctx.Done():
					return
				case <-ctx.Done():
					return
				case it, ok := <-tasks:
					if !ok {
						return
					}
					d := atomic.AddUint64(&processed, 1)
					if runner.options.OnPhaseProgress != nil && totalCandidates > 0 {
						percent := int(d * 100 / uint64(totalCandidates))
						if percent > 100 {
							percent = 100
						}
						if int32(percent) != atomic.LoadInt32(&lastPercent) {
							atomic.StoreInt32(&lastPercent, int32(percent))
							runner.options.OnPhaseProgress("webprobe", "running", int64(d), int64(totalCandidates), percent)
						}
					}
					select {
					case <-runner.ctx.Done():
						return
					case <-ctx.Done():
						return
					case <-ticker.C:
					}
					var u string
					switch {
					case it.scheme != "":
						// 端口指纹已给出 TLS 事实，直接构造 URL，省去一次协议试探。
						u = it.scheme + "://" + it.raw
					case strings.Contains(it.raw, "://"):
						// 用户显式给出的 URL 自带协议，无需再试探。
						u = it.raw
					default:
						resolved, err := retryhttpclient.CheckProtocol(it.raw)
						if err != nil || strings.TrimSpace(resolved) == "" {
							continue
						}
						u = resolved
					}
					// 裸主机名的候选预先剔除不掉（试探完才知道 URL），在这里补判一次。
					if len(resumed) > 0 {
						if k := webProbeResumeKey(u, ""); k != "" {
							if _, ok := resumed[k]; ok {
								continue
							}
						}
					}
					meta, fetched := fetchResponse(u)
					if fetched == nil {
						continue
					}
					if strings.TrimSpace(meta.Server) == "" && it.fact != nil {
						// HTTP 响应没有 Server 头时，回落到端口指纹识别的产品与版本。
						meta.Server = strings.Join(strings.Fields(it.fact.Product+" "+it.fact.Version), " ")
					}
					webfp := webscan.Response{
						StatusCode: fetched.status,
						Headers:    fetched.headers,
						Body:       fetched.body,
					}
					// 抓 favicon 会多一次请求，因此默认不抓：只有显式开启 -w-favicon，或外置
					// 规则集里写了 favicon 规则（用户意图明显）时才抓。
					if runner.options.WebFavicon || matcher.HasFavicon() {
						webfp.Favicon = fetchFavicon(u)
					}
					applyWebFingerprint(&meta, matcher.Match(webfp))
					record(u, meta)
				}
			}
		}()
	}

	// 取消后必须停止投递：select 里的 break 只跳出 select 本身，因此这里用标签跳出整个循环，
	// 否则取消后仍会继续往 tasks 里塞任务（虽然消费方已退出，只会做无用功）。
dispatch:
	for _, c := range candidates {
		if runner.ctx.Err() != nil || (ctx != nil && ctx.Err() != nil) {
			break
		}
		select {
		case <-runner.ctx.Done():
			break dispatch
		case <-ctx.Done():
			break dispatch
		case tasks <- c:
		}
	}
	close(tasks)
	wg.Wait()
	done := atomic.LoadUint64(&processed)
	status := "completed"
	if ctx != nil && ctx.Err() != nil {
		status = "interrupted"
	} else if runner.ctx != nil && runner.ctx.Err() != nil {
		status = "interrupted"
	} else if int(done) != totalCandidates {
		status = "interrupted"
	}
	if runner.options.OnPhaseProgress != nil {
		percent := 0
		if totalCandidates > 0 {
			percent = int(done * 100 / uint64(totalCandidates))
			if percent > 100 {
				percent = 100
			}
		}
		if status == "completed" && totalCandidates > 0 {
			percent = 100
		}
		runner.options.OnPhaseProgress("webprobe", status, int64(done), int64(totalCandidates), percent)
	}
	if runner.options.Debug && !runner.options.SDKMode && !runner.options.Silent {
		runner.clearProgressLine()
		gologger.Print().Msgf("%s", log.Op(log.LevelInfo, utils.StageWebProbe,
			status,
			fmt.Sprintf("probed %d/%d", done, totalCandidates),
			fmt.Sprintf("alive %d", len(webURLs)),
			time.Since(webStart).Truncate(time.Second).String(),
		))
	}

	// 资产聚合汇总：单个结果行回答「这个 URL 是什么」，汇总行回答「这批目标整体是什么」。
	// 与 vuln-scan 的收尾汇总同一口径，属于默认可见的总结行；中断时也打印，
	// 让用户在拿到半份结果的同时知道已经摸清了哪些资产。
	if !runner.options.SDKMode && !runner.options.Silent {
		probed := make([]WebMeta, 0, len(webMetaByKey))
		for _, u := range webURLs {
			if meta, ok := webMetaByKey[fingerprint.KeyFromTarget(u)]; ok {
				probed = append(probed, meta)
			}
		}
		if summary := webAssetSummary(probed); summary != "" {
			runner.clearProgressLine()
			gologger.Print().Msgf("%s", log.Op(log.LevelInfo, utils.StageWebProbe, summary))
		}
	}

	runner.webMu.Lock()
	for k, v := range webURLByKey {
		runner.webURLByKey[k] = v
	}
	for k, v := range webMetaByKey {
		runner.webMetaByKey[k] = v
	}
	runner.webMu.Unlock()

	return webURLs
}

func (c *openPortsCollector) Snapshot() map[string][]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make(map[string][]int, len(c.open))
	for host, ports := range c.open {
		cp[host] = append([]int(nil), ports...)
	}
	return cp
}

// shouldSkipRequires 判断目标是否因 requires 门控而跳过。
//
// fingerRequiresByKey 是「该目标命中的指纹标识集合」，同时包含指纹 PoC 的 tag 与 id，
// 因此 requires: [mysql]（tag）与 requires: [ajp-protocol-detect]（指纹 PoC id）都能命中。
func shouldSkipRequires(target string, p poc.Poc, keyForTarget func(string) string, fingerRequiresByKey map[string]map[string]struct{}, testMode bool) bool {
	if testMode {
		return false
	}
	if len(p.Info.Requires) == 0 {
		return false
	}
	reqSet := make(map[string]struct{}, len(p.Info.Requires))
	for _, r := range p.Info.Requires {
		rr := strings.ToLower(strings.TrimSpace(r))
		if rr == "" {
			continue
		}
		reqSet[rr] = struct{}{}
	}
	if len(reqSet) == 0 {
		return false
	}

	mode := strings.ToLower(strings.TrimSpace(p.Info.RequiresMode))
	if mode == "" {
		mode = "strict"
	}
	if mode != "strict" && mode != "opportunistic" {
		mode = "strict"
	}

	if len(fingerRequiresByKey) == 0 {
		return mode == "strict"
	}

	key := ""
	if keyForTarget != nil {
		key = keyForTarget(target)
	}
	if key == "" {
		return mode == "strict"
	}

	tts := fingerRequiresByKey[key]
	if len(tts) == 0 {
		return mode == "strict"
	}
	for r := range reqSet {
		if _, ok := tts[r]; ok {
			return false
		}
	}
	return true
}

// webTechRequires 把 -w 阶段识别出的 Web 技术栈翻译成 requires 词表。
//
// requires 原本只能命中「指纹 PoC 的 tag/id」，粒度受限于指纹 PoC；接入 Web 指纹后，
// requires: [wordpress] / [thinkphp] / [apache-shiro] 这类写法可直接命中响应里识别出的
// 技术栈，从而跳过明显不可能命中的 PoC。
//
// targets 是本次扫描真正会跑的目标列表，metas 是 webProbe 的原始结果（键为去掉路径的
// host:port）。这里按 host:port 反查，使带路径的目标也能用上其站点级指纹；键仍取
// keyFromTargetWithPath，保证与 shouldSkipRequires 的查表口径一致。
func webTechRequires(targets []string, metas map[string]WebMeta) map[string]map[string]struct{} {
	if len(targets) == 0 || len(metas) == 0 {
		return nil
	}
	techsByKey := make(map[string][]WebTech, len(metas))
	for k, meta := range metas {
		if len(meta.Technologies) > 0 {
			techsByKey[k] = meta.Technologies
		}
	}
	if len(techsByKey) == 0 {
		return nil
	}
	out := make(map[string]map[string]struct{})
	for _, t := range targets {
		techs, ok := techsByKey[fingerprint.KeyFromTarget(t)]
		if !ok {
			continue
		}
		key := keyFromTargetWithPath(t)
		if key == "" {
			continue
		}
		set := out[key]
		if set == nil {
			set = make(map[string]struct{}, len(techs)*3)
			out[key] = set
		}
		for _, tech := range techs {
			for _, tok := range webscan.MatchTokens(tech.RuleID, tech.Name, tech.Category) {
				set[tok] = struct{}{}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func shouldSkipFingerprintFilteredByMode(mode string, globalFingerTags map[string]struct{}, targetTags map[string]struct{}, pocTags map[string]struct{}) bool {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "strict"
	}
	if mode != "strict" && mode != "opportunistic" {
		mode = "strict"
	}
	if len(globalFingerTags) == 0 || len(pocTags) == 0 {
		return false
	}
	appSpecific := false
	for t := range pocTags {
		if _, ok := globalFingerTags[t]; ok {
			appSpecific = true
			break
		}
	}
	if !appSpecific {
		return false
	}
	if len(targetTags) == 0 {
		return mode == "strict"
	}
	for t := range pocTags {
		if _, ok := targetTags[t]; ok {
			return false
		}
	}
	return true
}

func (e *Engine) AcquireChecker() *Checker {
	c := CheckerPool.Get().(*Checker)
	c.Options = e.options
	c.Result.Output = e.options.Output
	c.OOBAdapter = e.oobAdapter
	c.OOBAlive = e.oobAlive
	c.OOBMgr = e.OOBMgr()
	if c.CustomLib != nil {
		c.CustomLib.SetOOBManager(e.OOBMgr())
	}
	return c
}

func (e *Engine) ReleaseChecker(c *Checker) {
	// *c.OriginalRequest = http.Request{}
	c.VariableMap = make(map[string]any)
	c.Result = &result.Result{}
	c.CustomLib = NewCustomLib()
	c.OOBAdapter = nil
	c.OOBAlive = false
	c.OOBMgr = nil
	CheckerPool.Put(c)
}

type Engine struct {
	options *config.Options
	// ticker paces task scheduling. It is created per stage and stopped from
	// Stop, which runs on a different goroutine, so access must be atomic.
	ticker        atomic.Pointer[time.Ticker]
	mu            sync.Mutex
	paused        uint32
	stopped       uint32
	quit          chan struct{}
	activeTasks   int64
	queuedTasks   int64
	startedTasks  uint32
	slowLogged    uint32
	pedmMu        sync.Mutex
	pedmStatsByID map[string]*pedmStat
	pedmPairByID  map[string]*pedmStat
	pedmActiveMu  sync.Mutex
	pedmActive    map[uint64]*pedmActiveTask
	pedmTaskSeq   uint64
	pedmStop      chan struct{}
	oobAdapter    *oobadapter.OOBAdapter
	oobAlive      bool
	// oobMgr is swapped between scans and read lock-free from the scan hot
	// path, so it must be an atomic pointer rather than a plain field.
	oobMgr atomic.Pointer[OOBManager]
}

// setTicker installs the scheduling ticker, stopping any previous one.
func (e *Engine) setTicker(t *time.Ticker) {
	if old := e.ticker.Swap(t); old != nil {
		old.Stop()
	}
}

// stopTicker stops and clears the scheduling ticker. It is safe to call when
// no ticker is installed and safe to call concurrently.
func (e *Engine) stopTicker() {
	if old := e.ticker.Swap(nil); old != nil {
		old.Stop()
	}
}

// OOBMgr returns the active out-of-band manager, or nil when OOB is inactive.
func (e *Engine) OOBMgr() *OOBManager {
	if e == nil {
		return nil
	}
	return e.oobMgr.Load()
}

// setOOBManager installs a manager, stopping any previous one so its poll
// goroutine cannot outlive the swap.
func (e *Engine) setOOBManager(m *OOBManager) {
	if e == nil {
		return
	}
	if old := e.oobMgr.Swap(m); old != nil {
		old.Stop()
	}
}

func NewEngine(options *config.Options) *Engine {
	engine := &Engine{
		options:       options,
		quit:          make(chan struct{}),
		pedmStatsByID: make(map[string]*pedmStat),
		pedmPairByID:  make(map[string]*pedmStat),
		pedmActive:    make(map[uint64]*pedmActiveTask),
	}
	return engine
}

type pedmStat struct {
	mu    sync.Mutex
	count uint64
	total time.Duration
	max   time.Duration
}

type pedmEntry struct {
	id     string
	target string
	pocID  string
	count  uint64
	total  time.Duration
	max    time.Duration
}

type pedmActiveTask struct {
	stage     string
	pocID     string
	target    string
	startedAt time.Time
	nextLogAt time.Time
}

type pedmActiveSnapshot struct {
	Active  int
	Queued  int
	Slow    int
	Longest time.Duration
	PocID   string
	Target  string
}

func (e *Engine) pedmReset() {
	atomic.StoreUint32(&e.startedTasks, 0)
	atomic.StoreUint32(&e.slowLogged, 0)
	e.pedmStopMonitor()
	e.pedmMu.Lock()
	e.pedmStatsByID = make(map[string]*pedmStat)
	e.pedmPairByID = make(map[string]*pedmStat)
	e.pedmMu.Unlock()
	e.pedmActiveMu.Lock()
	e.pedmActive = make(map[uint64]*pedmActiveTask)
	e.pedmActiveMu.Unlock()
}

func (e *Engine) pedmRecord(pocID string, dur time.Duration) {
	if e == nil {
		return
	}
	pocID = strings.TrimSpace(pocID)
	if pocID == "" {
		return
	}

	e.pedmMu.Lock()
	s := e.pedmEnsureStat(e.pedmStatsByID, pocID)
	e.pedmMu.Unlock()

	e.pedmApplyDuration(s, dur)
}

func (e *Engine) pedmRecordPair(target, pocID string, dur time.Duration) {
	if e == nil {
		return
	}
	key := pedmPairKey(target, pocID)
	if key == "" {
		return
	}

	e.pedmMu.Lock()
	s := e.pedmEnsureStat(e.pedmPairByID, key)
	e.pedmMu.Unlock()

	e.pedmApplyDuration(s, dur)
}

func (e *Engine) pedmEnsureStat(store map[string]*pedmStat, key string) *pedmStat {
	s := store[key]
	if s == nil {
		s = &pedmStat{}
		store[key] = s
	}
	return s
}

func (e *Engine) pedmApplyDuration(s *pedmStat, dur time.Duration) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.count++
	s.total += dur
	if dur > s.max {
		s.max = dur
	}
	s.mu.Unlock()
}

func (e *Engine) pedmMaybeLogSlow(options *config.Options, stage, pocID, target string, dur time.Duration) {
	if e == nil || options == nil {
		return
	}
	if options.PedmSlowThresholdSec <= 0 {
		return
	}
	if options.PedmSlowLogLimit <= 0 {
		return
	}
	threshold := time.Duration(options.PedmSlowThresholdSec) * time.Second
	if dur < threshold {
		return
	}
	if atomic.AddUint32(&e.slowLogged, 1) > uint32(options.PedmSlowLogLimit) {
		return
	}
	e.pedmLog(options, fmt.Sprintf("PEDM-SLOW | completed | stage=%s dur=%s poc=%s target=%s", stage, dur.String(), pocID, target))
}

func (e *Engine) pedmSummary(options *config.Options) {
	if e == nil || options == nil {
		return
	}
	if options.PedmSummaryTop <= 0 {
		return
	}

	e.pedmMu.Lock()
	entries := e.pedmCollectEntries(e.pedmStatsByID, false)
	pairEntries := e.pedmCollectEntries(e.pedmPairByID, true)
	e.pedmMu.Unlock()

	if len(entries) == 0 && len(pairEntries) == 0 {
		return
	}

	by := strings.ToLower(strings.TrimSpace(options.PedmSummaryBy))
	if by != "avg" && by != "max" {
		by = "max"
	}

	top := options.PedmSummaryTop
	if len(entries) > 0 {
		e.pedmSortEntries(entries, by)
		e.pedmPrintSummary("poc", top, by, entries)
	}
	if len(pairEntries) > 0 {
		e.pedmSortEntries(pairEntries, by)
		e.pedmPrintSummary("target+poc", top, by, pairEntries)
	}
}

func (e *Engine) pedmCollectEntries(store map[string]*pedmStat, splitPair bool) []pedmEntry {
	entries := make([]pedmEntry, 0, len(store))
	for id, s := range store {
		if s == nil {
			continue
		}
		s.mu.Lock()
		c := s.count
		t := s.total
		m := s.max
		s.mu.Unlock()
		if c == 0 {
			continue
		}
		entry := pedmEntry{id: id, count: c, total: t, max: m}
		if splitPair {
			entry.target, entry.pocID = pedmSplitPairKey(id)
		} else {
			entry.pocID = id
		}
		entries = append(entries, entry)
	}
	return entries
}

func (e *Engine) pedmSortEntries(entries []pedmEntry, by string) {
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		ai := e.pedmMetric(a, by)
		aj := e.pedmMetric(b, by)
		if ai != aj {
			return ai > aj
		}
		if a.pocID != b.pocID {
			return a.pocID < b.pocID
		}
		return a.target < b.target
	})
}

func (e *Engine) pedmMetric(entry pedmEntry, by string) time.Duration {
	if by == "avg" && entry.count > 0 {
		return entry.total / time.Duration(entry.count)
	}
	return entry.max
}

func (e *Engine) pedmPrintSummary(scope string, top int, by string, entries []pedmEntry) {
	if len(entries) == 0 {
		return
	}
	if top > len(entries) {
		top = len(entries)
	}
	if top <= 0 {
		return
	}

	e.pedmLog(e.options, fmt.Sprintf("PEDM-SUMMARY | scope=%s by=%s top=%d", scope, by, top))
	for i := 0; i < top; i++ {
		it := entries[i]
		avg := it.total / time.Duration(it.count)
		if scope == "target+poc" {
			e.pedmLog(e.options, fmt.Sprintf("PEDM #%d | target=%s | poc=%s | count=%d avg=%s max=%s", i+1, it.target, it.pocID, it.count, avg.String(), it.max.String()))
			continue
		}
		e.pedmLog(e.options, fmt.Sprintf("PEDM #%d | poc=%s | count=%d avg=%s max=%s", i+1, it.pocID, it.count, avg.String(), it.max.String()))
	}
}

func (e *Engine) pedmLog(options *config.Options, line string) {
	if strings.TrimSpace(line) == "" {
		return
	}
	if options != nil && options.OnPedmLog != nil {
		options.OnPedmLog(line)
		return
	}
	gologger.Print().Msg(log.LogColor.Time(line))
}

func pedmPairKey(target, pocID string) string {
	target = strings.TrimSpace(target)
	pocID = strings.TrimSpace(pocID)
	if target == "" || pocID == "" {
		return ""
	}
	return target + "\x00" + pocID
}

func pedmSplitPairKey(v string) (string, string) {
	parts := strings.SplitN(v, "\x00", 2)
	if len(parts) != 2 {
		return "", strings.TrimSpace(v)
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func (e *Engine) pedmStartMonitor(options *config.Options) {
	if e == nil || options == nil || !options.PocExecutionDurationMonitor || options.PedmSlowThresholdSec <= 0 {
		return
	}

	stop := make(chan struct{})
	e.pedmActiveMu.Lock()
	if e.pedmStop != nil {
		close(e.pedmStop)
	}
	e.pedmStop = stop
	e.pedmActiveMu.Unlock()

	threshold := time.Duration(options.PedmSlowThresholdSec) * time.Second
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
			}

			now := time.Now()
			logs := make([]string, 0)

			e.pedmActiveMu.Lock()
			activeCount := len(e.pedmActive)
			for _, task := range e.pedmActive {
				if task == nil || task.startedAt.IsZero() {
					continue
				}
				elapsed := now.Sub(task.startedAt)
				if elapsed < threshold {
					continue
				}
				if !task.nextLogAt.IsZero() && now.Before(task.nextLogAt) {
					continue
				}
				task.nextLogAt = now.Add(1 * time.Minute)
				logs = append(logs, fmt.Sprintf("PEDM-SLOW | running | stage=%s dur=%s active=%d poc=%s target=%s", task.stage, elapsed.Truncate(time.Second).String(), activeCount, task.pocID, task.target))
			}
			e.pedmActiveMu.Unlock()

			for _, line := range logs {
				e.pedmLog(options, line)
			}
		}
	}()
}

func (e *Engine) pedmStopMonitor() {
	if e == nil {
		return
	}
	e.pedmActiveMu.Lock()
	stop := e.pedmStop
	e.pedmStop = nil
	e.pedmActiveMu.Unlock()
	if stop != nil {
		close(stop)
	}
}

func (e *Engine) pedmStartTask(stage, pocID, target string) uint64 {
	if e == nil {
		return 0
	}
	taskID := atomic.AddUint64(&e.pedmTaskSeq, 1)
	e.pedmActiveMu.Lock()
	e.pedmActive[taskID] = &pedmActiveTask{
		stage:     strings.TrimSpace(stage),
		pocID:     strings.TrimSpace(pocID),
		target:    strings.TrimSpace(target),
		startedAt: time.Now(),
	}
	e.pedmActiveMu.Unlock()
	return taskID
}

func (e *Engine) pedmDoneTask(taskID uint64) {
	if e == nil || taskID == 0 {
		return
	}
	e.pedmActiveMu.Lock()
	delete(e.pedmActive, taskID)
	e.pedmActiveMu.Unlock()
}

func (e *Engine) pedmSnapshot(options *config.Options) pedmActiveSnapshot {
	if e == nil {
		return pedmActiveSnapshot{}
	}
	threshold := time.Duration(0)
	if options != nil && options.PedmSlowThresholdSec > 0 {
		threshold = time.Duration(options.PedmSlowThresholdSec) * time.Second
	}

	now := time.Now()
	snap := pedmActiveSnapshot{}
	snap.Queued = int(atomic.LoadInt64(&e.queuedTasks))
	e.pedmActiveMu.Lock()
	snap.Active = len(e.pedmActive)
	for _, task := range e.pedmActive {
		if task == nil || task.startedAt.IsZero() {
			continue
		}
		elapsed := now.Sub(task.startedAt)
		if threshold > 0 && elapsed >= threshold {
			snap.Slow++
		}
		if elapsed > snap.Longest {
			snap.Longest = elapsed
			snap.PocID = task.pocID
			snap.Target = task.target
		}
	}
	e.pedmActiveMu.Unlock()
	return snap
}

func (e *Engine) taskHardTimeout(taskPoc *poc.Poc) time.Duration {
	if e == nil || e.options == nil {
		return 0
	}
	fixedFallbackSec := 0
	if e.options.TaskHardTimeoutSec > 0 {
		fixedFallbackSec = e.options.TaskHardTimeoutSec
	}
	if e.options.TaskSmartTimeout {
		return poc.TaskTimeoutDuration(taskPoc, fixedFallbackSec)
	}
	if fixedFallbackSec <= 0 {
		return 0
	}
	return time.Duration(fixedFallbackSec) * time.Second
}

func (e *Engine) taskTimeoutLog(stage, pocID, target string, dur, limit time.Duration) {
	if e == nil || e.options == nil || !e.options.PocExecutionDurationMonitor {
		return
	}
	if dur <= 0 {
		dur = limit
	}
	e.pedmLog(e.options, fmt.Sprintf("TASK-TIMEOUT | stage=%s elapsed=%s limit=%s poc=%s target=%s", stage, dur.Truncate(time.Second).String(), limit.String(), pocID, target))
}

func (runner *Runner) Execute() {

	options := runner.options
	if runner.engine != nil {
		runner.engine.pedmReset()
		defer runner.engine.pedmStopMonitor()
		if options.PocExecutionDurationMonitor {
			runner.engine.pedmStartMonitor(options)
		}
	}
	if runner.engine != nil {
		// Stop any manager left over from a previous run before dropping the
		// reference, otherwise its poll goroutine would leak.
		runner.engine.stopOOBManager()
		runner.engine.oobAdapter = nil
		runner.engine.oobAlive = false
	}

	pocSlice := options.CreatePocList()
	fingerprintPocs, pocSlice := options.FingerprintPoCs(pocSlice)

	reversePocs, otherPocs := options.ReversePoCs(pocSlice)

	// fmt.Println(len(reversePocs), len(otherPocs), len(pocSlice))
	// 如果无 OOB PoC 将跳过 OOB 存活检测
	// 在SDK模式下，只有明确启用OOB时才进行连接检测
	if len(reversePocs) > 0 {
		// 检查是否是SDK模式且未启用OOB
		if options.SDKMode && !options.EnableOOB {
			if runner.engine != nil {
				runner.engine.oobAdapter = nil
				runner.engine.oobAlive = false
			}
		} else {
			// 非SDK模式或已启用OOB，执行正常的连接检测
			runner.options.SetOOBAdapter()
			if oobAdapter, err := oobadapter.NewOOBAdapter(options.OOB, &oobadapter.ConnectorParams{
				Key:     options.OOBKey,
				Domain:  options.OOBDomain,
				HTTPUrl: options.OOBHttpUrl,
				ApiUrl:  options.OOBApiUrl,
			}); err == nil {
				if runner.engine != nil {
					runner.engine.oobAdapter = oobAdapter
					runner.engine.oobAlive = oobAdapter.IsVaild()
				}
			} else {
				if runner.engine != nil {
					runner.engine.oobAdapter = nil
					runner.engine.oobAlive = false
				}
			}
		}
		// if !OOBAlive {
		// 	gologger.Error().Msg("Using OOB Server: " + options.OOB + " is not vaild")
		// }
	}

	if runner.engine != nil && runner.engine.oobAlive && runner.engine.oobAdapter != nil {
		pollInterval := time.Duration(options.OOBPollInterval) * time.Second
		hitRetention := time.Duration(options.OOBHitRetention) * time.Minute
		runner.engine.setOOBManager(NewOOBManager(runner.ctx, runner.engine.oobAdapter, pollInterval, hitRetention))
		// The poll loop must not outlive the scan. Without this the goroutine
		// survives every completed scan, because runner.ctx is only cancelled
		// by an explicit Stop.
		defer runner.engine.stopOOBManager()
	}
	runner.startOOBResolver()
	defer runner.stopOOBResolver()

	runner.printOOBStatus(reversePocs)

	// javascript PoC 加载汇总放在启动横幅之后打印，避免插进 Core/POC/Cur/OOB 这一组中间。
	options.PrintJSReport()

	// portFacts 汇总端口扫描阶段的指纹结论，供后续 webProbe 复用，避免重复探测。
	var portFacts *openPortsCollector

	// portscan pre-scan: run after OOB status output to ensure ordering
	if options.PortScan {
		origTargets := runner.options.Targets.List()
		origSeen := make(map[string]struct{}, len(origTargets))
		for _, t := range origTargets {
			if s, ok := t.(string); ok && s != "" {
				origSeen[s] = struct{}{}
			}
		}

		var idx *targets.TargetIndex
		if runner.TargetIndex != nil {
			idx = runner.TargetIndex
		} else {
			seeds := make([]string, 0, runner.options.Targets.Len())
			for _, t := range runner.options.Targets.List() {
				if s, ok := t.(string); ok {
					s = strings.TrimSpace(s)
					if s != "" {
						seeds = append(seeds, s)
					}
				}
			}
			idx = targets.BuildTargetIndex(seeds)
			runner.TargetIndex = idx
		}

		hosts := idx.PreScanTargets()
		if len(hosts) > 0 {
			psOpts := portscan.DefaultOptions()
			psOpts.Targets = hosts
			// CLI 端只保留 main.go 那一条统一进度条（由 OnPhaseProgress 驱动），
			// 所以关掉 portscan 自带的进度条与调试输出，避免两条进度条抢同一行。
			psOpts.Debug = false
			psOpts.LiveStats = false
			// 阶段边界行（host-disc / port-scan started、端口排名版本）默认静默，只有 -debug 时才让 portscan 打印。
			psOpts.StageLog = options.Debug
			// Quiet 表达「只要结果、不要过程」：-silent 与 SDK 场景下，端口扫描不再输出收尾汇总
			// 与丢包/封禁告警。常规终端保持 false，让收尾汇总与 web-probe / vuln-scan 一致地出现。
			psOpts.Quiet = options.SDKMode || options.Silent
			if options.OnPhaseProgress != nil {
				psOpts.OnProgress = func(phase string, status string, finished int, total int, percent int) {
					options.OnPhaseProgress(phase, status, int64(finished), int64(total), percent)
				}
			}
			if options.OnHostDiscovered != nil {
				psOpts.OnDiscoveredHost = func(host string) {
					options.OnHostDiscovered(host)
				}
			}
			if options.PSPorts != "" {
				psOpts.Ports = options.PSPorts
			}
			// Do not override module logging flags here
			if options.PSRateLimit > 0 {
				psOpts.RateLimit = options.PSRateLimit
			}
			// 连接速率上限与并发上限是两个正交维度：并发管「同时多少条连接」，
			// 速率管「每秒新开多少条连接」。0 表示不限速（-pcps 0 / -aggressive）。
			psOpts.ConnectRateLimit = options.PSCPS
			psOpts.ConnectRateLimitPerHost = options.PSCPSHost
			psOpts.LinkProbe = options.PSLinkProbe
			if options.PSTimeout > 0 {
				psOpts.Timeout = time.Duration(options.PSTimeout) * time.Millisecond
			}
			// 判定用 >= 0：0 是合法值（关闭重试），也是 CLI 与 SDK 的默认值。
			if options.PSRetries >= 0 {
				psOpts.Retries = options.PSRetries
			}
			if options.PSSkipDiscovery {
				psOpts.SkipDiscovery = true
			}
			if options.PSS4Chunk != 0 {
				psOpts.S4ChunkSize = options.PSS4Chunk
			}
			if options.PSHostConcurrency > 0 {
				psOpts.MaxHostConcurrency = options.PSHostConcurrency
			}
			if options.PSNoAdaptiveTimeout {
				psOpts.AdaptiveTimeout = false
			}
			psOpts.ServiceProbes = options.PSServiceProbe
			psOpts.FingerprintDir = options.PSFingerprintDir
			psOpts.ReportStates = options.PSReportStates
			collector := newOpenPortsCollector()
			portFacts = collector
			psOpts.OnResult = func(r *portscan.ScanResult) {
				if options.OnPortScanResult != nil {
					options.OnPortScanResult(toPortScanInfo(r))
				}
				if !options.SDKMode {
					// 与 Web/漏洞结果行统一：序号只回答「本阶段累积了多少条」，
					// 不表示先后（并发命中时到达顺序本就随机）。
					// 打印前先清掉进度条所在行，避免结果行与进度条互相覆盖。
					runner.clearProgressLine()
					gologger.Print().Msgf("%s", formatPortResult(r, int(atomic.AddUint32(&runner.portSeq, 1))))
				}
				// 只有开放端口才进入后续扫描目标与 webProbe 的指纹复用集合。
				// closed / filtered 行（-ps-states）只描述状态，若一并收集会把关不上的
				// 端口当成资产追加为扫描目标。
				if r.State == portscan.PortStateOpen {
					collector.AddResult(r)
				}
			}
			if sc, err := portscan.NewScanner(psOpts); err == nil {
				baseCtx := runner.ctx
				if baseCtx == nil {
					baseCtx = context.Background()
				}
				_ = sc.Scan(baseCtx)
				newTargets := make([]string, 0)
				for host, ports := range collector.Snapshot() {
					seenPort := make(map[int]struct{})
					for _, p := range ports {
						if _, ok := seenPort[p]; ok {
							continue
						}
						seenPort[p] = struct{}{}
						newTargets = append(newTargets, net.JoinHostPort(host, strconv.Itoa(p)))
					}
				}
				if len(newTargets) > 0 {
					for _, nt := range newTargets {
						if _, ok := origSeen[nt]; ok {
							continue
						}
						origSeen[nt] = struct{}{}
						options.Targets.Append(nt)
						if runner.TargetIndex != nil {
							runner.TargetIndex.Add(nt)
						}
					}
				}
			}
		} else if options.Debug && !options.SDKMode {
			gologger.Print().Msgf("%s", log.Op(log.LevelInfo, utils.StageHostDiscovery, "skipped", "no valid hosts"))
			gologger.Print().Msgf("%s", log.Op(log.LevelInfo, utils.StagePortScan, "skipped", "no valid hosts"))
		} else if options.OnPhaseProgress != nil {
			options.OnPhaseProgress("host_discovery", "skipped", 0, 0, 0)
			options.OnPhaseProgress("portscan", "skipped", 0, 0, 0)
		}
	} else if options.Debug && !options.SDKMode {
		gologger.Print().Msgf("%s", log.Op(log.LevelInfo, utils.StageHostDiscovery, "skipped", "-ps not enabled"))
		gologger.Print().Msgf("%s", log.Op(log.LevelInfo, utils.StagePortScan, "skipped", "-ps not enabled"))
	} else if options.OnPhaseProgress != nil {
		options.OnPhaseProgress("host_discovery", "skipped", 0, 0, 0)
		options.OnPhaseProgress("portscan", "skipped", 0, 0, 0)
	}

	allTargets := make([]string, 0, runner.options.Targets.Len())
	for _, t := range runner.options.Targets.List() {
		s, ok := t.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		allTargets = append(allTargets, s)
	}

	idx := runner.TargetIndex

	if idx == nil {
		idx = targets.BuildTargetIndex(allTargets)
		runner.TargetIndex = idx
	}
	baseCtx := runner.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	netTargetsStrict := append([]string(nil), idx.HostPorts...)
	var webTargets []string
	if options.EnableWebProbe {
		webTargets = runner.webProbe(baseCtx, idx, portFacts)
	}
	if !runner.options.SDKMode {
		webMetas := make([]WebMeta, 0, len(webTargets))
		runner.webMu.Lock()
		for _, u := range webTargets {
			key := fingerprint.KeyFromTarget(u)
			if key == "" {
				continue
			}
			meta, ok := runner.webMetaByKey[key]
			if !ok {
				continue
			}
			if strings.TrimSpace(meta.URL) == "" {
				meta.URL = u
			}
			webMetas = append(webMetas, meta)
		}
		runner.webMu.Unlock()
		if len(webMetas) > 0 {
			_, _ = sqlite.InsertWebProbeSummary(db2.TaskID, "webprobe", "webprobe", "webprobe", "webprobe", webMetas)
			if runner.Report != nil {
				entries := make([]report.WebProbeEntry, 0, len(webMetas))
				for i, meta := range webMetas {
					urlStr := strings.TrimSpace(meta.URL)
					if urlStr == "" {
						continue
					}
					number := utils.GetNumberText(i + 1)
					entry := report.WebProbeEntry{
						Number: number,
						URL:    urlStr,
						Title:  strings.TrimSpace(meta.Title),
						// Fingerprint 只放技术栈摘要，不回落 Server/X-Powered-By：
						// 后两者在报告里各占一个徽标，回落会造成同义重复。
						Fingerprint:  webTechSummary(meta.Technologies),
						Confidence:   strings.TrimSpace(meta.Confidence),
						Technologies: webTechNames(meta.Technologies),
						Server:       strings.TrimSpace(meta.Server),
						PoweredBy:    strings.TrimSpace(meta.PoweredBy),
						Redirects:    meta.Redirects,
						FaviconHash:  strings.TrimSpace(meta.FaviconHash),
						WAF:          strings.TrimSpace(meta.WAF),
					}
					if meta.TLS != nil {
						entry.TLS = &report.WebProbeTLS{
							Subject:  meta.TLS.Subject,
							Issuer:   meta.TLS.Issuer,
							NotAfter: meta.TLS.NotAfter,
						}
					}
					entries = append(entries, entry)
				}
				_ = runner.Report.AppendWebProbeEntries(entries)
			}
		}
	}
	mergeTargets := func(parts ...[]string) []string {
		seen := make(map[string]struct{})
		out := make([]string, 0)
		for _, p := range parts {
			for _, t := range p {
				t = strings.TrimSpace(t)
				if t == "" {
					continue
				}
				if _, ok := seen[t]; ok {
					continue
				}
				seen[t] = struct{}{}
				out = append(out, t)
			}
		}
		return out
	}
	resolvedHosts := make([]string, 0, len(idx.Hosts))
	runner.webMu.Lock()
	for _, h := range idx.Hosts {
		key := fingerprint.KeyFromTarget(h)
		if key != "" {
			if u := strings.TrimSpace(runner.webURLByKey[key]); u != "" {
				resolvedHosts = append(resolvedHosts, u)
				continue
			}
		}
		resolvedHosts = append(resolvedHosts, h)
	}
	runner.webMu.Unlock()

	keyForWebDedup := func(target string) string {
		target = strings.TrimSpace(target)
		if target == "" {
			return ""
		}
		if strings.Contains(target, "://") {
			return keyFromTargetWithPath(target)
		}
		host, port, err := net.SplitHostPort(target)
		if err == nil && host != "" && port != "" {
			return net.JoinHostPort(host, port)
		}
		return ""
	}

	dedupWebTargets := func(in []string) []string {
		bestByKey := make(map[string]string)
		keysInOrder := make([]string, 0, len(in))
		out := make([]string, 0, len(in))
		seenLoose := make(map[string]struct{})
		for _, raw := range in {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			key := keyForWebDedup(raw)
			if key == "" {
				if _, ok := seenLoose[raw]; ok {
					continue
				}
				seenLoose[raw] = struct{}{}
				out = append(out, raw)
				continue
			}
			if prev, ok := bestByKey[key]; ok {
				prevIsURL := strings.Contains(prev, "://")
				rawIsURL := strings.Contains(raw, "://")
				if !prevIsURL && rawIsURL {
					bestByKey[key] = raw
				}
				continue
			}
			bestByKey[key] = raw
			keysInOrder = append(keysInOrder, key)
		}
		for _, k := range keysInOrder {
			if v, ok := bestByKey[k]; ok {
				out = append(out, v)
			}
		}
		return out
	}

	// webHostPorts 是交给 HTTP PoC 的 host:port 候选，已按协议感知门控过滤。
	//
	// 端口扫描会把每个开放端口都变成独立目标，其中 22/3306/6379 这类端口永远不会回
	// HTTP：对它们跑全套 HTTP PoC，每个任务都要等到 -timeout × -retries 才失败，几个
	// 这样的目标就足以把整体速率压到个位数。指纹既然已经给出「不是 Web」的结论，就不该
	// 再让 HTTP PoC 去打——这与 webProbe 的候选过滤是同一把尺子。
	//
	// 关闭 -w 时不做任何过滤：此时没有 Web 探测结论，也不存在「探测与扫描口径不一致」
	// 的问题，保持旧行为，让 PoC 自己去所有端口上试协议。
	webHostPorts := idx.HostPorts
	skippedNonWeb := 0
	if options.EnableWebProbe {
		webHostPorts = make([]string, 0, len(idx.HostPorts))
		for _, hp := range idx.HostPorts {
			if !webTargetAllowed(hp, portFacts.FactFor(hp)) {
				skippedNonWeb++
				continue
			}
			webHostPorts = append(webHostPorts, hp)
		}
	}

	webScanTargets := dedupWebTargets(mergeTargets(idx.URLs, resolvedHosts, webTargets, webHostPorts))

	isNetOnlyPoc := func(p poc.Poc) bool {
		hasHTTP := false
		hasNet := false
		hasGo := false
		for _, rm := range p.Rules {
			t := strings.ToLower(strings.TrimSpace(rm.Value.Request.Type))
			switch t {
			case "", poc.HTTP_Type, poc.HTTPS_Type:
				hasHTTP = true
			case poc.TCP_Type, poc.UDP_Type, poc.SSL_Type, poc.JS_Type:
				hasNet = true
			case poc.GO_Type:
				hasGo = true
			default:
				hasHTTP = true
			}
		}
		if hasGo {
			return false
		}
		return hasNet && !hasHTTP
	}

	taskCount := 0
	if !options.DisableFingerprint && len(fingerprintPocs) > 0 {
		fingerNet := make([]poc.Poc, 0)
		fingerWeb := make([]poc.Poc, 0)
		for _, p := range fingerprintPocs {
			if isNetOnlyPoc(p) {
				fingerNet = append(fingerNet, p)
			} else {
				fingerWeb = append(fingerWeb, p)
			}
		}
		if len(fingerNet) > 0 {
			taskCount += len(fingerNet) * len(netTargetsStrict)
		}
		if len(fingerWeb) > 0 {
			taskCount += len(fingerWeb) * len(webScanTargets)
		}
	}
	for _, p := range pocSlice {
		if !isNetOnlyPoc(p) {
			taskCount += len(webScanTargets)
		} else {
			taskCount += len(netTargetsStrict)
		}
	}
	options.Count += taskCount
	if options.OnScanInfoUpdate != nil {
		pocTotal := len(pocSlice)
		if !options.DisableFingerprint && len(fingerprintPocs) > 0 {
			pocTotal += len(fingerprintPocs)
		}
		oobEnabled, oobStatus := runner.getOOBStatus(reversePocs)
		options.OnScanInfoUpdate(config.ScanInfoUpdate{
			TotalTargets: len(webScanTargets),
			Targets:      append([]string(nil), webScanTargets...),
			TotalPocs:    pocTotal,
			TotalScans:   options.Count,
			OOBEnabled:   oobEnabled,
			OOBStatus:    oobStatus,
		})
	}

	if options.Smart {
		options.SmartControl()
	}

	// 与 PORT-SCAN / WEB-PROBE 同一口径：阶段边界行仅在 -debug 时输出。
	if options.Debug && !options.SDKMode {
		pocTotal := len(pocSlice)
		if !options.DisableFingerprint && len(fingerprintPocs) > 0 {
			pocTotal += len(fingerprintPocs)
		}
		runner.clearProgressLine()
		gologger.Print().Msgf("%s", log.Op(log.LevelInfo, utils.StageVulnScan,
			"started",
			fmt.Sprintf("targets=%d", options.Targets.Len()),
			fmt.Sprintf("pocs=%d", pocTotal),
			fmt.Sprintf("tasks=%d", options.Count),
		))
		// 被门控挡掉的目标必须可追溯：否则用户看到「我的端口没被扫」却找不到原因。
		if skippedNonWeb > 0 {
			gologger.Print().Msgf("%s", log.Op(log.LevelInfo, utils.StageVulnScan,
				"gated",
				fmt.Sprintf("non-http-targets=%d", skippedNonWeb),
				"skipped http pocs",
			))
		}
	}

	if !options.DisableFingerprint && len(fingerprintPocs) > 0 {
		fingerNet := make([]poc.Poc, 0)
		fingerWeb := make([]poc.Poc, 0)
		for _, p := range fingerprintPocs {
			if isNetOnlyPoc(p) {
				fingerNet = append(fingerNet, p)
			} else {
				fingerWeb = append(fingerWeb, p)
			}
		}
		if len(fingerNet) > 0 && len(netTargetsStrict) > 0 {
			runner.runFingerprintStage(baseCtx, netTargetsStrict, fingerNet)
		}
		if len(fingerWeb) > 0 && len(webScanTargets) > 0 {
			runner.runFingerprintStage(baseCtx, webScanTargets, fingerWeb)
		}
	}

	normalizeTags := func(tags string, skipFingerprint bool) map[string]struct{} {
		tags = strings.TrimSpace(tags)
		if tags == "" {
			return nil
		}
		out := make(map[string]struct{})
		for _, t := range strings.Split(strings.ToLower(tags), ",") {
			tt := strings.TrimSpace(t)
			if tt == "" {
				continue
			}
			if skipFingerprint && tt == "fingerprint" {
				continue
			}
			out[tt] = struct{}{}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}

	keyForTarget := func(target string) string {
		return keyFromTargetWithPath(target)
	}

	// fingerTagsByKey 只放「指纹 tag」，供指纹过滤使用；
	// fingerRequiresByKey 额外并入指纹 PoC 的 id 与 -w 识别出的 Web 技术栈，供 requires
	// 匹配使用（作者既可能写 requires: [mysql]（tag），也可能写 requires: [ajp-protocol-detect]
	// （指纹 PoC id），还可能写 requires: [wordpress]（Web 指纹））。
	fingerTagsByKey := make(map[string]map[string]struct{})
	fingerRequiresByKey := make(map[string]map[string]struct{})
	globalFingerTags := make(map[string]struct{})
	{
		runner.fingerMu.Lock()
		fingerSnap := make(map[string][]fingerprint.Hit, len(runner.fingerByKey))
		for k, v := range runner.fingerByKey {
			if len(v) == 0 {
				continue
			}
			vv := make([]fingerprint.Hit, len(v))
			copy(vv, v)
			fingerSnap[k] = vv
		}
		runner.fingerMu.Unlock()

		for k, hits := range fingerSnap {
			tagSet := make(map[string]struct{})
			reqSet := make(map[string]struct{})
			for _, h := range hits {
				for t := range normalizeTags(h.Tags, true) {
					tagSet[t] = struct{}{}
					reqSet[t] = struct{}{}
				}
				if id := strings.ToLower(strings.TrimSpace(h.ID)); id != "" {
					reqSet[id] = struct{}{}
				}
			}
			if len(reqSet) == 0 {
				continue
			}
			fingerRequiresByKey[k] = reqSet
			if len(tagSet) == 0 {
				continue
			}
			fingerTagsByKey[k] = tagSet
			for t := range tagSet {
				globalFingerTags[t] = struct{}{}
			}
		}
	}

	// 把 -w 识别出的 Web 技术栈并入 requires 词表：Web 指纹比指纹 PoC 更能说清
	// 「这个站点是什么」，因此 requires: [wordpress] 这类门控才真正落地。
	if len(webScanTargets) > 0 {
		runner.webMu.Lock()
		webSnap := make(map[string]WebMeta, len(runner.webMetaByKey))
		for k, v := range runner.webMetaByKey {
			webSnap[k] = v
		}
		runner.webMu.Unlock()

		for k, set := range webTechRequires(webScanTargets, webSnap) {
			reqSet := fingerRequiresByKey[k]
			if reqSet == nil {
				reqSet = make(map[string]struct{}, len(set))
				fingerRequiresByKey[k] = reqSet
			}
			for tok := range set {
				reqSet[tok] = struct{}{}
			}
		}
	}

	pocTagsCache := make(map[string]map[string]struct{})
	shouldSkipFingerprintFiltered := func(target string, p poc.Poc) bool {
		if isNetOnlyPoc(p) {
			return false
		}
		if len(globalFingerTags) == 0 {
			return false
		}
		pt, ok := pocTagsCache[p.Id]
		if !ok {
			pt = normalizeTags(p.Info.Tags, true)
			pocTagsCache[p.Id] = pt
		}
		if len(pt) == 0 {
			return false
		}
		appSpecific := false
		for t := range pt {
			if _, ok := globalFingerTags[t]; ok {
				appSpecific = true
				break
			}
		}
		if !appSpecific {
			return false
		}
		key := keyForTarget(target)
		if key == "" {
			return false
		}
		tts := fingerTagsByKey[key]
		return shouldSkipFingerprintFilteredByMode(options.FingerprintFilterMode, globalFingerTags, tts, pt)
	}

	runStage := func(pocs []poc.Poc, rate, concurrency int) {
		if runner.engine == nil || atomic.LoadUint32(&runner.engine.stopped) != 0 || runner.options.VulnerabilityScannerBreakpoint {
			return
		}
		if rate <= 0 {
			rate = 1
		}
		if concurrency <= 0 {
			concurrency = 1
		}

		interval := time.Second / time.Duration(rate)
		if interval <= 0 {
			// time.NewTicker panics on a non-positive interval, which a very
			// high rate limit would otherwise produce.
			interval = time.Nanosecond
		}
		runner.engine.setTicker(time.NewTicker(interval))
		defer runner.engine.stopTicker()

		type stageTask struct {
			tap   *TransData
			pocID string
		}

		tasks := make(chan stageTask, concurrency*4)
		var workers sync.WaitGroup

		var counters sync.Map // map[string]*atomic.Int64
		getCounter := func(pocID string) *atomic.Int64 {
			if v, ok := counters.Load(pocID); ok {
				return v.(*atomic.Int64)
			}
			c := &atomic.Int64{}
			actual, _ := counters.LoadOrStore(pocID, c)
			return actual.(*atomic.Int64)
		}
		finish := func(pocID string) {
			v, ok := counters.Load(pocID)
			if !ok {
				return
			}
			if v.(*atomic.Int64).Add(-1) == 0 {
				runner.ScanProgress.MarkPocDone(pocID)
			}
		}

		for i := 0; i < concurrency; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for {
					select {
					case <-runner.engine.quit:
						return
					case <-runner.ctx.Done():
						return
					case task, ok := <-tasks:
						if !ok {
							return
						}
						atomic.AddInt64(&runner.engine.queuedTasks, -1)
						runner.engine.waitTick()
						if atomic.LoadUint32(&runner.engine.stopped) != 0 || runner.options.VulnerabilityScannerBreakpoint {
							finish(task.pocID)
							continue
						}
						runner.exec(task.tap)
						finish(task.pocID)
					}
				}
			}()
		}

		for _, pocItem := range pocs {
			if atomic.LoadUint32(&runner.engine.stopped) != 0 || runner.options.VulnerabilityScannerBreakpoint || runner.ctx.Err() != nil {
				break
			}
			targetView := webScanTargets
			if isNetOnlyPoc(pocItem) {
				targetView = netTargetsStrict
			}

			if len(runner.options.Resume) > 0 && runner.ScanProgress.Contains(pocItem.Id) {
				if runner.options.ResumeDoneTasks == 0 {
					for range targetView {
						runner.NotVulCallback()
					}
				}
				continue
			}

			scheduled := 0
			for _, t := range targetView {
				if atomic.LoadUint32(&runner.engine.stopped) != 0 || runner.options.VulnerabilityScannerBreakpoint || runner.ctx.Err() != nil {
					break
				}

				if len(runner.options.Resume) > 0 && runner.ScanProgress.ContainsTask(pocItem.Id, t) {
					if runner.options.ResumeDoneTasks == 0 {
						runner.NotVulCallback()
					}
					continue
				}

				if shouldSkipRequires(t, pocItem, keyForTarget, fingerRequiresByKey, runner.options.Test) {
					runner.ScanProgress.IncrementTask(pocItem.Id, t)
					runner.NotVulCallback()
					continue
				}

				if shouldSkipFingerprintFiltered(t, pocItem) {
					runner.ScanProgress.IncrementTask(pocItem.Id, t)
					runner.NotVulCallback()
					continue
				}

				getCounter(pocItem.Id).Add(1)
				scheduled++

				task := stageTask{tap: &TransData{Target: t, Poc: pocItem}, pocID: pocItem.Id}
				select {
				case <-runner.engine.quit:
					finish(task.pocID)
				case <-runner.ctx.Done():
					finish(task.pocID)
				case tasks <- task:
					atomic.AddInt64(&runner.engine.queuedTasks, 1)
				}
			}
			if scheduled == 0 {
				runner.ScanProgress.MarkPocDone(pocItem.Id)
			}
		}

		close(tasks)
		workers.Wait()
		atomic.StoreInt64(&runner.engine.queuedTasks, 0)
	}

	oobRate := options.OOBRateLimit
	if oobRate <= 0 {
		oobRate = options.RateLimit
	}
	oobCon := options.OOBConcurrency
	if oobCon <= 0 {
		oobCon = options.Concurrency
	}
	if runner.engine != nil && len(reversePocs) > 0 && (!runner.engine.oobAlive || runner.engine.oobAdapter == nil) {
		for _, pocItem := range reversePocs {
			if atomic.LoadUint32(&runner.engine.stopped) != 0 || runner.options.VulnerabilityScannerBreakpoint || runner.ctx.Err() != nil {
				break
			}
			targetView := webScanTargets
			if isNetOnlyPoc(pocItem) {
				targetView = netTargetsStrict
			}

			if len(runner.options.Resume) > 0 && runner.ScanProgress.Contains(pocItem.Id) {
				if runner.options.ResumeDoneTasks == 0 {
					for range targetView {
						runner.NotVulCallback()
					}
				}
				continue
			}

			for range targetView {
				if runner.options.ResumeDoneTasks == 0 {
					runner.NotVulCallback()
				}
			}
			runner.ScanProgress.MarkPocDone(pocItem.Id)
		}
	} else {
		runStage(reversePocs, oobRate, oobCon)
	}

	runStage(otherPocs, options.RateLimit, options.Concurrency)

	runner.finalizeOOBPendings()

	if options.PocExecutionDurationMonitor && runner.engine != nil {
		runner.engine.pedmSummary(options)
	}
}

func (runner *Runner) exec(tap *TransData) {
	options := runner.options

	if len(tap.Target) > 0 && len(tap.Poc.Id) > 0 {
		baseCtx := runner.ctx
		if baseCtx == nil {
			baseCtx = context.Background()
		}
		if baseCtx.Err() != nil {
			return
		}
		atomic.AddInt64(&runner.engine.activeTasks, 1)
		defer atomic.AddInt64(&runner.engine.activeTasks, -1)
		if options.PocExecutionDurationMonitor {
			limit := options.PedmLogLimit
			if limit < 0 {
				limit = 0
			}
			n := atomic.AddUint32(&runner.engine.startedTasks, 1)
			if limit > 0 && n <= uint32(limit) {
				runner.engine.pedmLog(options, fmt.Sprintf("POC-TASK #%d | VULN | %s | %s", n, tap.Poc.Id, tap.Target))
			}

			taskID := runner.engine.pedmStartTask("VULN", tap.Poc.Id, tap.Target)
			defer runner.engine.pedmDoneTask(taskID)

			taskCtx := baseCtx
			cancel := func() {}
			hardTimeout := runner.engine.taskHardTimeout(&tap.Poc)
			if hardTimeout > 0 {
				taskCtx, cancel = context.WithTimeout(baseCtx, hardTimeout)
			}
			defer cancel()

			start := time.Now()
			runner.executeExpression(taskCtx, tap.Target, &tap.Poc)
			dur := time.Since(start)
			runner.engine.pedmRecord(tap.Poc.Id, dur)
			runner.engine.pedmRecordPair(tap.Target, tap.Poc.Id, dur)
			runner.engine.pedmMaybeLogSlow(options, "VULN", tap.Poc.Id, tap.Target, dur)
			if hardTimeout > 0 && errors.Is(taskCtx.Err(), context.DeadlineExceeded) {
				runner.engine.taskTimeoutLog("VULN", tap.Poc.Id, tap.Target, dur, hardTimeout)
			}
			return
		} else {
			taskCtx := baseCtx
			cancel := func() {}
			hardTimeout := runner.engine.taskHardTimeout(&tap.Poc)
			if hardTimeout > 0 {
				taskCtx, cancel = context.WithTimeout(baseCtx, hardTimeout)
			}
			defer cancel()
			start := time.Time{}
			if hardTimeout > 0 {
				start = time.Now()
			}
			runner.executeExpression(taskCtx, tap.Target, &tap.Poc)
			if hardTimeout > 0 && errors.Is(taskCtx.Err(), context.DeadlineExceeded) {
				runner.engine.taskTimeoutLog("VULN", tap.Poc.Id, tap.Target, time.Since(start), hardTimeout)
			}
		}
	}
}

// emitFailure 把单个 PoC 的执行失败上报给调用方，不影响扫描继续进行。
func (runner *Runner) emitFailure(target string, p *poc.Poc, err error) {
	if runner == nil || runner.OnFailure == nil || err == nil {
		return
	}
	pocID := ""
	if p != nil {
		pocID = p.Id
	}
	runner.OnFailure(target, pocID, err)
}

func (runner *Runner) executeExpression(ctx context.Context, target string, poc *poc.Poc) {
	c := runner.engine.AcquireChecker()
	defer runner.engine.ReleaseChecker(c)
	if runner.ScanProgress != nil && poc != nil && poc.Id != "" && target != "" {
		defer runner.ScanProgress.IncrementTask(poc.Id, target)
	}

	defer func() {
		// https://github.com/zan8in/afrog/v3/issues/7
		if r := recover(); r != nil {
			c.Result.IsVul = false
			runner.emitFailure(target, poc, fmt.Errorf("panic: %v", r))
			runner.OnResult(c.Result)
		}
	}()

	if ctx != nil {
		c.VariableMap[retryhttpclient.ContextVarKey] = ctx
	}
	if err := c.Check(target, poc); err != nil {
		runner.emitFailure(target, poc, err)
	}
	if c.Result != nil {
		c.Result.FingerResult = runner.fingerprintForTarget(c.Result.Target)
	}
	if c.CustomLib != nil && c.Result != nil {
		if pendings := c.CustomLib.TakeOOBPending(); len(pendings) > 0 {
			runner.registerOOBPendings(c.Result, pendings)
		}
	}
	runner.OnResult(c.Result)
}

type runnerFingerprintExecutor struct {
	runner *Runner
}

func (e runnerFingerprintExecutor) Exec(ctx context.Context, target string, p *poc.Poc) (matched bool, resolvedTarget string, err error) {
	if e.runner == nil || e.runner.engine == nil {
		return false, "", nil
	}
	if e.runner.options != nil && e.runner.options.Resume != "" && e.runner.ScanProgress != nil {
		fpID := "finger:" + p.Id
		if e.runner.ScanProgress.ContainsPoc(fpID) {
			if e.runner.options.ResumeDoneTasks == 0 {
				e.runner.NotVulCallback()
			}
			return false, "", nil
		}
		if e.runner.ScanProgress.ContainsTask(fpID, target) {
			if e.runner.options.ResumeDoneTasks == 0 {
				e.runner.NotVulCallback()
			}
			return false, "", nil
		}
	}
	c := e.runner.engine.AcquireChecker()
	defer e.runner.engine.ReleaseChecker(c)
	defer e.runner.NotVulCallback()
	if e.runner.ScanProgress != nil && p != nil && p.Id != "" && target != "" {
		fpID := "finger:" + p.Id
		defer e.runner.ScanProgress.IncrementTask(fpID, target)
	}

	var start time.Time
	var taskID uint64
	taskCtx := ctx
	cancel := func() {}
	hardTimeout := e.runner.engine.taskHardTimeout(p)
	if taskCtx == nil {
		taskCtx = context.Background()
	}
	if hardTimeout > 0 {
		taskCtx, cancel = context.WithTimeout(taskCtx, hardTimeout)
	}
	defer cancel()
	if e.runner.options != nil && e.runner.options.PocExecutionDurationMonitor {
		taskID = e.runner.engine.pedmStartTask("FINGER", p.Id, target)
		defer e.runner.engine.pedmDoneTask(taskID)
		start = time.Now()
	} else if hardTimeout > 0 {
		start = time.Now()
	}
	c.VariableMap[retryhttpclient.ContextVarKey] = taskCtx
	err = c.Check(target, p)
	if !start.IsZero() {
		dur := time.Since(start)
		if e.runner.options != nil && e.runner.options.PocExecutionDurationMonitor {
			e.runner.engine.pedmRecord(p.Id, dur)
			e.runner.engine.pedmRecordPair(target, p.Id, dur)
			e.runner.engine.pedmMaybeLogSlow(e.runner.options, "FINGER", p.Id, target, dur)
		}
		if hardTimeout > 0 && errors.Is(taskCtx.Err(), context.DeadlineExceeded) {
			e.runner.engine.taskTimeoutLog("FINGER", p.Id, target, dur, hardTimeout)
		}
	}
	if c.Result == nil {
		return false, "", err
	}
	if e.runner.options != nil && e.runner.options.Debug {
		pocID := ""
		if c.Result.PocInfo != nil {
			pocID = c.Result.PocInfo.Id
		}
		for i, pr := range c.Result.AllPocResult {
			// 请求在捕获前就失败时（例如被熔断跳过），没有任何内容可 dump，
			// 打一对「Dumped Request / unavailable」纯属噪音。
			if pr == nil || (pr.ResultRequest == nil && pr.ResultResponse == nil) {
				continue
			}
			idx := i + 1
			gologger.Info().Msgf("\r\n[%d][%s] Dumped Request\n", idx, pocID)
			gologger.Print().Msgf("%s\n", result.DebugDumpRequestText(pr))
			gologger.Info().Msgf("\r\n[%d][%s] Dumped Response\n", idx, pocID)
			gologger.Print().Msgf("%s\n", result.DebugDumpResponseText(pr))
		}
	}
	if c.Result.IsVul {
		key := keyFromTargetWithPath(c.Result.Target)
		if key == "" {
			key = keyFromTargetWithPath(target)
		}
		if key != "" {
			e.runner.setFingerprintResult(key, p.Id, c.Result)
			hit := fingerprint.Hit{
				ID:       p.Id,
				Name:     p.Info.Name,
				Tags:     p.Info.Tags,
				Severity: p.Info.Severity,
			}
			e.runner.fingerMu.Lock()
			e.runner.fingerByKey[key] = append(e.runner.fingerByKey[key], hit)
			e.runner.fingerMu.Unlock()
			if e.runner.OnFingerprint != nil {
				e.runner.OnFingerprint(key, []fingerprint.Hit{hit})
			}
		}
	}
	return c.Result.IsVul, c.Result.Target, err
}

func (runner *Runner) runFingerprintStage(ctx context.Context, targets []string, pocs []poc.Poc) {
	if runner == nil || runner.engine == nil || atomic.LoadUint32(&runner.engine.stopped) != 0 {
		return
	}
	if len(targets) == 0 || len(pocs) == 0 {
		return
	}
	if ctx != nil && ctx.Err() != nil {
		return
	}

	e := &fingerprint.Engine{Rate: runner.options.RateLimit, Concurrency: runner.options.Concurrency}
	e.Run(ctx, targets, pocs, runnerFingerprintExecutor{runner: runner})
	if runner.ScanProgress != nil {
		for _, p := range pocs {
			if p.Id == "" {
				continue
			}
			runner.ScanProgress.MarkPocDone("finger:" + p.Id)
		}
	}
}

func (runner *Runner) fingerprintForTarget(target string) []fingerprint.Hit {
	key := keyFromTargetWithPath(target)
	if key == "" {
		return nil
	}
	runner.fingerMu.Lock()
	hits := runner.fingerByKey[key]
	runner.fingerMu.Unlock()
	if len(hits) == 0 {
		return nil
	}
	out := make([]fingerprint.Hit, len(hits))
	copy(out, hits)
	return out
}

func (e *Engine) waitTick() {
	ticker := e.ticker.Load()
	if ticker == nil {
		return
	}
	start := time.Now()
	select {
	case <-ticker.C:
	case <-e.quit:
		return
	}
	retryhttpclient.AddTaskGateWait(time.Since(start))
	for atomic.LoadUint32(&e.paused) != 0 {
		select {
		case <-e.quit:
			return
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (e *Engine) Pause() {
	atomic.StoreUint32(&e.paused, 1)
	gologger.Debug().Msgf("engine paused: ticker gated")
}

func (e *Engine) Resume() {
	atomic.StoreUint32(&e.paused, 0)
	gologger.Debug().Msgf("engine resumed: ticker released")
}

func (e *Engine) IsPaused() bool {
	return atomic.LoadUint32(&e.paused) != 0
}

func (e *Engine) Stop() {
	if !atomic.CompareAndSwapUint32(&e.stopped, 0, 1) {
		return
	}
	e.stopTicker()
	close(e.quit)
	e.stopOOBManager()
	gologger.Debug().Msgf("engine stopped: ticker stopped and scheduling halted")
}

// stopOOBManager terminates the OOB poll goroutine and clears the reference.
// It is safe to call when no manager is running.
func (e *Engine) stopOOBManager() {
	if e == nil {
		return
	}
	if mgr := e.oobMgr.Swap(nil); mgr != nil {
		mgr.Stop()
	}
}

func (runner *Runner) NotVulCallback() {
	runner.OnResult(&result.Result{IsVul: false})
}

type TransData struct {
	Target string
	Poc    poc.Poc
}

// 获取OOB状态信息
func (runner *Runner) getOOBStatus(reversePocs []poc.Poc) (bool, string) {
	if len(reversePocs) == 0 {
		return true, "not required (no OOB PoCs)"
	}

	runner.options.SetOOBAdapter()

	// 从配置中获取当前OOB服务名称
	serviceName := strings.ToLower(runner.options.OOB)

	if runner.engine == nil || runner.engine.oobAdapter == nil {
		return false, serviceName + " not configured"
	}

	if !runner.engine.oobAdapter.IsVaild() {
		return false, serviceName + " connection failed"
	}

	return true, serviceName + " active"
}

// 新增OOB状态显示函数
func (runner *Runner) printOOBStatus(reversePocs []poc.Poc) {
	// 在SDK模式下，不显示OOB状态信息，由SDK自己控制显示；
	// Silent 模式下也不输出，避免污染 -json-stream 的 stdout 事件流
	if runner.options.SDKMode || runner.options.Silent {
		return
	}
	// 本轮没有反连类 PoC 时，OOB 是否配置与结果无关，打一行「未使用」只是噪音。
	if len(reversePocs) == 0 {
		return
	}

	status, msg := runner.getOOBStatus(reversePocs)

	// 与进度行/结果行同一套运维行语法：`[LEV] 阶段  事实`。
	// 状态本身已由级别标签表达，正文不再重复上色，避免整行都是饱和色。
	level := log.LevelInfo
	if !status {
		level = log.LevelErr
	}
	// 与其他运维行一样走 stderr：stdout 要留给 -json-stream 的 NDJSON。
	fmt.Fprintln(os.Stderr, log.Op(level, "oob", msg))
}

// func parseElaspsedTime(time time.Duration) string {
// 	s := fmt.Sprintf("%v", time)
// 	if len(s) > 0 {
// 		if strings.HasSuffix(s, "s") && !strings.HasSuffix(s, "ms") {
// 			t := strings.Replace(s, "s", "", -1)
// 			ts, err := strconv.ParseFloat(t, 64)
// 			if err != nil {
// 				return s
// 			}
// 			if ts >= 40 {
// 				return log.LogColor.Midium(s)
// 			}
// 		}
// 		if strings.HasSuffix(s, "m") {
// 			return log.LogColor.Red(s)
// 		}
// 	}
// 	return log.LogColor.Green(s)
// }

// func JndiTest() bool {
// 	url := "http://" + config.ReverseJndi + ":" + config.ReverseApiPort + "/?api=test"
// 	resp, _, err := retryhttpclient.Get(url)
// 	if err != nil {
// 		return false
// 	}
// 	if strings.Contains(string(resp), "no") || strings.Contains(string(resp), "yes") {
// 		return true
// 	}
// 	return false
// }

// func CeyeTest() bool {
// 	url := fmt.Sprintf("http://%s.%s", "test", config.ReverseCeyeDomain)
// 	resp, _, err := retryhttpclient.Get(url)
// 	if err != nil {
// 		return false
// 	}
// 	if strings.Contains(string(resp), "\"meta\":") || strings.Contains(string(resp), "201") {
// 		return true
// 	}
// 	return false
// }

// func EyeTest() bool {
// 	index := strings.Index(config.ReverseEyeDomain, ".")
// 	domain := config.ReverseEyeDomain

// 	if index != -1 {
// 		domain = config.ReverseEyeDomain[:index]
// 	}

// 	url := fmt.Sprintf("http://%s/api/dns/%s/test/?token=%s", config.ReverseEyeHost, domain, config.ReverseEyeToken)
// 	resp, _, err := retryhttpclient.Get(url)
// 	if err != nil {
// 		return false
// 	}
// 	if strings.Contains(string(resp), "False") {
// 		return true
// 	}
// 	return false
// }
