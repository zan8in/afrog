// Package misconfig 实现被动「会话与传输安全」配置检测（B 档）。
//
// 与 SQL 注入等「需重放才能验证」的漏洞不同，本检测器**完全零流量**：它只对已经
// 捕获到的响应做本地解析（Set-Cookie、Cache-Control、URL），一个请求都不发。
// 因此它的成本可以忽略，唯一要克制的是**噪声**——每条结论都必须是对响应里某个
// 客观事实的陈述，而不是推测：
//
//   - Cookie 缺 Secure / HttpOnly / SameSite：读的是 Set-Cookie 里的字面属性；
//   - Domain 过宽：只在 Domain 落到裸顶级域（如 .com）这类**必然错误**的取值时才报，
//     正常的父域共享（app.example.com 上 Domain=example.com）是常见且常常是有意为之
//     的配置，报它就是误报；
//   - Session ID 落 URL：URL 里出现 jsessionid / PHPSESSID 这类会话参数；
//   - 可缓存的 HTTPS 敏感响应：HTTPS 响应既下发 Cookie 又把 Cache-Control 标成
//     public，等于邀请共享缓存把会话复制出去。
//
// 聚合口径：Target 取 origin（scheme://host），Location 取「规则:主体」。这样同一
// 站点在不同路径上重复下发的同一个 Cookie 只算一条，符合「按 Host 聚合」的约定，
// 同时保留「是哪条规则、哪个 Cookie」的可核对信息。
package misconfig

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/passive"
)

const (
	// DetectorName 是检测器标识。
	DetectorName = "misconfig"
	// VulnType 是漏洞类型标识。
	VulnType = "session-security"
)

// 规则标识，用于 Location 与 Extra，便于前端与报告按规则归类。
const (
	ruleCookieSecure   = "cookie-secure"
	ruleCookieHTTPOnly = "cookie-httponly"
	ruleCookieSameSite = "cookie-samesite"
	ruleCookieDomain   = "cookie-domain"
	ruleSessionIDInURL = "session-id-in-url"
	ruleCacheableHTTPS = "cacheable-https"
)

// bareTLDs 是「不可能作为合法 Cookie Domain」的裸顶级域。
//
// 浏览器的 Cookie 规范要求 Domain 至少是一个可注册域；把 Domain 写成 .com 之类的
// 裸顶级域既是配置错误，也会让 Cookie 在理论上被投递给所有 .com 站点。只在命中
// 这一小撮取值时才报，避免把正常的父域共享误判成漏洞。
var bareTLDs = map[string]bool{
	"com": true, "net": true, "org": true, "cn": true, "io": true, "cc": true,
	"top": true, "xyz": true, "info": true, "biz": true, "co": true, "me": true,
	"tv": true, "us": true, "eu": true, "ru": true, "jp": true, "kr": true,
	"dev": true, "app": true, "site": true, "shop": true, "online": true,
}

// sessionParamNames 是出现在 URL 里即视为「会话标识落入 URL」的参数名（小写）。
var sessionParamNames = map[string]bool{
	"jsessionid":        true,
	"phpsessid":         true,
	"sessionid":         true,
	"session_id":        true,
	"sid":               true,
	"aspsessionid":      true,
	"asp.net_sessionid": true,
}

// Options 控制各条规则的开关。零值表示全部开启，与「零值跟随默认」的约定一致。
type Options struct {
	DisableCookieSecure   bool
	DisableCookieHTTPOnly bool
	DisableCookieSameSite bool
	DisableCookieDomain   bool
	DisableSessionIDInURL bool
	DisableCacheableHTTPS bool
}

// Detector 是会话与传输安全被动检测器。
type Detector struct {
	opts Options
}

// New 创建检测器。
func New(opts Options) *Detector { return &Detector{opts: opts} }

// DefaultOptions 返回默认（全部开启）的选项。
func DefaultOptions() Options { return Options{} }

// Name 实现 passive.Detector。
func (d *Detector) Name() string { return DetectorName }

// CostClass 声明本检测器为**本地类**：零流量、无重放，因此调度层会把它内联在
// 门控池执行，不受注入点短路影响，也不进检测池——会话安全配置检查永不缺席。
func (d *Detector) CostClass() passive.CostClass { return passive.CostLocal }

// Interest 是零流量门控：只有「下发了 Cookie」或「URL 里带会话标识」的事务才值得
// 看一眼。门控必须足够窄——否则每一个普通请求都会把检测池的队列塞满，而那些请求
// 根本没有任何会话安全事实可读。
func (d *Detector) Interest(tx *passive.CapturedTransaction) bool {
	if tx == nil || tx.Request == nil || tx.Response == nil {
		return false
	}
	if len(tx.Response.Headers.Values("Set-Cookie")) > 0 {
		return true
	}
	return hasSessionIDInURL(tx.Request.URL)
}

// InterestReason 实现 passive.InterestReasoner。
func (d *Detector) InterestReason(tx *passive.CapturedTransaction) string {
	if tx == nil || tx.Request == nil || tx.Response == nil {
		return "缺少完整请求或响应"
	}
	if len(tx.Response.Headers.Values("Set-Cookie")) > 0 {
		return ""
	}
	if hasSessionIDInURL(tx.Request.URL) {
		return ""
	}
	return "响应未下发 Cookie，URL 中也没有会话标识"
}

// Detect 实现 passive.Detector。刻意不使用 ctx / probe：本检测器零流量，
// 全部结论都来自已捕获的响应。
func (d *Detector) Detect(_ context.Context, tx *passive.CapturedTransaction, _ passive.Prober) ([]passive.Finding, error) {
	if tx == nil || tx.Request == nil || tx.Response == nil {
		return nil, nil
	}

	findings := make([]passive.Finding, 0, 2)
	findings = append(findings, d.checkCookies(tx)...)
	if f, ok := d.checkSessionIDInURL(tx); ok {
		findings = append(findings, f)
	}
	return findings, nil
}

// checkCookies 逐条 Set-Cookie 核对安全属性。
func (d *Detector) checkCookies(tx *passive.CapturedTransaction) []passive.Finding {
	rawCookies := tx.Response.Headers.Values("Set-Cookie")
	if len(rawCookies) == 0 {
		return nil
	}
	https := isHTTPS(tx.Request.URL)
	cacheablePublic := isPubliclyCacheable(tx.Response.Headers)

	out := make([]passive.Finding, 0, len(rawCookies))
	seen := make(map[string]bool, len(rawCookies))
	emit := func(f passive.Finding) {
		if f.Location == "" || seen[f.Location] {
			return
		}
		seen[f.Location] = true
		out = append(out, f)
	}

	for _, raw := range rawCookies {
		c, err := http.ParseSetCookie(raw)
		if err != nil || c == nil || c.Name == "" {
			continue
		}
		secretish := looksSessionCookie(c.Name)

		if https && !d.opts.DisableCookieSecure && !c.Secure {
			emit(makeFinding(tx, ruleCookieSecure, c.Name, "low", "Cookie 未设置 Secure 标记",
				"HTTPS 响应下发的 Cookie「"+c.Name+"」缺少 Secure 属性，浏览器可能将其随明文 HTTP 请求一起发送，存在被中间人截获的风险。\r\n\r\nSet-Cookie: "+raw))
		}
		if !d.opts.DisableCookieHTTPOnly && !c.HttpOnly {
			sev := "low"
			if secretish {
				sev = "medium"
			}
			emit(makeFinding(tx, ruleCookieHTTPOnly, c.Name, sev, "Cookie 未设置 HttpOnly 标记",
				"Cookie「"+c.Name+"」缺少 HttpOnly 属性，客户端脚本可读取该值；若页面存在 XSS，会话凭据可被直接窃取。\r\n\r\nSet-Cookie: "+raw))
		}
		if !d.opts.DisableCookieSameSite && !hasSameSite(raw) {
			emit(makeFinding(tx, ruleCookieSameSite, c.Name, "low", "Cookie 未设置 SameSite 标记",
				"Cookie「"+c.Name+"」未声明 SameSite 属性，跨站请求场景下的发送行为依赖浏览器默认值，建议显式声明 Lax 或 Strict。\r\n\r\nSet-Cookie: "+raw))
		}
		if !d.opts.DisableCookieDomain {
			if dom, bad := broadCookieDomain(c.Domain); bad {
				emit(makeFinding(tx, ruleCookieDomain, c.Name, "medium", "Cookie Domain 取值过宽",
					"Cookie「"+c.Name+"」的 Domain 被设置为「"+dom+"」，这是一个顶级域而不是可注册域；浏览器会拒绝该 Cookie，且一旦被接受将向该顶级域下所有站点发送。\r\n\r\nSet-Cookie: "+raw))
			}
		}
		if https && !d.opts.DisableCacheableHTTPS && cacheablePublic {
			emit(makeFinding(tx, ruleCacheableHTTPS, c.Name, "low", "HTTPS 响应可被共享缓存",
				"HTTPS 响应下发 Cookie「"+c.Name+"」的同时把 Cache-Control 标记为可公开缓存（public），共享缓存可能把含会话信息的响应副本投递给其他用户。\r\n\r\nCache-Control: "+
					tx.Response.Headers.Get("Cache-Control")))
		}
	}
	return out
}

// checkSessionIDInURL 检查会话标识是否出现在 URL 里。
func (d *Detector) checkSessionIDInURL(tx *passive.CapturedTransaction) (passive.Finding, bool) {
	if d.opts.DisableSessionIDInURL {
		return passive.Finding{}, false
	}
	u := tx.Request.URL
	if u == nil {
		return passive.Finding{}, false
	}
	// 路径参数形态：/app;jsessionid=XXXX
	if i := strings.Index(u.EscapedPath(), ";"); i >= 0 {
		if name, ok := sessionNameFromToken(u.EscapedPath()[i+1:]); ok {
			return makeFinding(tx, ruleSessionIDInURL, name, "medium", "会话标识出现在 URL 路径中",
				"URL 路径中携带会话标识「"+name+"」。URL 会被浏览器历史、日志与 Referer 头记录并外泄，会话凭据因此可能被他人直接复用。"), true
		}
	}
	for name := range u.Query() {
		if sessionParamNames[strings.ToLower(name)] {
			return makeFinding(tx, ruleSessionIDInURL, name, "medium", "会话标识出现在 URL 查询串中",
				"URL 查询参数「"+name+"」携带会话标识。URL 会被浏览器历史、日志与 Referer 头记录并外泄，会话凭据因此可能被他人直接复用。"), true
		}
	}
	return passive.Finding{}, false
}

// makeFinding 组装一条统一形态的发现。Target 取 origin，使同一站点在不同路径上的
// 同一问题归为一条（按 Host 聚合）。
func makeFinding(tx *passive.CapturedTransaction, rule, subject, severity, title, evidence string) passive.Finding {
	reqRaw, resRaw := passive.RawHTTPDump(tx.Request, tx.Response)

	var latency int64
	var status int
	if tx.Response != nil {
		latency = tx.Response.Duration.Milliseconds()
		status = tx.Response.Status
	}

	return passive.Finding{
		Detector:   DetectorName,
		VulnType:   VulnType,
		Severity:   severity,
		Confidence: passive.ConfidenceCertain,
		Title:      title,
		Target:     originOf(tx.Request.URL),
		Location:   rule + ":" + subject,
		LatencyMs:  latency,
		Evidence:   evidence,
		Request:    reqRaw,
		Response:   resRaw,
		Traces: []passive.Trace{{
			Label:     "捕获响应",
			Status:    status,
			LatencyMs: latency,
			Note:      evidence,
			Request:   string(reqRaw),
			Response:  string(resRaw),
		}},
		Extra: map[string]any{
			"rule":    rule,
			"subject": subject,
		},
	}
}

// hasSameSite 在原始 Set-Cookie 上判定 SameSite 属性是否出现。
//
// 不用 ParseSetCookie 的 SameSite 字段：该字段对「SameSite=None」与「未设置」在
// 部分场景下会都落到默认值，直接看字面属性更可靠。
func hasSameSite(raw string) bool {
	return strings.Contains(strings.ToLower(raw), "samesite")
}

// broadCookieDomain 判定 Domain 是否落到了裸顶级域。
func broadCookieDomain(domain string) (string, bool) {
	dom := strings.ToLower(strings.TrimSpace(domain))
	dom = strings.TrimPrefix(dom, ".")
	if dom == "" {
		return "", false
	}
	// 只有单标签（不含点）且是已知顶级域时才判为过宽。
	if strings.Contains(dom, ".") {
		return "", false
	}
	if bareTLDs[dom] {
		return domain, true
	}
	return "", false
}

// looksSessionCookie 用名字粗判 Cookie 是否是会话凭据，仅用于抬高一档严重级别。
func looksSessionCookie(name string) bool {
	n := strings.ToLower(name)
	for _, kw := range []string{"session", "sessid", "sid", "auth", "token", "jwt", "login", "sso"} {
		if strings.Contains(n, kw) {
			return true
		}
	}
	return false
}

// isPubliclyCacheable 判定 Cache-Control 是否明确允许共享缓存。
//
// 只认字面 public：多数应用用 private / no-store，命中 public 才值得报告，
// 避免把正常的可缓存静态资源也算进来。
func isPubliclyCacheable(h http.Header) bool {
	cc := strings.ToLower(h.Get("Cache-Control"))
	return strings.Contains(cc, "public")
}

func isHTTPS(u *url.URL) bool {
	return u != nil && strings.EqualFold(u.Scheme, "https")
}

func originOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func hasSessionIDInURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	if i := strings.Index(u.EscapedPath(), ";"); i >= 0 {
		if _, ok := sessionNameFromToken(u.EscapedPath()[i+1:]); ok {
			return true
		}
	}
	for name := range u.Query() {
		if sessionParamNames[strings.ToLower(name)] {
			return true
		}
	}
	return false
}

// sessionNameFromToken 从 "jsessionid=XXXX;..." 这类路径参数里取出会话参数名。
func sessionNameFromToken(s string) (string, bool) {
	token := s
	if i := strings.IndexAny(token, ";/?"); i >= 0 {
		token = token[:i]
	}
	eq := strings.Index(token, "=")
	if eq <= 0 {
		return "", false
	}
	name := strings.ToLower(token[:eq])
	if sessionParamNames[name] {
		return token[:eq], true
	}
	return "", false
}
