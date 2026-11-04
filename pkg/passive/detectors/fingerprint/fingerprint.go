// Package fingerprint 实现被动「技术栈识别」提取（等价于浏览器插件 Wappalyzer）。
//
// 它复用主动扫描既有的 webscan 引擎（精选规则 + Wappalyzer 社区全量库、RE2 匹配、
// 多级可信度），把已经捕获的响应直接喂给匹配器，命中的技术栈以 info 级提取物送入
// 提取面板。
//
// 为什么归入「提取」而不是「漏洞检测」：
//   - 零流量：用现成响应判定，不额外发包，因此不属于会重放的 Detector；
//   - 产物是线索：一条「用 Nginx 1.24」不是漏洞，而是后续渗透决策的输入；
//   - 口径一致：与敏感信息/信息收集同表同面板，按 origin 聚合、同一技术只留一条。
//
// 附带收益：WAF / CDN / 防护设备的识别结果会长期留在提取面板里，为「识别到 WAF →
// 决定是否绕过」提供依据。
//
// 本提取器默认关闭：它产出的是线索而非结论，是否值得开由使用者按场景决定。
package fingerprint

import (
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/zan8in/afrog/v3/pkg/passive"
	"github.com/zan8in/afrog/v3/pkg/passive/detectors/rulekit"
	"github.com/zan8in/afrog/v3/pkg/webscan"
	"github.com/zan8in/gologger"
)

// DetectorName 是提取器标识。
const DetectorName = "fingerprint"

// techCategory 是全部技术栈提取物的统一分类。
//
// 刻意不直接复用 webscan 的技术分类（waf/cms/framework…）作为面板分类：那样面板会
// 一下子多出近二十个分类、把「敏感信息 / 信息收集 / 技术栈」三分法冲散。精细分类
// 放在 Extra 的 tech_category 里，详情页照样能看到。
const techCategory = "tech"

// Extractor 是技术栈识别提取器。
type Extractor struct {
	matcher *webscan.Matcher

	// sampled 记录每个 origin 已经匹配过多少次静态资源。
	//
	// 静态资源（CSS）是技术栈判据的重要来源——Tailwind 的 --tw-、UnoCSS 的 --un-、
	// Monaco 的 .monaco-editor 几乎只出现在样式表里，只看 HTML 会漏掉一大片。
	// 但一个站点动辄几十个 chunk，每次响应都跑一遍匹配既浪费又没必要：
	// 同一份技术栈在第一批资源里就已经暴露完了。因此按 origin 限量采样。
	mu      sync.Mutex
	sampled map[string]int
}

// maxStaticSamplesPerOrigin 是每个 origin 允许参与指纹匹配的静态资源数量上限。
const maxStaticSamplesPerOrigin = 8

// New 加载内置指纹规则并创建提取器。规则加载失败时降级为空匹配器（不阻断被动扫描）。
func New() *Extractor {
	m, err := webscan.LoadMatcher("")
	if err != nil {
		gologger.Warning().Msgf("被动指纹提取器加载规则失败，已降级为空匹配器: %v", err)
		m = webscan.NewMatcher(nil)
	}
	return &Extractor{matcher: m, sampled: make(map[string]int)}
}

// Name 实现 passive.Extractor。
func (e *Extractor) Name() string { return DetectorName }

// Interest 只对「有响应的文档与样式表」感兴趣。
//
// 刻意排除 JS 与其它静态资源：
//   - 性能：指纹要拿几千条正则去匹配正文，JS bundle 常有数百 KB；提取器内联在
//     门控池执行，若每个静态产物都跑一遍，会直接拖慢入口（队首阻塞）。
//   - 准确率：JS 里的库名（如 `axios`）与真正的技术依赖是两回事，拿来回填技术栈
//     误报极高；而样式表里的变量名/类名是实打实的「这个框架在用」。
func (e *Extractor) Interest(tx *passive.CapturedTransaction) bool {
	if tx == nil || tx.Request == nil || tx.Response == nil {
		return false
	}
	if !tx.Static {
		return true
	}
	return isStylesheet(tx) && e.allowStatic(tx)
}

// allowStatic 按 origin 限量放行静态资源，超额的直接跳过。
func (e *Extractor) allowStatic(tx *passive.CapturedTransaction) bool {
	key := rulekit.Origin(tx.Request.URL)
	if key == "" {
		key = tx.Request.URL.Host
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sampled[key] >= maxStaticSamplesPerOrigin {
		return false
	}
	e.sampled[key]++
	return true
}

// Extract 实现 passive.Extractor。
func (e *Extractor) Extract(tx *passive.CapturedTransaction) []passive.Extraction {
	if tx == nil || tx.Request == nil || tx.Response == nil {
		return nil
	}
	resp := tx.Response

	mr := webscan.Response{
		StatusCode: resp.Status,
		Headers:    headerMap(resp.Headers),
		Body:       resp.Body,
		Cookies:    resp.Headers.Values("Set-Cookie"),
	}
	if tx.Request.URL != nil {
		mr.RequestURL = tx.Request.URL.String()
	}
	// 若这条响应本身就是 /favicon.ico，则交给 favicon 规则（mmh3 哈希）匹配；
	// 同时清空 Body——二进制 favicon 丢给正文正则是纯粹的浪费与噪声来源。
	if isFavicon(tx.Request.URL) {
		mr.Favicon = resp.Body
		mr.Body = nil
	}

	res := e.matcher.Match(mr)
	if len(res.Technologies) == 0 {
		return nil
	}

	reqRaw, resRaw := passive.RawHTTPDump(tx.Request, tx.Response)
	target := rulekit.Origin(tx.Request.URL)
	latency := resp.Duration.Milliseconds()

	out := make([]passive.Extraction, 0, len(res.Technologies))
	for _, tech := range res.Technologies {
		value := strings.TrimSpace(tech.Name)
		if value == "" {
			continue
		}
		if v := strings.TrimSpace(tech.Version); v != "" {
			value += " " + v
		}
		extra := map[string]any{
			"status":        resp.Status,
			"rule":          tech.RuleID,
			"tech_category": tech.Category,
		}
		if tech.CPE != "" {
			extra["cpe"] = tech.CPE
		}
		if tech.Version != "" {
			extra["version"] = tech.Version
		}
		if res.FaviconHash != "" {
			extra["favicon_hash"] = res.FaviconHash
		}
		out = append(out, passive.Extraction{
			Detector:   DetectorName,
			Rule:       tech.RuleID,
			Category:   techCategory,
			Title:      tech.Name,
			Severity:   "info",
			Confidence: tech.Confidence,
			Value:      value,
			Target:     target,
			Location:   "response",
			LatencyMs:  latency,
			Evidence:   evidence(tech),
			Request:    reqRaw,
			Response:   resRaw,
			Extra:      extra,
		})
	}
	return out
}

// evidence 汇总一条技术栈的可读依据，供面板直接展示。
func evidence(t webscan.Technology) string {
	parts := make([]string, 0, 3)
	if t.Category != "" {
		parts = append(parts, "分类: "+t.Category)
	}
	if t.Version != "" {
		parts = append(parts, "版本: "+t.Version)
	}
	if t.CPE != "" {
		parts = append(parts, "CPE: "+t.CPE)
	}
	return strings.Join(parts, "  ")
}

// headerMap 把 http.Header 摊平成 map[string]string（同名多值用逗号连接）。
func headerMap(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, vs := range h {
		if len(vs) == 0 {
			continue
		}
		out[k] = strings.Join(vs, ", ")
	}
	return out
}

// isStylesheet 判断这条静态资源是不是样式表。
//
// 先看 Content-Type，再回落扩展名：很多 CDN 对 .css 返回 application/octet-stream，
// 只看头部会漏；反过来只看扩展名又会被带 query 的伪静态骗到，两者互补最稳。
func isStylesheet(tx *passive.CapturedTransaction) bool {
	if ct := strings.ToLower(tx.Response.Headers.Get("Content-Type")); strings.Contains(ct, "text/css") {
		return true
	}
	if tx.Request.URL == nil {
		return false
	}
	return strings.HasSuffix(strings.ToLower(tx.Request.URL.Path), ".css")
}

// isFavicon 判断请求路径是否指向 favicon。
func isFavicon(u *url.URL) bool {
	if u == nil {
		return false
	}
	p := strings.ToLower(u.Path)
	return strings.HasSuffix(p, "favicon.ico") || strings.HasSuffix(p, "favicon.png")
}

// 编译期断言：本提取器必须满足 passive.Extractor 契约。
var _ passive.Extractor = (*Extractor)(nil)
