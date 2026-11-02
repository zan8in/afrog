package sqli

import (
	"net/http"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/passive"
)

// 本文件负责识别「这次响应是不是被 WAF / EDR 拦下了」。
//
// 它的唯一用途是决定要不要投入额外的绕过流量：误判只会多花几组候选（成本可控），
// 漏判则会让有 WAF 的站点整体漏报。因此判断口径是「看到明确拦截迹象才升级」，
// 而不是「不确定就升级」。

// wafStatusCodes 是被 WAF / EDR 拦截时最常见的响应码。
var wafStatusCodes = map[int]bool{
	http.StatusForbidden:          true, // 403
	http.StatusNotAcceptable:      true, // 406
	http.StatusTeapot:             true, // 418
	http.StatusTooManyRequests:    true, // 429
	http.StatusNotImplemented:     true, // 501
	http.StatusServiceUnavailable: true, // 503
}

// wafBodySignatures 是拦截页里常见的特征词（按小写比较）。
var wafBodySignatures = []string{
	"cloudflare", "mod_security", "modsecurity", "sucuri", "incapsula", "imperva",
	"akamai", "aws waf", "web application firewall", "request blocked", "blocked by",
	"安全狗", "云锁", "安全拦截", "请求被拦截", "拦截",
}

// wafHeaderSignatures 是 WAF / CDN 常见的响应头特征词。
var wafHeaderSignatures = []string{
	"cloudflare", "sucuri", "incapsula", "imperva", "akamai", "waf", "mod_security", "modsecurity",
}

// wafHeaderNames 是可能携带 WAF / CDN 标识的响应头。
var wafHeaderNames = []string{
	"Server", "X-Powered-By", "X-Waf-Status", "X-Sucuri-Id", "X-Iinfo", "X-Cdn", "Via",
}

// maxWAFBodyScan 限制特征扫描的响应体长度，避免在超大响应体上做无谓的匹配。
const maxWAFBodyScan = 64 << 10

// wafHeaderHint 在响应头里寻找 WAF / CDN 特征，返回命中的特征词。
//
// 只认「特征词出现在头值里」，不认「头存在」：任意 CDN 都可能带 X-Cdn，
// 把它的存在当成 WAF 会让大量正常站点误升级。
func wafHeaderHint(h http.Header) string {
	if h == nil {
		return ""
	}
	for _, name := range wafHeaderNames {
		v := strings.ToLower(h.Get(name))
		if v == "" {
			continue
		}
		for _, sig := range wafHeaderSignatures {
			if strings.Contains(v, sig) {
				return sig
			}
		}
	}
	return ""
}

// pointSession 记录单个注入点在检测过程中的可观测状态。
//
// 存在的意义是把「是否疑似被拦截」「方言是什么」从各轮次里收集起来，用于决定
// 要不要追加绕过流量、以及时间盲注该先试哪个方言——判定逻辑不该散落在每个确认函数里。
type pointSession struct {
	// baseStatus 是基线的响应状态码，用于识别「基线正常、注入后被拒」这一典型拦截特征。
	baseStatus int
	// wafSuspected 一旦置真不再回退：只要观察到一次明确拦截迹象就值得尝试绕过。
	wafSuspected bool
	// wafHint 记录命中的拦截特征，供证据说明。
	wafHint string
	// dialectHint 是根据已有响应认出的数据库方言，用于收敛时间盲注候选顺序。
	dialectHint string
	// dialectHintReason 记录方言指认依据，供证据说明与人工复核。
	dialectHintReason string
}

// observe 记录一次请求的响应，同时更新拦截迹象与方言指纹。
func (s *pointSession) observe(res *passive.CapturedResponse) {
	if s == nil || res == nil {
		return
	}
	s.observeWAF(res)
	s.observeDialect(res)
}

// observeDialect 用响应里的强信号指认数据库方言，只在尚无指纹时生效。
func (s *pointSession) observeDialect(res *passive.CapturedResponse) {
	if s == nil || s.dialectHint != "" {
		return
	}
	if dialect, reason := inferDBMSHint(res); dialect != "" {
		s.dialectHint = dialect
		s.dialectHintReason = reason
	}
}

// observeWAF 判断这次响应是否出现拦截迹象。
func (s *pointSession) observeWAF(res *passive.CapturedResponse) {
	if s == nil || s.wafSuspected || res == nil {
		return
	}
	if hint := wafHeaderHint(res.Headers); hint != "" {
		s.mark(hint)
		return
	}
	if !wafStatusCodes[res.Status] {
		return
	}
	// 基线正常、变异后被拒：典型 WAF 行为，即使响应体没有明显特征也算。
	if s.baseStatus >= 200 && s.baseStatus < 300 {
		s.mark("状态码由正常变为 " + http.StatusText(res.Status))
		return
	}
	if sig := bodySignature(res); sig != "" {
		s.mark(sig)
	}
}

func (s *pointSession) mark(hint string) {
	s.wafSuspected = true
	s.wafHint = hint
}

func bodySignature(res *passive.CapturedResponse) string {
	body := strings.ToLower(string(res.Body))
	if len(body) > maxWAFBodyScan {
		body = body[:maxWAFBodyScan]
	}
	for _, sig := range wafBodySignatures {
		if strings.Contains(body, sig) {
			return sig
		}
	}
	return ""
}
