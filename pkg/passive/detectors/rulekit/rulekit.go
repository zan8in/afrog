// Package rulekit 是「规则驱动的本地文本提取引擎」，供各类提取器复用。
//
// 提取器（敏感信息提取、信息收集 …）共享同一套能力：把事务拆成若干可扫描面、
// 用带锚点的正则匹配、再用校验器与语境佐证过滤，最后产出 passive.Extraction。
// 把引擎独立成包，是为了让「新增一个提取器 = 写一份规则表」：
// 提取器只会越加越多，如果每个都复制一份匹配循环，每一份复制都是未来的维护债。
//
// 准确率优先是硬约束：一条规则要么带字面锚点（先用 bytes.Contains 秒筛，命中才跑
// 正则），要么带校验器与语境佐证。占位值一律丢弃。
package rulekit

import (
	"bytes"
	"net/url"
	"regexp"

	"github.com/zan8in/afrog/v3/pkg/passive"
)

// 默认限额。提取器跑在门控池内联，必须给单条事务的产出封顶，避免一个异常响应
// （例如一整文件都是随机 base64）把面板淹没。
const (
	defaultMaxPerRule = 20
	defaultMaxPerTx   = 128
	defaultMaxBody    = 4 << 20 // 4MB：超过这个体积的响应体不再做提取，防内存与 CPU 尖峰
)

// Source 是一个可扫描面的位置标识。提取器据此限定规则只在某些面上匹配。
type Source string

const (
	// SourceURL 是请求 URL（含查询串）。
	SourceURL Source = "url"
	// SourceHeader 是响应头。
	SourceHeader Source = "response-header"
	// SourceBody 是响应体。
	SourceBody Source = "response-body"
)

// Rule 是一条提取规则。
//
// 准确率优先的三道保险都落在这里：
//   - Anchors 是**字面锚点**。命中任一锚点才会去跑正则：先用 bytes.Contains 做一次
//     极廉价的秒筛，既省下绝大多数正则开销，又天然过滤掉「结构相似但缺了固定前缀」
//     的误报（如 AWS 密钥必然含 AKIA/ASIA）。
//   - Validate 是**结构校验器**。对没有固定前缀的规则（身份证、银行卡、JWT）而言，
//     正则只能框出「看起来像」，必须靠校验位/Luhn/BIN/base64 解码把「确实是」判出来。
//   - Context 是**语境佐证**。对「结构上不够独特」的规则（裸数字串谁都能凑出来），
//     还要求命中处周边出现佐证信息，否则丢弃。
//
// 一条规则的 Anchors / Validate / Context 至少要有一个，三者皆无的规则不允许进表。
type Rule struct {
	ID       string
	Category string
	Title    string
	Severity string
	Conf     passive.Confidence
	Anchors  []string
	Re       *regexp.Regexp
	// Sources 限定本规则只在哪些扫描面上匹配；为空表示全部扫描面。
	//
	// 存在的意义：不同规则关心的面不同。例如「绝对 URL」这类信息收集规则只该看响应体，
	// 若也扫请求 URL，就会把用户访问的每一条 URL 自身当成一次发现，噪声淹没信息。
	Sources []Source
	// Group 是取值用的捕获组下标，0 表示整段匹配即值。
	Group    int
	Validate func(string) bool
	// Context 是语境佐证钩子，入参为整段内容与本次命中的 [start, end) 区间。
	// 返回 false 表示「语境不足以佐证」，该命中被丢弃。nil 表示不做额外要求。
	Context func(content []byte, start, end int) bool
}

// Options 控制提取器的限额。零值表示跟随默认。
type Options struct {
	// MaxPerRule 是单条规则在单个扫描面（surface）上的最大命中数。
	MaxPerRule int
	// MaxPerTx 是单条事务的最大提取物条数。
	MaxPerTx int
	// MaxBody 是参与提取的响应体体积上限（字节）。
	MaxBody int
}

// DefaultOptions 返回默认限额。
func DefaultOptions() Options { return Options{} }

// Engine 是规则表驱动的提取器，实现 passive.Extractor。
//
// 它天然是 CostLocal：零流量、内联在门控池执行，不受注入点短路，也不进检测池。
type Engine struct {
	name   string
	rules  []Rule
	maxPer int
	maxTx  int
	maxBdy int
}

// New 用给定标识与规则表创建提取器。
func New(name string, opts Options, rules []Rule) *Engine {
	e := &Engine{name: name, rules: rules}
	e.maxPer = opts.MaxPerRule
	if e.maxPer <= 0 {
		e.maxPer = defaultMaxPerRule
	}
	e.maxTx = opts.MaxPerTx
	if e.maxTx <= 0 {
		e.maxTx = defaultMaxPerTx
	}
	e.maxBdy = opts.MaxBody
	if e.maxBdy <= 0 {
		e.maxBdy = defaultMaxBody
	}
	return e
}

// Name 实现 passive.Extractor。
func (e *Engine) Name() string { return e.name }

// Interest 是快速门控：只要事务里有可扫的面（请求 URL、响应体或响应头）就值得扫。
//
// 提取是零流量的本地计算，门控可以放宽——真正需要挡的是「没有响应、也没有 URL」
// 的空事务。文本类静态资源（.js/.map）恰恰是提取的重点目标，绝不能被门控排除。
func (e *Engine) Interest(tx *passive.CapturedTransaction) bool {
	return tx != nil && tx.Request != nil && (tx.Request.URL != nil || tx.Response != nil)
}

// surface 是一个可扫描面：一段文本内容及其出处。
type surface struct {
	location Source
	header   string
	content  []byte
}

// surfaces 把事务拆成若干可扫描面。
//
// 覆盖顺序（也是优先级）：URL → 响应头 → 响应体。响应体是高发地，但它同时也最容易
// 产生噪声，因此放在最后、且受体积与文本性双重限制。
func (e *Engine) surfaces(tx *passive.CapturedTransaction) []surface {
	out := make([]surface, 0, 6)
	if u := tx.Request.URL; u != nil {
		out = append(out, surface{location: SourceURL, content: []byte(u.String())})
	}
	if resp := tx.Response; resp != nil {
		for name, vals := range resp.Headers {
			for _, v := range vals {
				out = append(out, surface{location: SourceHeader, header: name, content: []byte(v)})
			}
		}
		if len(resp.Body) > 0 && len(resp.Body) <= e.maxBdy && looksText(resp.Body) {
			out = append(out, surface{location: SourceBody, content: resp.Body})
		}
	}
	return out
}

// Extract 实现 passive.Extractor。
func (e *Engine) Extract(tx *passive.CapturedTransaction) []passive.Extraction {
	if tx == nil || tx.Request == nil {
		return nil
	}
	surfaces := e.surfaces(tx)
	if len(surfaces) == 0 {
		return nil
	}

	// 请求/响应原文只在整条事务上取一次，所有提取物共享同一份只读切片，
	// 既避免重复构造，也让面板能一次定位回同一个原始事务。
	reqRaw, resRaw := passive.RawHTTPDump(tx.Request, tx.Response)
	target := Origin(tx.Request.URL)

	var latency int64
	var status int
	if tx.Response != nil {
		latency = tx.Response.Duration.Milliseconds()
		status = tx.Response.Status
	}

	out := make([]passive.Extraction, 0, 8)
	seen := make(map[string]struct{})
	for i := range e.rules {
		r := &e.rules[i]
		for _, s := range surfaces {
			if !r.matchesSource(s.location) || !r.matchesAnchor(s.content) {
				continue
			}
			for _, m := range r.Re.FindAllSubmatchIndex(s.content, e.maxPer) {
				value := valueAt(s.content, m, r.Group)
				if value == "" || IsPlaceholder(value) {
					continue
				}
				if r.Validate != nil && !r.Validate(value) {
					continue
				}
				// 语境佐证：对结构上不够独特的规则（如裸卡号），要求命中处近旁出现佐证词。
				// 用带下标的匹配正是为了这里——没有位置就无从判断「值周边写了什么」。
				if r.Context != nil {
					gs, ge := groupRange(m, r.Group)
					if gs < 0 || !r.Context(s.content, gs, ge) {
						continue
					}
				}
				// 同一事务内按「规则 + 值」去重：同一个密钥在页头页脚各出现一次，
				// 只报一条即可，出处以首次命中的位置为准。
				key := r.ID + "|" + value
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}

				ex := passive.Extraction{
					Detector:   e.name,
					Rule:       r.ID,
					Category:   r.Category,
					Title:      r.Title,
					Severity:   r.Severity,
					Confidence: r.Conf,
					Value:      value,
					Target:     target,
					Location:   string(s.location),
					LatencyMs:  latency,
					Evidence:   evidenceAround(s.content, value),
					Request:    reqRaw,
					Response:   resRaw,
					Extra:      map[string]any{"status": status},
				}
				if s.header != "" {
					ex.Extra["header"] = s.header
				}
				out = append(out, ex)
				if len(out) >= e.maxTx {
					return out
				}
			}
		}
	}
	return out
}

// matchesSource 判断本规则是否应当在给定扫描面上匹配；未限定扫描面时一律匹配。
func (r *Rule) matchesSource(s Source) bool {
	if len(r.Sources) == 0 {
		return true
	}
	for _, want := range r.Sources {
		if want == s {
			return true
		}
	}
	return false
}

// matchesAnchor 判断是否值得对本段内容跑正则。
//
// 无锚点的规则（身份证 / 银行卡 / 通用赋值）直接返回 true——它们靠校验器兜底，
// 正则本身也已足够强。有锚点的规则先做一次极廉价的 bytes.Contains。
func (r *Rule) matchesAnchor(content []byte) bool {
	if len(r.Anchors) == 0 {
		return true
	}
	for _, a := range r.Anchors {
		if bytes.Contains(content, []byte(a)) {
			return true
		}
	}
	return false
}

// valueAt 从一次「带下标匹配」里取出规则约定的取值组。
func valueAt(content []byte, m []int, group int) string {
	s, e := groupRange(m, group)
	if s < 0 || e < 0 || e > len(content) {
		return ""
	}
	return string(content[s:e])
}

// groupRange 返回取值组在内容中的 [start, end) 区间；未参与匹配时返回 (-1, -1)。
//
// m 是 FindAllSubmatchIndex 的单次结果：形如 [m0s, m0e, m1s, m1e, …]，未参与匹配的组
// 以 -1 占位。group<=0 或越界时退回到整段匹配（与正则里「第一个捕获组」的语义一致）。
func groupRange(m []int, group int) (int, int) {
	if group > 0 && 2*group+1 < len(m) {
		return m[2*group], m[2*group+1]
	}
	if len(m) >= 4 { // 存在第一个捕获组时，退化为它
		return m[2], m[3]
	}
	if len(m) >= 2 {
		return m[0], m[1]
	}
	return -1, -1
}

// evidenceAround 截取命中值周边的上下文，供人工复核（值出现在什么语境下）。
func evidenceAround(content []byte, value string) string {
	const pad = 48
	idx := bytes.Index(content, []byte(value))
	if idx < 0 {
		return ""
	}
	start := idx - pad
	if start < 0 {
		start = 0
	}
	end := idx + len(value) + pad
	if end > len(content) {
		end = len(content)
	}
	snippet := content[start:end]
	// 压掉换行/制表，避免证据串在面板里撑破布局。
	snippet = bytes.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		}
		return r
	}, snippet)
	return string(snippet)
}

// looksText 粗判内容是否为文本：出现 NUL 字节即认为是二进制。
//
// 只在开头一小段里探测即可——真正的二进制（图片/字体/压缩包）开头就带魔数与 NUL。
func looksText(b []byte) bool {
	n := len(b)
	if n > 1024 {
		n = 1024
	}
	for i := 0; i < n; i++ {
		if b[i] == 0 {
			return false
		}
	}
	return true
}

// Origin 返回 URL 的 scheme://host 形式的源，用作提取物的聚合口径。
//
// 导出供各提取器复用：同一目标的技术栈/信息收集结果按 origin 聚合，避免同一主机
// 因不同路径被拆成多条记录。URL 为空时返回空串。
func Origin(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
