package webscan

import (
	"encoding/base64"
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/spaolacci/murmur3"
)

const (
	// maxBodyBytes 是参与匹配的正文长度上限，避免超大响应拖慢匹配。
	maxBodyBytes = 512 * 1024

	// maxScriptURLs 是从页面里最多抽取多少个脚本地址参与匹配。
	//
	// 与正文上限同理：正常页面的外链脚本在几十个量级，设个上限只是防住极端页面
	// （比如把全部资源内联了几百个 <script>）把匹配成本顶上去。
	maxScriptURLs = 256

	// maxInlineScripts 是最多收集多少段内联脚本文本。
	maxInlineScripts = 64
)

var (
	titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	// scriptSrcRe 抽取 <script src="...">。
	scriptSrcRe = regexp.MustCompile(`(?is)<script[^>]*\ssrc\s*=\s*["']([^"']+)["']`)
	// linkTagRe 抽取 <link ...>，再从中挑出模块预载脚本（SPA 打包器用它加载入口）。
	linkTagRe = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	// scriptBlockRe 抽取完整 <script> 标签（属性 + 标签体），用于区分外部脚本与内联脚本。
	scriptBlockRe = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script\s*>`)
	// scriptSrcAttrRe 判断 <script> 的属性里是否带 src。
	scriptSrcAttrRe = regexp.MustCompile(`(?is)\ssrc\s*=`)
	// hrefRe 抽取标签里的 href。
	hrefRe = regexp.MustCompile(`(?is)\shref\s*=\s*["']([^"']+)["']`)
	// relRe 抽取标签里的 rel。
	relRe = regexp.MustCompile(`(?is)\srel\s*=\s*["']([^"']+)["']`)
	// metaTagRe 抽取 <meta ...>。
	metaTagRe = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	// metaNameRe 抽取 meta 的 name/property/http-equiv。
	metaNameRe = regexp.MustCompile(`(?is)\s(?:name|property|http-equiv)\s*=\s*["']([^"']+)["']`)
	// metaContentRe 抽取 meta 的 content。
	metaContentRe = regexp.MustCompile(`(?is)\scontent\s*=\s*["']([^"']*)["']`)
)

// Matcher 在一份规则集上执行 Web 指纹匹配。
type Matcher struct {
	db *DB
}

// NewMatcher 基于规则集构造匹配器，db 为 nil 时返回一个空匹配器。
func NewMatcher(db *DB) *Matcher {
	if db == nil {
		db = &DB{}
	}
	return &Matcher{db: db}
}

// LoadMatcher 加载内置规则（并可选合并外置目录）后构造匹配器。
func LoadMatcher(dir string) (*Matcher, error) {
	db, err := LoadDB(dir)
	if err != nil {
		return nil, err
	}
	return NewMatcher(db), nil
}

// HasFavicon 报告外置规则集里是否有 favicon 规则。
//
// 调用方据此决定要不要额外抓取 /favicon.ico：内置规则虽然带了 favicon 规则，但抓取与否
// 仍以 -w-favicon 开关为准；而用户在外置目录里写 favicon 规则，本身就说明他要抓 favicon，
// 因此这里返回 true 时调用方应自动开启抓取、不必再要求开关。
func (m *Matcher) HasFavicon() bool {
	return m != nil && m.db != nil && m.db.hasFavicon
}

// Match 对一次 HTTP 响应做规则匹配，返回按可信度排序的技术栈。
func (m *Matcher) Match(resp Response) Result {
	var res Result
	if m == nil || m.db == nil {
		return res
	}

	mat := newMaterial(resp)
	res.FaviconHash = mat.faviconHash

	// 正文只扫一遍，得到「哪些字面量出现」的位图；后面几百条正文类模式直接查表，
	// 不再各自扫全文。大小写不敏感那组扫的是正文的小写副本。
	var hits, hitsCI []bool
	if mat.body != "" {
		if n := m.db.bodyLiteralCount; n > 0 {
			hits = make([]bool, n)
			m.db.bodyLiterals.scan(mat.body, hits)
		}
		if n := m.db.bodyLiteralCIDim; n > 0 {
			hitsCI = make([]bool, n)
			m.db.bodyLiteralsCI.scan(foldASCII(mat.body), hitsCI)
		}
	}

	// 同名同版本只保留可信度最高的一条：key 为 name\x00version。
	seen := make(map[string]int, 8)
	for _, rule := range m.db.Rules {
		tech, ok := m.matchRule(rule, mat, hits, hitsCI)
		if !ok {
			continue
		}
		if tech.Confidence > res.Confidence {
			res.Confidence = tech.Confidence
		}
		key := tech.Name + "\x00" + tech.Version
		if idx, dup := seen[key]; dup {
			if tech.Confidence > res.Technologies[idx].Confidence {
				res.Technologies[idx] = tech
			}
			continue
		}
		seen[key] = len(res.Technologies)
		res.Technologies = append(res.Technologies, tech)
	}
	sortTechnologies(res.Technologies)
	return res
}

// hitLiteral 判断某条正文类模式的字面量是否出现在正文里（任一出现即通过）。
func hitLiteral(mr *MatchRule, hits, hitsCI []bool) bool {
	table := hits
	if mr.literalCI {
		table = hitsCI
	}
	for _, id := range mr.bodyLiterals {
		if int(id) < len(table) && table[id] {
			return true
		}
	}
	return false
}

// containsLiteral 在短素材（响应头、Cookie 值、脚本地址…）上判断字面量是否存在。
func containsLiteral(text string, literals []string, ci bool) bool {
	if ci {
		text = foldASCII(text)
	}
	for _, lit := range literals {
		if strings.Contains(text, lit) {
			return true
		}
	}
	return false
}

// matchRule 取规则里第一条命中的 match 生成技术栈条目。
//
// hits / hitsCI 是正文类字面量的命中位图，可为 nil（正文为空时）。
func (m *Matcher) matchRule(rule *Rule, mat material, hits, hitsCI []bool) (Technology, bool) {
	if rule == nil {
		return Technology{}, false
	}
	for i := range rule.Match {
		mr := &rule.Match[i]
		text, ok := mat.source(mr)
		if !ok {
			continue
		}
		// 没有正则的模式是「存在性判据」：素材在就够了（Wappalyzer 里「只要有这个
		// Cookie / 这个响应头」的写法）。必须在 text=="" 之前判，否则值为空的
		// Cookie（如 TawkConnectionTime=）会被当成素材缺失而漏掉。
		if mr.re == nil {
			return Technology{
				Name:       rule.Name,
				Category:   rule.Category,
				CPE:        rule.CPE,
				Confidence: mr.confidenceFor(rule),
				RuleID:     rule.ID,
			}, true
		}
		if text == "" {
			continue
		}
		// 廉价预筛：模式里必然出现的字面量都不在素材里，就没必要跑正则。
		if len(mr.bodyLiterals) > 0 {
			if !hitLiteral(mr, hits, hitsCI) {
				continue
			}
		} else if len(mr.literals) > 0 && !containsLiteral(text, mr.literals, mr.literalCI) {
			continue
		}
		groups := &groupRef{match: mr.re.FindStringSubmatch(text), names: mr.names}
		if groups.match == nil {
			continue
		}
		version, _ := expandTemplate(mr.Version, groups)
		cpe, _ := expandTemplate(mr.CPE, groups)
		if cpe == "" {
			cpe = rule.CPE
		}
		return Technology{
			Name:       rule.Name,
			Version:    strings.TrimSpace(version),
			Category:   rule.Category,
			CPE:        strings.TrimSpace(cpe),
			Confidence: mr.confidenceFor(rule),
			RuleID:     rule.ID,
		}, true
	}
	return Technology{}, false
}

// material 是从一次 HTTP 响应里抽出的匹配素材。
type material struct {
	headerBlock string
	headers     map[string]string // 键名统一小写
	body        string
	title       string
	faviconHash string
	url         string
	// scriptSrc 是页面引用的脚本地址，多条以换行拼接——拼成一个字符串既省一次分配，
	// 也让「字面量预筛」只要扫一遍。
	scriptSrc string
	// scripts 是页面内联脚本的内容，同样按换行拼接。
	scripts string
	// metas 是 <meta> 的 name/property/http-equiv（小写）到 content 的映射。
	metas map[string]string
	// cookies 是 Set-Cookie 名到值的映射。
	cookies map[string]string
}

func newMaterial(resp Response) material {
	mat := material{
		headers: make(map[string]string, len(resp.Headers)),
		metas:   make(map[string]string, 8),
		cookies: make(map[string]string, 8),
		url:     resp.RequestURL,
	}

	keys := make([]string, 0, len(resp.Headers))
	for k := range resp.Headers {
		lk := strings.ToLower(strings.TrimSpace(k))
		if lk == "" {
			continue
		}
		mat.headers[lk] = resp.Headers[k]
		keys = append(keys, lk)
	}
	// 固定顺序拼接响应头块，保证同一响应多次匹配结果稳定。
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(strings.TrimSpace(mat.headers[k]))
		sb.WriteString("\r\n")
	}
	mat.headerBlock = sb.String()

	if body := resp.Body; len(body) > 0 {
		if len(body) > maxBodyBytes {
			body = body[:maxBodyBytes]
		}
		mat.body = string(body)
		mat.extractHTML(body)
	}
	for _, c := range resp.Cookies {
		name, value := splitCookie(c)
		if name == "" {
			continue
		}
		if _, dup := mat.cookies[name]; !dup {
			mat.cookies[name] = value
		}
	}
	if len(resp.Favicon) > 0 {
		mat.faviconHash = faviconHash(resp.Favicon)
	}
	return mat
}

// extractHTML 从正文里抽取标题、脚本地址与元信息。
func (mat *material) extractHTML(body []byte) {
	if m := titleRe.FindSubmatch(body); len(m) > 1 {
		t := html.UnescapeString(strings.TrimSpace(string(m[1])))
		mat.title = strings.Join(strings.Fields(t), " ")
	}

	var sb strings.Builder
	count := 0
	for _, m := range scriptBlockRe.FindAllSubmatch(body, -1) {
		attrs := m[1]
		// 带 src 的是外部脚本，归 scriptSrc 管；这里只收内联脚本。
		if scriptSrcAttrRe.Match(attrs) {
			continue
		}
		content := strings.TrimSpace(string(m[2]))
		if content == "" {
			continue
		}
		sb.WriteString(content)
		sb.WriteByte('\n')
		if count++; count >= maxInlineScripts {
			break
		}
	}
	mat.scripts = sb.String()

	mat.scriptSrc = collectScriptSrc(body)

	for _, tag := range metaTagRe.FindAll(body, -1) {
		name := metaNameRe.FindSubmatch(tag)
		if len(name) < 2 {
			continue
		}
		content := metaContentRe.FindSubmatch(tag)
		value := ""
		if len(content) > 1 {
			value = html.UnescapeString(string(content[1]))
		}
		key := strings.ToLower(strings.TrimSpace(string(name[1])))
		if key == "" {
			continue
		}
		if _, dup := mat.metas[key]; !dup {
			mat.metas[key] = value
		}
	}
}

// collectScriptSrc 汇总页面引用的全部脚本地址。
func collectScriptSrc(body []byte) string {
	var sb strings.Builder
	count := 0
	for _, m := range scriptSrcRe.FindAllSubmatch(body, -1) {
		sb.Write(m[1])
		sb.WriteByte('\n')
		if count++; count >= maxScriptURLs {
			return sb.String()
		}
	}
	// SPA 打包器（Vite/SvelteKit/Next…）用 modulepreload 加载入口脚本，不留 <script src>，
	// 漏掉它等于漏掉了整个前端框架的判据来源。
	for _, tag := range linkTagRe.FindAll(body, -1) {
		if count >= maxScriptURLs {
			break
		}
		rel := relRe.FindSubmatch(tag)
		if len(rel) < 2 {
			continue
		}
		r := strings.ToLower(string(rel[1]))
		if r != "modulepreload" && r != "preload" {
			continue
		}
		href := hrefRe.FindSubmatch(tag)
		if len(href) < 2 {
			continue
		}
		sb.Write(href[1])
		sb.WriteByte('\n')
		count++
	}
	return sb.String()
}

// splitCookie 从一条 Set-Cookie 里取出 Cookie 名与值。
func splitCookie(raw string) (string, string) {
	seg := raw
	if i := strings.IndexByte(seg, ';'); i >= 0 {
		seg = seg[:i]
	}
	seg = strings.TrimSpace(seg)
	if seg == "" {
		return "", ""
	}
	if i := strings.IndexByte(seg, '='); i >= 0 {
		return strings.TrimSpace(seg[:i]), strings.TrimSpace(seg[i+1:])
	}
	return seg, ""
}

// source 按 match 的 source 取出待匹配文本，ok 为 false 表示该类素材不存在。
func (mat material) source(mr *MatchRule) (string, bool) {
	switch mr.Source {
	case SourceHeader:
		if strings.TrimSpace(mr.Header) == "" {
			return mat.headerBlock, mat.headerBlock != ""
		}
		v, ok := mat.headers[strings.ToLower(strings.TrimSpace(mr.Header))]
		return v, ok
	case SourceBody:
		return mat.body, mat.body != ""
	case SourceTitle:
		return mat.title, mat.title != ""
	case SourceFavicon:
		return mat.faviconHash, mat.faviconHash != ""
	case SourceScriptSrc:
		return mat.scriptSrc, mat.scriptSrc != ""
	case SourceScripts:
		return mat.scripts, mat.scripts != ""
	case SourceCSS, SourceHTML, SourceText:
		return mat.body, mat.body != ""
	case SourceURL:
		return mat.url, mat.url != ""
	case SourceMeta:
		v, ok := mat.metas[strings.ToLower(strings.TrimSpace(mr.Key))]
		return v, ok
	case SourceCookies:
		v, ok := mat.cookies[strings.TrimSpace(mr.Key)]
		return v, ok
	default:
		return "", false
	}
}

// faviconHash 计算 favicon 的 mmh3 哈希（有符号十进制字符串）。
//
// 算法与业界通用实现一致：先 base64 编码（每 76 字符插入换行并在末尾补一个换行），
// 再对结果取 murmur3 x32 哈希并按 int32 解读。这样得到的哈希才能与公开的 favicon
// 指纹库对齐。
func faviconHash(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	sb.Grow(len(encoded) + len(encoded)/76 + 1)
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		sb.WriteString(encoded[i:end])
		sb.WriteByte('\n')
	}
	return strconv.FormatInt(int64(int32(murmur3.Sum32([]byte(sb.String())))), 10)
}

// groupRef 提供按名字或序号读取捕获组的能力。
//
// match 是 regexp.FindStringSubmatch 的结果：下标 i 对应第 i 个子匹配（0 为整体匹配），
// names 是该正则的 SubexpNames，两者下标一一对应。
type groupRef struct {
	match []string
	names []string
}

func (g *groupRef) byName(name string) string {
	if g == nil || name == "" {
		return ""
	}
	for i, n := range g.names {
		if n == name && i < len(g.match) {
			return g.match[i]
		}
	}
	return ""
}

func (g *groupRef) byNumber(num string) string {
	if g == nil || num == "" {
		return ""
	}
	n := 0
	for i := 0; i < len(num); i++ {
		if num[i] < '0' || num[i] > '9' {
			return ""
		}
		n = n*10 + int(num[i]-'0')
	}
	if n < len(g.match) {
		return g.match[n]
	}
	return ""
}

// expandTemplate 展开取值模板，支持 $0..$9、$name 与 ${name}。
func expandTemplate(tpl string, groups *groupRef) (string, []string) {
	if tpl == "" {
		return "", nil
	}
	var sb strings.Builder
	var used []string
	for i := 0; i < len(tpl); {
		if tpl[i] != '$' {
			sb.WriteByte(tpl[i])
			i++
			continue
		}
		if i+1 >= len(tpl) {
			sb.WriteByte('$')
			break
		}
		next := tpl[i+1]
		switch {
		case next == '{':
			end := strings.IndexByte(tpl[i+2:], '}')
			if end < 0 {
				sb.WriteByte('$')
				i++
				continue
			}
			name := tpl[i+2 : i+2+end]
			sb.WriteString(groups.byName(name))
			used = append(used, name)
			i += end + 3
		case next >= '0' && next <= '9':
			j := i + 1
			for j < len(tpl) && tpl[j] >= '0' && tpl[j] <= '9' {
				j++
			}
			num := tpl[i+1 : j]
			sb.WriteString(groups.byNumber(num))
			used = append(used, num)
			i = j
		case isNameByte(next):
			j := i + 1
			for j < len(tpl) && isNameByte(tpl[j]) {
				j++
			}
			name := tpl[i+1 : j]
			sb.WriteString(groups.byName(name))
			used = append(used, name)
			i = j
		default:
			sb.WriteByte('$')
			i++
		}
	}
	return sb.String(), used
}

func isNameByte(c byte) bool {
	return c == '_' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
}
