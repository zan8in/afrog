package nuclei2afrog

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/poc"
	"gopkg.in/yaml.v2"
)

// 本文件把 nuclei 的 http 请求块翻译成 afrog 的 rule：
//   - 请求侧：method / path / headers / body / raw
//   - 匹配侧：matchers → 单条 CEL 布尔表达式
//   - 抽取侧：extractors → poc.Extractors
//
// 语义依据（均以 nuclei 源码为准）：
//   - matchers-condition 缺省 OR，显式 and 才是 AND（pkg/operators/operators.go:233）
//   - matcher 的 condition 缺省 OR，显式 and 才是 AND（pkg/operators/matchers/compile.go）
//   - status / size matcher 只支持 OR，condition 被忽略（matchers/match.go:25-54）
//   - part 缺省 body，header == all_headers，part=="all" 是 body+header 拼接（protocols/http/operators.go:90-112）
//   - DSL matcher 完全绕过 part（protocols/http/operators.go:44-45）
//   - word matcher 的 words 会先做模板渲染（matchers/match.go:74）

// ---------------- 命中区域（part） ----------------

type partView struct {
	expr string
	kind vkind
	// guard 非空时表示该视图有「键可能不存在」的前置条件（如响应头）。
	// 必须在取值表达式外用 `&&` 兜住：否则整条 CEL 会求值报 no such key，
	// 而不是像 nuclei 那样「取到空串即不命中」。
	guard string
}

// reMultiResponsePart 命中多响应引用（body_2 / content_type_3 / location_2 ...）。
var reMultiResponsePart = regexp.MustCompile(`_\d+$`)

// nonHeaderParts 是 nuclei part 里「不是响应头」的固定字段。
// 依据 pkg/protocols/http/operators.go:125-139 的 responseToDSLMap：
// 除这些键外，其余键都来自响应头（头名转小写、`-` 换成 `_`）或 Cookie 名。
var nonHeaderParts = map[string]bool{
	"all":            true, // body + all_headers 的拼接，afrog 无等价视图
	"host":           true,
	"type":           true,
	"matched":        true,
	"request":        true,
	"status_code":    true,
	"duration":       true,
	"content_length": true,
	"ip":             true,
	"path":           true,
	"template-id":    true,
	"template-info":  true,
	"template-path":  true,
}

// resolvePart 把 nuclei 的 matcher/extractor part 解析成 afrog 的 CEL 视图。
// 返回 false 表示 afrog 没有对应视图（如 part=all / interactsh_* / 多响应变量）。
func resolvePart(part string) (partView, bool) {
	p := strings.ToLower(strings.TrimSpace(part))
	switch p {
	case "", "body":
		return partView{expr: "response.body", kind: kBytes}, true
	case "header", "all_headers":
		return partView{expr: "response.raw_header", kind: kBytes}, true
	case "raw":
		return partView{expr: "response.raw", kind: kBytes}, true
	case "content_type":
		return partView{expr: "response.content_type", kind: kString}, true
	case "response":
		// nuclei 的 part=response 取完整原始响应（含状态行与响应头）
		return partView{expr: "response.raw", kind: kBytes}, true
	}
	if nonHeaderParts[p] || reMultiResponsePart.MatchString(p) {
		return partView{}, false
	}
	// 其余 part 在 nuclei 里就是某个响应头：头名小写并把 `-` 换成 `_`，
	// 而 afrog 的 response.headers 键是「小写 + 保留 -」，所以把 `_` 换回 `-`。
	key := celStringLiteral(strings.ReplaceAll(p, "_", "-"))
	return partView{
		expr:  "response.headers[" + key + "]",
		kind:  kString,
		guard: key + " in response.headers",
	}, true
}

// guardExpr 为带前置条件的取值视图包上存在性判断，使其在键缺失时返回 false。
func guardExpr(pv partView, expr string) string {
	if pv.guard == "" {
		return expr
	}
	return pv.guard + " && (" + expr + ")"
}

// ---------------- 请求级模板变量 ----------------

// celViewVar 把 nuclei 的请求级变量映射成 afrog CEL 表达式。
// 语义对照见 docs/plan/afrog-nuclei-template-conversion-spec.md §8。
var celViewVar = map[string]string{
	"baseurl":  `(request.url.scheme + "://" + request.url.host + request.url.path)`,
	"rooturl":  `(request.url.scheme + "://" + request.url.host)`,
	"hostname": "request.url.host",
	"host":     "request.url.domain",
	"port":     "request.url.port",
	"path":     "request.url.path",
	"query":    "request.url.query",
	"scheme":   "request.url.scheme",
}

var reTemplateVar = regexp.MustCompile(`\{\{([^{}]*)\}\}`)

// tplSeg 是模板文本切分后的片段：普通文本，或一个 {{...}} 变量（inner 为花括号内容）。
type tplSeg struct {
	text  string
	inner string
	isVar bool
}

// splitTemplates 按「最外层花括号配对」把含 {{...}} 的文本切成片段。
// 用配对计数而不是正则，才能正确处理 {{md5({{num}})}} 这类嵌套写法：
// 正则的 `[^{}]*` 会在这里把 `{{num}}` 单独当作变量，丢掉外层函数。
func splitTemplates(s string) []tplSeg {
	var out []tplSeg
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			out = append(out, tplSeg{text: lit.String()})
			lit.Reset()
		}
	}
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == '{' && i+1 < len(s) && s[i+1] == '{' {
			if depth == 0 {
				flush()
				start = i + 2
			}
			depth++
			i++
			continue
		}
		if s[i] == '}' && i+1 < len(s) && s[i+1] == '}' && depth > 0 {
			depth--
			if depth == 0 {
				out = append(out, tplSeg{inner: s[start:i], isVar: true})
			}
			i++
			continue
		}
		if depth == 0 {
			lit.WriteByte(s[i])
		}
	}
	if depth > 0 { // 花括号未闭合：原样当普通文本
		lit.WriteString(s[start-2:])
	}
	flush()
	return out
}

// renderToCEL 把含 {{...}} 的 nuclei 文本翻译成 CEL 字符串表达式。
// vars 是运行期一定存在的变量（小写名 → afrog CEL 里的实际标识符），
// 即 set / constants / payloads 提供的名字。
// unresolved 非空表示存在无法映射的变量，调用方应判定为 gap。
func renderToCEL(text string, vars map[string]string) (string, []string) {
	if !strings.Contains(text, "{{") {
		return celStringLiteral(text), nil
	}
	var parts []string
	var unresolved []string
	for _, seg := range splitTemplates(text) {
		if !seg.isVar {
			parts = append(parts, celStringLiteral(seg.text))
			continue
		}
		expr, ok := resolveTemplateVar(seg.inner, vars)
		if !ok {
			unresolved = append(unresolved, strings.TrimSpace(seg.inner))
			continue
		}
		parts = append(parts, expr)
	}
	if len(unresolved) > 0 {
		return "", unresolved
	}
	switch len(parts) {
	case 0:
		return celStringLiteral(""), nil
	case 1:
		return parts[0], nil
	default:
		return "(" + strings.Join(parts, " + ") + ")", nil
	}
}

// resolveTemplateVar 把一个 {{...}} 变量翻成 CEL 字符串表达式。
// 覆盖三类写法：内置请求变量（{{BaseURL}}）、set/brute 提供的普通变量（{{num}}）、
// 表达式型占位符（{{md5(num)}}、{{md5({{num}})}}、{{rand_base(5)}}）。
func resolveTemplateVar(inner string, vars map[string]string) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(inner))
	if expr, ok := celViewVar[name]; ok {
		return expr, true
	}
	if rePlainIdent.MatchString(name) {
		if ident := vars[name]; ident != "" {
			// set / payload 变量在 afrog CEL 里就是字符串标识符。
			return "string(" + ident + ")", true
		}
		if strings.HasPrefix(name, "randstr") {
			// nuclei 的 {{randstr}} 既非变量也非函数，求值失败后按字面量参与匹配。
			// 这里按字面量匹配，与 nuclei 的回落行为保持一致。
			return celStringLiteral("{{" + name + "}}"), true
		}
		return "", false
	}
	// 表达式型占位符：必须是函数调用或嵌套占位符，避免把 {{a-b}} 这类
	// 非表达式内容误当成 DSL 运算。
	if !strings.Contains(inner, "(") && !strings.Contains(inner, "{{") {
		return "", false
	}
	expanded, ok := expandInnerVars(inner, vars)
	if !ok {
		return "", false
	}
	node, err := parseDSL(expanded)
	if err != nil {
		return "", false
	}
	for _, id := range dslIdents(node) {
		key := strings.ToLower(strings.TrimSpace(id))
		if vars[key] != "" {
			continue
		}
		if _, ok := viewTable[key]; ok {
			continue
		}
		if _, ok := celViewVar[key]; ok {
			continue
		}
		return "", false
	}
	out, w := emitDSLNode(node)
	if w != nil && w.Gap {
		return "", false
	}
	return toStrExpr(out), true
}

// expandInnerVars 把表达式型占位符内层的 {{var}} 替换成 afrog CEL 里等价的写法，
// 得到可交给 parseDSL 的 nuclei DSL 文本（如 md5({{num}}) → md5(num)）。
func expandInnerVars(inner string, vars map[string]string) (string, bool) {
	if !strings.Contains(inner, "{{") {
		return inner, true
	}
	var b strings.Builder
	for _, seg := range splitTemplates(inner) {
		if !seg.isVar {
			b.WriteString(seg.text)
			continue
		}
		name := strings.ToLower(strings.TrimSpace(seg.inner))
		if rePlainIdent.MatchString(name) && vars[name] != "" {
			b.WriteString(vars[name])
			continue
		}
		return "", false
	}
	return b.String(), true
}

// renderRequestText 渲染请求侧文本（path/body/header/raw）：
//   - nuclei 请求级内置变量换成 afrog 的 CEL 视图（{{BaseURL}} → {{request.url...}}）；
//   - 纯标识符占位符（{{username}} / {{n2a_path}}）原样保留，由 afrog 的 set / brute
//     在运行期替换；
//   - 函数式占位符（{{md5(num)}} / {{rand_base(5)}} / {{to_lower(x)}}）按 afrog CEL
//     语法重写后再保留为占位符，afrog 的 renderCELPlaceholders 会在运行期求值。
func renderRequestText(s string) (string, []Warning) {
	if !strings.Contains(s, "{{") {
		return s, nil
	}
	var warns []Warning
	out := reTemplateVar.ReplaceAllStringFunc(s, func(m string) string {
		inner := strings.TrimSpace(m[2 : len(m)-2])
		name := strings.ToLower(inner)
		if expr, ok := celViewVar[name]; ok {
			return "{{" + expr + "}}"
		}
		if rePlainIdent.MatchString(inner) {
			if strings.HasPrefix(name, "randstr") {
				warns = append(warns, Warning{
					Field:   "request",
					Message: "nuclei 的 {{randstr}} 在 afrog 中不是内置变量，将按字面量发送（请求与匹配两侧保持一致）",
				})
			}
			return m
		}
		if expr, w := translateDSLValue(inner); w == nil || !w.Gap {
			if w != nil {
				w.Field = "request"
				warns = append(warns, *w)
			}
			return "{{" + expr + "}}"
		}
		// 重写失败时保留原样，交由 CEL 编译自校验决定是否降级
		return m
	})
	return out, warns
}

// knownRequestVars 返回请求文本里可以被解析的变量名（小写）。
// 只有这些名字运行期一定存在，其余标识符占位符会让请求原样发出 {{var}}。
func knownRequestVars(tpl *nucleiTemplate, block *nucleiHTTP) map[string]bool {
	known := make(map[string]bool, len(celViewVar)+len(tpl.Variables)+len(tpl.Constants)+len(block.Payloads)+1)
	for k := range celViewVar {
		known[k] = true
	}
	for k := range tpl.Variables {
		known[strings.ToLower(strings.TrimSpace(k))] = true
	}
	for k := range tpl.Constants {
		known[strings.ToLower(strings.TrimSpace(k))] = true
	}
	for k := range block.Payloads {
		known[strings.ToLower(strings.TrimSpace(k))] = true
	}
	known[brutePathVar] = true
	return known
}

// matchVars 返回「小写名 → afrog CEL 里的实际标识符」，供 matcher 内的模板变量求值。
// 这些名字在运行期一定作为字符串变量存在（set 由 UpdateVariableMap 注入，
// brute payload 由 forEachBrutePayload 注入），可直接当 CEL 标识符引用。
// hasBrutePath 表示请求已被拆成 afrog brute（存在 {{n2a_path}} 变量）。
func matchVars(tpl *nucleiTemplate, block *nucleiHTTP, hasBrutePath bool) map[string]string {
	vars := make(map[string]string, len(tpl.Variables)+len(tpl.Constants)+len(block.Payloads)+1)
	for _, src := range []map[string]any{tpl.Constants, tpl.Variables} {
		for k := range src {
			name := strings.TrimSpace(k)
			if name == "" {
				continue
			}
			vars[strings.ToLower(name)] = name
		}
	}
	for k := range block.Payloads {
		name := strings.TrimSpace(k)
		if name == "" {
			continue
		}
		vars[strings.ToLower(name)] = name
	}
	if hasBrutePath {
		vars[brutePathVar] = brutePathVar
	}
	return vars
}

// checkRequestVars 校验请求文本里的标识符占位符都有来源，
// 避免产出「运行期把 {{var}} 原样发出去」的坏请求。
// 表达式占位符（含函数调用）不在此处判定，由 CEL 编译自校验兜底。
func checkRequestVars(fields map[string]string, known map[string]bool) ([]Warning, bool) {
	var warns []Warning
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names)

	ok := true
	reported := make(map[string]bool)
	for _, f := range names {
		for _, m := range reTemplateVar.FindAllStringSubmatch(fields[f], -1) {
			inner := strings.TrimSpace(m[1])
			if inner == "" || !rePlainIdent.MatchString(inner) {
				continue
			}
			lower := strings.ToLower(inner)
			if known[lower] || strings.HasPrefix(lower, "randstr") || reported[lower] {
				continue
			}
			reported[lower] = true
			ok = false
			warns = append(warns, Warning{
				Field:   "request." + f,
				Message: fmt.Sprintf("变量 {{%s}} 既非 nuclei 内置变量，也非 set/brute 提供，运行期会原样发出该占位符", inner),
				Gap:     true,
			})
		}
	}
	return warns, ok
}

// ---------------- 字面量与条件合成 ----------------

// bytesLiteral 生成对任意字节安全的 CEL bytes 字面量（非可打印字节转义为 \xNN）。
func bytesLiteral(raw []byte) string {
	var b strings.Builder
	b.WriteString(`b"`)
	for _, c := range raw {
		switch c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 || c >= 0x7f {
				fmt.Fprintf(&b, `\x%02x`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteString(`"`)
	return b.String()
}

// condOp 把 nuclei 的 condition 字段翻成 CEL 连接符。缺省为 OR。
func condOp(condition string) string {
	if strings.EqualFold(strings.TrimSpace(condition), "and") {
		return " && "
	}
	return " || "
}

// joinExpr 用 op 连接若干子表达式。
// 只有「子表达式最外层的逻辑运算符与 op 不同」时才补括号，因此不再产出 (…) 套 (…) 的冗余写法，
// 同时保证 (a || b) && c 这类必须保留括号的场景语义不变。
func joinExpr(items []string, op string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	parts := make([]string, len(items))
	for i, it := range items {
		if childOp := topLevelOp(it); childOp != "" && childOp != op {
			parts[i] = "(" + it + ")"
		} else {
			parts[i] = it
		}
	}
	return strings.Join(parts, op)
}

// topLevelOp 返回表达式在「括号深度 0」上出现的逻辑运算符（" && " / " || " / " ? "）。
// 返回空串表示顶层没有逻辑运算符，即该表达式优先级一定高于 && / ||（比较、函数调用等）。
// 扫描时跳过字符串/字节字面量，避免把字面量里的 && 当成运算符。
func topLevelOp(expr string) string {
	depth := 0
	for i := 0; i < len(expr); i++ {
		switch c := expr[i]; c {
		case '"', '\'':
			i = skipQuoted(expr, i)
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '?':
			if depth == 0 {
				return " ? "
			}
		case '&', '|':
			if depth == 0 && i+1 < len(expr) && expr[i+1] == c {
				if c == '&' {
					return " && "
				}
				return " || "
			}
		}
	}
	return ""
}

// skipQuoted 返回 s[start] 处字面量的结束引号下标（未闭合时返回末尾）。
func skipQuoted(s string, start int) int {
	quote := s[start]
	for i := start + 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case quote:
			return i
		}
	}
	return len(s) - 1
}

// stripOuterParens 去掉最外层冗余括号。
// 判据是「首个 '(' 的配对 ')' 恰好落在串尾」，即整串被同一对括号完整包裹。
// 此时去掉这层括号一定安全：结果要么作为整条 rule 表达式使用，要么会被 joinExpr
// 依据 topLevelOp 重新补回必要的括号。
func stripOuterParens(expr string) string {
	for {
		s := strings.TrimSpace(expr)
		if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' {
			return s
		}
		depth := 0
		closeAt := -1
	scan:
		for i := 0; i < len(s); i++ {
			switch s[i] {
			case '"', '\'':
				i = skipQuoted(s, i)
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					closeAt = i
					break scan
				}
			}
		}
		if closeAt != len(s)-1 {
			return s
		}
		expr = strings.TrimSpace(s[1 : len(s)-1])
	}
}

// containsStr 生成「字符串 needle 是否命中 target」的 CEL 表达式。
func containsStr(target partView, needleExpr string, ci bool) string {
	if target.kind == kBytes {
		return target.expr + ".bcontains(" + toBytesExpr(emitted{expr: needleExpr, kind: kString}) + ")"
	}
	if ci {
		return target.expr + ".icontains(" + needleExpr + ")"
	}
	return target.expr + ".contains(" + needleExpr + ")"
}

// containsBytes 生成「bytes needle 是否命中 target」的 CEL 表达式。
func containsBytes(target partView, needleExpr string) string {
	if target.kind == kBytes {
		return target.expr + ".bcontains(" + needleExpr + ")"
	}
	return target.expr + ".contains(toUtf8(" + needleExpr + "))"
}

// regexMatch 生成正则匹配表达式（afrog 用 regexp2，nuclei 用 Go RE2）。
func regexMatch(target partView, re string) string {
	if target.kind == kBytes {
		return celStringLiteral(re) + ".bmatches(" + target.expr + ")"
	}
	return celStringLiteral(re) + ".rmatches(" + target.expr + ")"
}

// ---------------- matcher → CEL ----------------

// compileMatchers 把一个 http 块的全部 matcher 编译成单条 CEL 表达式。
// vars 是 matcher 内模板变量可引用的运行期变量（见 matchVars）。
// ok=false 表示存在无法映射的 matcher，调用方应判定为 gap。
func compileMatchers(block *nucleiHTTP, vars map[string]string) (string, []Warning, bool) {
	if len(block.Matchers) == 0 {
		return "", []Warning{{
			Field:   "matchers",
			Message: "http 块没有任何 matcher，afrog 的 rule 必须有布尔表达式",
			Gap:     true,
		}}, false
	}

	items := make([]string, 0, len(block.Matchers))
	var warns []Warning
	for i := range block.Matchers {
		expr, w, ok := compileMatcher(&block.Matchers[i], vars)
		warns = append(warns, w...)
		if !ok {
			return "", warns, false
		}
		items = append(items, expr)
	}
	return joinExpr(items, condOp(block.MatchersCondition)), warns, true
}

// compileMatcher 把单个 matcher 编译成 CEL 布尔表达式。
// vars 是 matcher 内模板变量可引用的运行期变量（见 matchVars）。
func compileMatcher(m *nucleiMatcher, vars map[string]string) (string, []Warning, bool) {
	typ := strings.ToLower(strings.TrimSpace(m.Type))
	var (
		expr  string
		warns []Warning
	)

	gap := func(format string, a ...any) (string, []Warning, bool) {
		warns = append(warns, Warning{
			Field:   "matchers." + typ,
			Message: fmt.Sprintf(format, a...),
			Gap:     true,
		})
		return "", warns, false
	}

	switch typ {
	case "status":
		if len(m.Status) == 0 {
			return gap("status matcher 未给出状态码")
		}
		items := make([]string, 0, len(m.Status))
		for _, s := range m.Status {
			if s < 100 || s > 999 {
				warns = append(warns, Warning{
					Field:   "matchers.status",
					Message: fmt.Sprintf("状态码 %d 不是 3 位，afrog 校验器会拒绝", s),
				})
			}
			items = append(items, fmt.Sprintf("response.status == %d", s))
		}
		expr = joinExpr(items, " || ")

	case "size":
		if len(m.Size) == 0 {
			return gap("size matcher 未给出长度")
		}
		pv, ok := resolvePart(m.Part)
		if !ok {
			return gap("size matcher 的 part=%q 在 afrog 中无对应视图", m.Part)
		}
		items := make([]string, 0, len(m.Size))
		for _, n := range m.Size {
			items = append(items, guardExpr(pv, fmt.Sprintf("length(%s) == %d", pv.expr, n)))
		}
		expr = joinExpr(items, " || ")

	case "word", "words":
		if len(m.Words) == 0 {
			return gap("word matcher 未给出 words")
		}
		pv, ok := resolvePart(m.Part)
		if !ok {
			return gap("word matcher 的 part=%q 在 afrog 中无对应视图", m.Part)
		}
		hexEncoded := strings.EqualFold(strings.TrimSpace(m.Encoding), "hex")
		items := make([]string, 0, len(m.Words))
		for _, w := range m.Words {
			switch {
			case hexEncoded:
				raw, err := hex.DecodeString(strings.TrimSpace(w))
				if err != nil {
					return gap("word matcher 的 hex 编码 %q 解码失败", w)
				}
				items = append(items, guardExpr(pv, containsBytes(pv, bytesLiteral(raw))))
			case strings.Contains(w, "{{"):
				ne, unresolved := renderToCEL(w, vars)
				if len(unresolved) > 0 {
					return gap("words 中的模板变量 {{%s}} 无法映射为 CEL", strings.Join(unresolved, ","))
				}
				items = append(items, guardExpr(pv, containsStr(pv, ne, m.CaseInsensitive)))
			default:
				items = append(items, guardExpr(pv, containsStr(pv, celStringLiteral(w), m.CaseInsensitive)))
			}
		}
		expr = joinExpr(items, condOp(m.Condition))

	case "regex":
		if len(m.Regex) == 0 {
			return gap("regex matcher 未给出 regex")
		}
		pv, ok := resolvePart(m.Part)
		if !ok {
			return gap("regex matcher 的 part=%q 在 afrog 中无对应视图", m.Part)
		}
		items := make([]string, 0, len(m.Regex))
		for _, re := range m.Regex {
			if strings.Contains(re, "{{") {
				return gap("regex %q 含模板变量，afrog 的 bmatches/rmatches 只接受字面量正则", re)
			}
			items = append(items, guardExpr(pv, regexMatch(pv, re)))
		}
		expr = joinExpr(items, condOp(m.Condition))

	case "binary":
		if len(m.Binary) == 0 {
			return gap("binary matcher 未给出 binary")
		}
		pv, ok := resolvePart(m.Part)
		if !ok {
			return gap("binary matcher 的 part=%q 在 afrog 中无对应视图", m.Part)
		}
		items := make([]string, 0, len(m.Binary))
		for _, s := range m.Binary {
			raw, err := hex.DecodeString(strings.TrimSpace(s))
			if err != nil {
				return gap("binary matcher 的 %q 不是合法 hex", s)
			}
			items = append(items, guardExpr(pv, containsBytes(pv, bytesLiteral(raw))))
		}
		expr = joinExpr(items, condOp(m.Condition))

	case "dsl":
		if len(m.DSL) == 0 {
			return gap("dsl matcher 未给出 dsl")
		}
		items := make([]string, 0, len(m.DSL))
		for _, d := range m.DSL {
			out, w := translateDSL(d)
			if w != nil {
				warns = append(warns, *w)
				if w.Gap {
					return "", warns, false
				}
			}
			// DSL 翻译器为每个运算符节点补了括号（如 (response.status == 200)）。
			// 每条 dsl 都是完整子表达式，这里先剥掉各自最外层冗余括号，
			// 再由 joinExpr 依据「顶层运算符是否与连接符相同」决定是否补回，
			// 从而得到 a && b && c 这样的扁平写法。
			items = append(items, stripOuterParens(out))
		}
		expr = stripOuterParens(joinExpr(items, condOp(m.Condition)))

	default:
		return gap("matcher 类型 %q 无法映射到 afrog CEL", m.Type)
	}

	if m.Negative {
		expr = "!(" + expr + ")"
	}
	return expr, warns, true
}

// ---------------- extractor → poc.Extractors ----------------

var reCelIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// translateExtractors 把一个 http 块的 extractor 列表翻成 afrog 的类型化提取器。
// reserved 里是已被占用的变量名（如 set 变量），自动命名时会避开。
func translateExtractors(list []nucleiExtractor, reserved map[string]bool) ([]poc.Extractors, []Warning, bool) {
	out := make([]poc.Extractors, 0, len(list))
	var warns []Warning
	taken := make(map[string]bool, len(list)+len(reserved))
	for k := range reserved {
		taken[k] = true
	}
	auto := 0
	autoName := func() string {
		for {
			n := fmt.Sprintf("n2a_ext%d", auto)
			auto++
			if !taken[n] {
				taken[n] = true
				return n
			}
		}
	}
	for i := range list {
		e := &list[i]
		name := strings.TrimSpace(e.Name)
		if name == "" || !reCelIdent.MatchString(name) || taken[name] {
			// nuclei 的 extractor name 是可选字段，afrog 则必填且必须是合法 CEL 标识符。
			// 未命名 / 名字非法 / 与既有变量重名时自动改名，语义不变（该值本就无外部引用）。
			renamed := autoName()
			warns = append(warns, Warning{
				Field:   "extractors",
				Message: fmt.Sprintf("原 extractor 名字 %q 不可用，已自动命名为 %q", e.Name, renamed),
			})
			name = renamed
		} else {
			taken[name] = true
		}
		typ := strings.ToLower(strings.TrimSpace(e.Type))
		switch typ {
		case "regex":
			if len(e.Regex) == 0 {
				warns = append(warns, Warning{
					Field:   "extractors",
					Message: fmt.Sprintf("extractor %q: regex 类型但缺少 regex", name),
					Gap:     true,
				})
				return nil, warns, false
			}
			part, note, ok := extractorPart(e.Part)
			if !ok {
				warns = append(warns, Warning{
					Field:   "extractors",
					Message: fmt.Sprintf("extractor %q: part=%q 在 afrog 中无对应取值来源", name, e.Part),
					Gap:     true,
				})
				return nil, warns, false
			}
			if note != "" {
				warns = append(warns, Warning{Field: "extractors", Message: fmt.Sprintf("extractor %q: %s", name, note)})
			}
			item := poc.Extractors{
				Name:  name,
				Type:  "regex",
				Part:  part,
				Regex: regexAlternation(e.Regex),
			}
			if e.Group > 0 {
				item.Group = strconv.Itoa(e.Group)
			}
			if len(e.Regex) > 1 {
				warns = append(warns, Warning{
					Field:   "extractors",
					Message: fmt.Sprintf("extractor %q: %d 条 regex 已合并为一条轮换（结果集合语义一致）", name, len(e.Regex)),
				})
			}
			out = append(out, item)

		case "kval":
			if len(e.KVal) == 0 {
				warns = append(warns, Warning{
					Field:   "extractors",
					Message: fmt.Sprintf("extractor %q: kval 类型但缺少 kval", name),
					Gap:     true,
				})
				return nil, warns, false
			}
			if len(e.KVal) > 1 {
				warns = append(warns, Warning{
					Field:   "extractors",
					Message: fmt.Sprintf("extractor %q: 含 %d 个 kval 键，afrog 每个提取器只支持一个", name, len(e.KVal)),
					Gap:     true,
				})
				return nil, warns, false
			}
			// nuclei 的 kval 是在归一化后的响应映射里按键取值的字典查找，
			// afrog 的 kval 以响应头为主，语义最接近。
			if p := strings.ToLower(strings.TrimSpace(e.Part)); p != "" && p != "header" && p != "all_headers" {
				warns = append(warns, Warning{
					Field:   "extractors",
					Message: fmt.Sprintf("extractor %q: nuclei kval 的 part=%q 与 afrog 的响应头查找语义不完全一致", name, e.Part),
				})
			}
			out = append(out, poc.Extractors{
				Name: name,
				Type: "kval",
				Part: "header",
				Key:  strings.TrimSpace(e.KVal[0]),
			})

		case "json":
			if len(e.JSON) == 0 {
				warns = append(warns, Warning{
					Field:   "extractors",
					Message: fmt.Sprintf("extractor %q: json 类型但缺少 json", name),
					Gap:     true,
				})
				return nil, warns, false
			}
			part, note, ok := extractorPart(e.Part)
			if !ok {
				warns = append(warns, Warning{
					Field:   "extractors",
					Message: fmt.Sprintf("extractor %q: part=%q 在 afrog 中无对应取值来源", name, e.Part),
					Gap:     true,
				})
				return nil, warns, false
			}
			if note != "" {
				warns = append(warns, Warning{Field: "extractors", Message: fmt.Sprintf("extractor %q: %s", name, note)})
			}
			// nuclei 一个 extractor 可挂多条 json 路径，afrog 每个提取器只支持一条：
			// 拆成多个提取器（首条沿用原名，其余自动命名），提取结果集合语义一致。
			for i, path := range e.JSON {
				item := poc.Extractors{Name: name, Type: "json", Part: part, Path: strings.TrimSpace(path)}
				if i > 0 {
					item.Name = autoName()
					warns = append(warns, Warning{
						Field:   "extractors",
						Message: fmt.Sprintf("extractor %q: 第 %d 条 json 路径已拆分为独立提取器 %q", name, i+1, item.Name),
					})
				}
				out = append(out, item)
			}

		case "dsl":
			if len(e.DSL) == 0 {
				warns = append(warns, Warning{
					Field:   "extractors",
					Message: fmt.Sprintf("extractor %q: dsl 类型但缺少 dsl", name),
					Gap:     true,
				})
				return nil, warns, false
			}
			// 同 json：多条 dsl 拆成多个提取器。
			for i, d := range e.DSL {
				// afrog 没有 DNS CNAME 概念（nuclei 的 cname 来自拨号期 DNS 记录），
				// takeover 模板常以 cname 作为报告字段，丢弃该提取器不影响检出。
				if isCnameDSL(d) {
					warns = append(warns, Warning{
						Field:   "extractors",
						Message: fmt.Sprintf("extractor %q: dsl %q 依赖 DNS CNAME，afrog 无对应视图，已丢弃该提取器", name, strings.TrimSpace(d)),
					})
					continue
				}
				val, w := translateDSLValue(d)
				if w != nil {
					warns = append(warns, *w)
					return nil, warns, false
				}
				item := poc.Extractors{Name: name, Type: "cel", Value: val}
				if i > 0 {
					item.Name = autoName()
					warns = append(warns, Warning{
						Field:   "extractors",
						Message: fmt.Sprintf("extractor %q: 第 %d 条 dsl 已拆分为独立提取器 %q", name, i+1, item.Name),
					})
				}
				out = append(out, item)
			}

		default:
			warns = append(warns, Warning{
				Field:   "extractors",
				Message: fmt.Sprintf("extractor 类型 %q 无法映射到 afrog", e.Type),
				Gap:     true,
			})
			return nil, warns, false
		}
	}
	return out, warns, true
}

// extractorPart 把 nuclei extractor 的 part 翻成 afrog 的取值来源。
// 第二个返回值非空时表示做了语义放宽（如单个响应头退化为响应头全文）。
// 返回 false 表示 afrog 没有对应来源（part=all / 多响应 _N 等）。
func extractorPart(part string) (string, string, bool) {
	p := strings.ToLower(strings.TrimSpace(part))
	switch p {
	case "", "body":
		return "", "", true // afrog 缺省即 body
	case "header", "all_headers":
		return "header", "", true
	case "raw":
		return "raw", "", true
	case "response":
		// nuclei 的 part=response 即完整原始响应
		return "raw", "", true
	case "status_code":
		return "status", "", true
	}
	if nonHeaderParts[p] || reMultiResponsePart.MatchString(p) {
		return "", "", false
	}
	// 其余 part 在 nuclei 里对应某个响应头（或 Cookie 名）。afrog 没有「按单个头取值」
	// 的提取来源，退化为响应头全文：匹配范围是超集，只会多提取、不会漏。
	return "header", fmt.Sprintf("part=%q 在 afrog 中无同名来源，已放宽为响应头全文（只多提取不漏提取）", part), true
}

// regexAlternation 把多条 regex 合并为一条轮换表达式（保持「任一命中」语义）。
func regexAlternation(list []string) string {
	if len(list) == 1 {
		return list[0]
	}
	parts := make([]string, 0, len(list))
	for _, re := range list {
		parts = append(parts, "(?:"+re+")")
	}
	return strings.Join(parts, "|")
}

// translateDSLValue 把一条 nuclei DSL 表达式翻成 CEL 值表达式（不要求结果是 bool）。
// 返回的 Warning 可能是非 Gap 的提示（如字符集差异），此时表达式仍然可用。
func translateDSLValue(s string) (string, *Warning) {
	node, err := parseDSL(s)
	if err != nil {
		return "", &Warning{Message: fmt.Sprintf("DSL 解析失败：%s（%v）", strings.TrimSpace(s), err), Gap: true}
	}
	out, w := emitDSLNode(node)
	if w != nil && w.Gap {
		return "", w
	}
	return toStrExpr(out), w
}

// isCnameDSL 判断一条 dsl 是否只是对 nuclei 的 cname 变量求值（如 takeover 模板的
// `dsl: [cname]`）。afrog 没有 DNS CNAME 视图，这类提取器只能丢弃。
func isCnameDSL(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "cname")
}

// ---------------- 请求 ----------------

const brutePathVar = "n2a_path"

// buildRequest 把一个 nuclei http 块翻成 afrog 的 rule request。
// brutePaths 非空时表示多 path，需要落成 afrog brute。
// known 是运行期一定存在的变量名（见 knownRequestVars），用于校验占位符是否可解析。
func buildRequest(block *nucleiHTTP, known map[string]bool) (poc.RuleRequest, []string, []Warning, bool) {
	var warns []Warning

	req := poc.RuleRequest{FollowRedirects: block.Redirects}

	if len(block.Raw) > 0 {
		raw, w := renderRequestText(block.Raw[0])
		warns = append(warns, w...)
		req.Raw = raw
		if len(block.Raw) > 1 {
			warns = append(warns, Warning{
				Field:   "request.raw",
				Message: fmt.Sprintf("http 块含 %d 条 raw 请求，afrog 每个 rule 只发一条", len(block.Raw)),
				Gap:     true,
			})
			return req, nil, warns, false
		}
	} else {
		req.Method = strings.ToUpper(strings.TrimSpace(block.Method))
		if req.Method == "" {
			req.Method = "GET"
		}
		if block.HostRedirects {
			warns = append(warns, Warning{
				Field:   "request",
				Message: "host-redirects 在 afrog 中没有对应开关，已忽略",
			})
		}
	}

	if len(block.Headers) > 0 {
		headers := make(map[string]string, len(block.Headers))
		for k, v := range block.Headers {
			hv, w := renderRequestText(v)
			warns = append(warns, w...)
			headers[k] = hv
		}
		req.Headers = headers
	}

	if block.Body != "" {
		body, w := renderRequestText(block.Body)
		warns = append(warns, w...)
		req.Body = body
	}

	if len(block.Raw) > 0 {
		// raw 请求自带 path，不再处理 block.Path
		vw, vok := checkRequestVars(map[string]string{"raw": req.Raw}, known)
		warns = append(warns, vw...)
		return req, nil, warns, vok
	}

	path, brutePaths, w, ok := buildPaths(block.Path)
	warns = append(warns, w...)
	if !ok {
		return req, nil, warns, false
	}
	req.Path = path
	vw, vok := checkRequestVars(reqTextField(req), known)
	warns = append(warns, vw...)
	return req, brutePaths, warns, vok
}

// reqTextField 收集请求里会出现 {{...}} 占位符的字段，供 checkRequestVars 校验。
func reqTextField(req poc.RuleRequest) map[string]string {
	fields := make(map[string]string, len(req.Headers)+4)
	if req.Path != "" {
		fields["path"] = req.Path
	}
	if req.Body != "" {
		fields["body"] = req.Body
	}
	if req.Raw != "" {
		fields["raw"] = req.Raw
	}
	if req.Data != "" {
		fields["data"] = req.Data
	}
	for k, v := range req.Headers {
		fields["headers."+k] = v
	}
	return fields
}

// buildPaths 归一化 nuclei 的 path 列表，返回 rule 的 path 与（多值时的）brute 候选。
func buildPaths(paths []string) (string, []string, []Warning, bool) {
	var warns []Warning
	if len(paths) == 0 {
		warns = append(warns, Warning{
			Field:   "request.path",
			Message: "http 块未给出 path，afrog 侧回落为 /",
		})
		return "/", nil, warns, true
	}

	normalized := make([]string, 0, len(paths))
	for _, p := range paths {
		np, kind, ok := normalizePath(p)
		if !ok {
			warns = append(warns, Warning{
				Field:   "request.path",
				Message: fmt.Sprintf("path %q 含无法映射的模板变量", p),
				Gap:     true,
			})
			return "", nil, warns, false
		}
		if kind != "" {
			warns = append(warns, Warning{Field: "request.path", Message: fmt.Sprintf("path %q：%s", p, kind)})
		}
		normalized = append(normalized, np)
	}
	if len(normalized) == 1 {
		return normalized[0], nil, warns, true
	}
	warns = append(warns, Warning{
		Field:   "request.path",
		Message: fmt.Sprintf("http 块含 %d 条 path，已落成 afrog brute 逐条迭代", len(normalized)),
	})
	return "{{" + brutePathVar + "}}", normalized, warns, true
}

// normalizePath 把单条 nuclei path 归一化为 afrog 的 path 写法。
// 第二个返回值是提示信息，第三个返回值表示是否可转换。
func normalizePath(p string) (string, string, bool) {
	p = strings.TrimSpace(p)
	switch {
	case strings.HasPrefix(p, "{{BaseURL}}"):
		rest := p[len("{{BaseURL}}"):]
		// nuclei 的 {{BaseURL}} 含目标自身路径，afrog 的非 ^ 路径也会拼上目标路径
		return ensureLeadingSlash(rest), "", true
	case strings.HasPrefix(p, "{{RootURL}}"):
		rest := p[len("{{RootURL}}"):]
		// {{RootURL}} 不含目标路径，等价于 afrog 的 ^ 绝对路径
		return "^" + ensureLeadingSlash(rest), "{{RootURL}} 已按绝对路径（^）映射", true
	}
	if strings.Contains(p, "{{") {
		return "", "", false
	}
	if strings.HasPrefix(p, "/") {
		// nuclei 的 path 必须是绝对 URL，裸 /foo 只可能来自 author 的简写，按站点根处理
		return "^" + p, "裸路径已按绝对路径（^）映射", true
	}
	return "/" + p, "无前导 / 的路径已补全", true
}

func ensureLeadingSlash(s string) string {
	if s == "" {
		return "/"
	}
	if !strings.HasPrefix(s, "/") {
		return "/" + s
	}
	return s
}

// ---------------- 顶层 ----------------

// translate 把模板翻译成 afrog PoC（A/B 类）。
// ok=false 表示存在无法机械转换的结构，调用方应降级为 C 类。
func translate(tpl *nucleiTemplate) (poc.Poc, []Warning, bool) {
	out := poc.Poc{
		Id:   tpl.ID,
		Info: buildInfo(tpl),
	}

	var warns []Warning

	set, sw, ok := buildSet(tpl)
	warns = append(warns, sw...)
	if !ok {
		return out, warns, false
	}
	out.Set = set

	// set 变量占用的名字，供 extractor 自动命名避让
	reserved := make(map[string]bool, len(set))
	for _, item := range set {
		if k, ok := item.Key.(string); ok {
			reserved[k] = true
		}
	}

	blocks := tpl.httpBlocks()
	rules := make(poc.RuleMapSlice, 0, len(blocks))
	keys := make([]string, 0, len(blocks))

	for i := range blocks {
		blk := &blocks[i]

		req, brutePaths, w, ok := buildRequest(blk, knownRequestVars(tpl, blk))
		warns = append(warns, w...)
		if !ok {
			return out, warns, false
		}

		expr, w, ok := compileMatchers(blk, matchVars(tpl, blk, len(brutePaths) > 0))
		warns = append(warns, w...)
		if !ok {
			return out, warns, false
		}

		exts, w, ok := translateExtractors(blk.Extractors, reserved)
		warns = append(warns, w...)
		if !ok {
			return out, warns, false
		}

		brute, w, ok := buildBrute(blk, brutePaths)
		warns = append(warns, w...)
		if !ok {
			return out, warns, false
		}

		key := fmt.Sprintf("r%d", i)
		rules = append(rules, poc.RuleMap{Key: key, Value: poc.Rule{
			Brute:      brute,
			Request:    req,
			Expression: expr,
			Extractors: exts,
		}})
		keys = append(keys, key+"()")
	}

	if len(rules) == 0 {
		warns = append(warns, Warning{
			Field:   "http",
			Message: "模板不含可转换的 http 请求块",
			Gap:     true,
		})
		return out, warns, false
	}

	out.Rules = rules
	out.Expression = strings.Join(keys, " || ")
	if len(rules) > 1 {
		warns = append(warns, Warning{
			Field:   "rules",
			Message: fmt.Sprintf("含 %d 个 http 请求块，已拆成 %d 个 rule 并以 || 合并（任一命中即报告）", len(rules), len(rules)),
		})
	}
	return out, warns, true
}

// buildInfo 组装 afrog 的 info 段。
func buildInfo(tpl *nucleiTemplate) poc.Info {
	ci := tpl.Info.Classification
	return poc.Info{
		Name:        strings.TrimSpace(tpl.Info.Name),
		Author:      joinComma(tpl.Info.Author),
		Severity:    normalizeSeverity(tpl.Info.Severity),
		Description: strings.TrimSpace(tpl.Info.Description),
		Reference:   asStringList(tpl.Info.Reference, false),
		Tags:        joinComma(tpl.Info.Tags),
		// nuclei 模板没有「创建时间」字段，用转换当天日期补齐；
		// 格式与 afrog 现有 PoC 一致（YYYY/MM/DD）。
		Created: time.Now().Format("2006/01/02"),
		Classification: poc.Classification{
			CvssMetrics: strings.TrimSpace(ci.CVSSMetrics),
			CvssScore:   ci.CVSSScore,
			CveId:       joinComma(ci.CVEID),
			CweId:       joinComma(ci.CWEID),
		},
	}
}

// setEntry 是一个待落成 afrog set 的变量。
type setEntry struct {
	name string
	expr string
	deps []string // 该表达式引用的其它 set 变量名（小写）
}

// buildSet 把 nuclei 的 variables / constants 落成 afrog 的 set。
//
// afrog 的 set 值走 CustomLib.RunEval（见 checker.applyLegacyExtractor），
// 因此每一项都必须是「求值即得字符串」的 CEL 表达式：
//   - 纯字面量 → CEL 字符串字面量（与 nuclei 的字符串变量语义一致）；
//   - {{rand_int(1,9)}} 这类函数占位符 → 翻译成 CEL 调用并强制转 string；
//   - {{othervar}} 这类变量引用 → 裸标识符，并按依赖关系排序，保证被引用者先求值。
func buildSet(tpl *nucleiTemplate) (yaml.MapSlice, []Warning, bool) {
	var warns []Warning
	if len(tpl.Variables) == 0 && len(tpl.Constants) == 0 {
		return nil, nil, true
	}

	// constants 优先于同名 variables；raws/nameOf 的键统一小写，值保留原始名。
	raws := make(map[string]string, len(tpl.Variables)+len(tpl.Constants))
	nameOf := make(map[string]string, len(tpl.Variables)+len(tpl.Constants))
	for _, src := range []map[string]any{tpl.Constants, tpl.Variables} {
		ks := make([]string, 0, len(src))
		for k := range src {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			lk := strings.ToLower(strings.TrimSpace(k))
			if _, seen := raws[lk]; seen {
				continue
			}
			v, ok := src[k].(string)
			if !ok {
				warns = append(warns, Warning{
					Field:   "set",
					Message: fmt.Sprintf("变量 %q 的值不是字符串，afrog 的 set 只支持字符串表达式", k),
					Gap:     true,
				})
				return nil, warns, false
			}
			raws[lk] = v
			nameOf[lk] = strings.TrimSpace(k)
		}
	}

	names := make([]string, 0, len(raws))
	for lk := range raws {
		names = append(names, lk)
	}
	sort.Strings(names)

	entries := make([]setEntry, 0, len(names))
	for _, lk := range names {
		expr, deps, w, ok := renderSetValue(raws[lk], nameOf)
		if w != nil {
			w.Field = "set"
			w.Message = fmt.Sprintf("变量 %q: %s", nameOf[lk], w.Message)
			warns = append(warns, *w)
			if !ok {
				return nil, warns, false
			}
		}
		entries = append(entries, setEntry{name: nameOf[lk], expr: expr, deps: deps})
	}

	ordered, cycle := topoSortSet(entries)
	if cycle != "" {
		warns = append(warns, Warning{
			Field:   "set",
			Message: fmt.Sprintf("变量 %q 存在循环引用，afrog 的 set 按顺序求值无法表达", cycle),
			Gap:     true,
		})
		return nil, warns, false
	}

	set := make(yaml.MapSlice, 0, len(ordered))
	for _, e := range ordered {
		set = append(set, yaml.MapItem{Key: e.name, Value: e.expr})
	}
	warns = append(warns, Warning{
		Field:   "set",
		Message: fmt.Sprintf("已把 %d 个顶层 variables/constants 落成 afrog set", len(set)),
	})
	return set, warns, true
}

// renderSetValue 把一个 nuclei 变量值翻译成 afrog set 所需的 CEL 字符串表达式。
// nameOf 是「小写名 → 原始名」的映射，用于识别变量引用并保留大小写。
// 返回的 Warning 可能是非 Gap 的提示（如字符集差异），此时表达式依然可用。
func renderSetValue(raw string, nameOf map[string]string) (string, []string, *Warning, bool) {
	if !strings.Contains(raw, "{{") {
		return celStringLiteral(raw), nil, nil, true
	}

	var (
		parts, deps, unresolved []string
		notice                  *Warning
	)
	last := 0
	for _, loc := range reTemplateVar.FindAllStringSubmatchIndex(raw, -1) {
		if loc[0] > last {
			parts = append(parts, celStringLiteral(raw[last:loc[0]]))
		}
		inner := strings.TrimSpace(raw[loc[2]:loc[3]])
		lk := strings.ToLower(inner)
		switch {
		case celViewVar[lk] != "":
			parts = append(parts, celViewVar[lk])
		case rePlainIdent.MatchString(inner) && nameOf[lk] != "":
			// set 项全部规范化为字符串，裸标识符即 string。
			parts = append(parts, nameOf[lk])
			deps = append(deps, lk)
		default:
			node, err := parseDSL(inner)
			if err != nil {
				unresolved = append(unresolved, inner)
				break
			}
			for _, ref := range dslIdents(node) {
				if rk := strings.ToLower(strings.TrimSpace(ref)); nameOf[rk] != "" {
					deps = append(deps, rk)
				}
			}
			out, w := emitDSLNode(node)
			if w != nil {
				if w.Gap {
					return "", nil, w, false
				}
				notice = w
			}
			if out.kind == kUnknown {
				unresolved = append(unresolved, inner)
				break
			}
			s, ok := toCelString(out)
			if !ok {
				return "", nil, &Warning{Message: fmt.Sprintf("占位符 %q 的类型无法转成字符串", inner), Gap: true}, false
			}
			parts = append(parts, s)
		}
		last = loc[1]
	}
	if len(unresolved) > 0 {
		return "", nil, &Warning{
			Message: fmt.Sprintf("引用了 afrog 无法解析的占位符 %s", strings.Join(unresolved, ",")),
			Gap:     true,
		}, false
	}
	if last < len(raw) {
		parts = append(parts, celStringLiteral(raw[last:]))
	}

	switch len(parts) {
	case 0:
		return celStringLiteral(""), nil, notice, true
	case 1:
		return parts[0], deps, notice, true
	default:
		return "(" + strings.Join(parts, " + ") + ")", deps, notice, true
	}
}

// topoSortSet 按依赖关系排序 set 项：被引用的变量必须先求值。
// 同级之间保持字母序以保证输出可复现；存在循环引用时返回该变量名。
func topoSortSet(entries []setEntry) ([]setEntry, string) {
	byName := make(map[string]setEntry, len(entries))
	keys := make([]string, 0, len(entries))
	for _, e := range entries {
		lk := strings.ToLower(e.name)
		byName[lk] = e
		keys = append(keys, lk)
	}
	sort.Strings(keys)

	const (
		visiting = 1
		done     = 2
	)
	state := make(map[string]int, len(entries))
	out := make([]setEntry, 0, len(entries))
	cycle := ""

	var visit func(lk string) bool
	visit = func(lk string) bool {
		switch state[lk] {
		case done:
			return true
		case visiting:
			cycle = byName[lk].name
			return false
		}
		state[lk] = visiting
		e := byName[lk]
		deps := append([]string(nil), e.deps...)
		sort.Strings(deps)
		for _, d := range deps {
			if _, ok := byName[d]; !ok {
				continue
			}
			if !visit(d) {
				return false
			}
		}
		state[lk] = done
		out = append(out, e)
		return true
	}

	for _, lk := range keys {
		if !visit(lk) {
			return nil, cycle
		}
	}
	return out, ""
}

// buildBrute 把 nuclei 的 payloads 与多 path 落成 afrog 的 brute。
// 输出顺序遵循 afrog 惯例：mode（可选）/ commit / continue / 各 payload。
func buildBrute(block *nucleiHTTP, brutePaths []string) (yaml.MapSlice, []Warning, bool) {
	var warns []Warning
	payloads := make(yaml.MapSlice, 0, len(block.Payloads)+1)

	if len(brutePaths) > 0 {
		payloads = append(payloads, yaml.MapItem{Key: brutePathVar, Value: brutePaths})
	}

	if len(block.Payloads) > 0 {
		attack := strings.ToLower(strings.TrimSpace(block.Attack))
		switch attack {
		case "", "clusterbomb", "pitchfork":
		case "batteringram":
			warns = append(warns, Warning{
				Field:   "brute",
				Message: "attack=batteringram 要求各变量同步取同一个 payload 值，afrog 无法表达",
				Gap:     true,
			})
			return nil, warns, false
		default:
			warns = append(warns, Warning{
				Field:   "brute",
				Message: fmt.Sprintf("attack 类型 %q 无法映射到 afrog", block.Attack),
				Gap:     true,
			})
			return nil, warns, false
		}

		keys := make([]string, 0, len(block.Payloads))
		for k := range block.Payloads {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			list, ok := payloadList(block.Payloads[k])
			if !ok || len(list) == 0 {
				warns = append(warns, Warning{
					Field:   "brute",
					Message: fmt.Sprintf("payload %q 不是字符串列表，afrog 的 brute 无法表达", k),
					Gap:     true,
				})
				return nil, warns, false
			}
			payloads = append(payloads, yaml.MapItem{Key: k, Value: list})
		}
	}

	if len(payloads) == 0 {
		return nil, warns, true
	}

	out := make(yaml.MapSlice, 0, len(payloads)+3)
	if strings.EqualFold(strings.TrimSpace(block.Attack), "pitchfork") {
		out = append(out, yaml.MapItem{Key: "mode", Value: "pitchfork"})
	}
	out = append(out,
		yaml.MapItem{Key: "commit", Value: "winner"},
		yaml.MapItem{Key: "continue", Value: false},
	)
	out = append(out, payloads...)
	return out, warns, true
}

// payloadList 把 nuclei payload 值统一成 []string。
func payloadList(v any) ([]string, bool) {
	switch vv := v.(type) {
	case []string:
		return vv, true
	case []any:
		out := make([]string, 0, len(vv))
		for _, it := range vv {
			if it == nil {
				continue
			}
			s, ok := it.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}
