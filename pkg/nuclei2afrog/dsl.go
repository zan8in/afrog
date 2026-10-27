package nuclei2afrog

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// 本文件把 nuclei 的 DSL 表达式（govaluate 语法）翻译成 afrog 的 CEL 表达式。
//
// 关键语义（均以 nuclei / govaluate 源码为准）：
//   - 字符串字面量用单引号或双引号，`\` 转义「紧跟的任意一个字符」（非 C 风格）；
//   - nuclei 的 body/header/raw 是 string，afrog 的 response.body/raw_header/raw 是 bytes，
//     因此字符串函数必须落到 `b*` 系列或显式 toBytes/toUtf8；
//   - nuclei 的 duration 单位是秒（float），afrog 的 response.latency 单位是毫秒（int）。

// 各视图的 kind
type vkind int

const (
	kUnknown vkind = iota
	kString
	kBytes
	kInt
	kFloat
	kBool
)

// emitted 是翻译结果片段：表达式文本 + 类型 + 是否需要毫秒换算。
type emitted struct {
	expr     string
	kind     vkind
	duration bool // 该片段是 nuclei duration（秒）
}

// ---------- AST ----------

type dslNode interface{}

type dslLit struct {
	kind    string // "string" | "number" | "bool"
	str     string
	num     float64
	text    string
	isFloat bool
	b       bool
}

type dslIdent struct{ name string }

// dslIdents 收集 DSL 节点里出现的标识符，用于推导变量间的依赖关系。
func dslIdents(n dslNode) []string {
	var out []string
	switch v := n.(type) {
	case *dslIdent:
		out = append(out, v.name)
	case *dslCall:
		for _, a := range v.args {
			out = append(out, dslIdents(a)...)
		}
	case *dslUnary:
		out = append(out, dslIdents(v.x)...)
	case *dslBinary:
		out = append(out, dslIdents(v.l)...)
		out = append(out, dslIdents(v.r)...)
	}
	return out
}

type dslCall struct {
	fn   string
	args []dslNode
}

type dslUnary struct {
	op string
	x  dslNode
}

type dslBinary struct {
	op   string
	l, r dslNode
}

// ---------- 词法 ----------

type dslToken struct {
	kind    string // ident | number | string | op | lparen | rparen | comma
	text    string
	num     float64
	text2   string // 数字原始文本
	isFloat bool
}

// dslOperators 按长度降序排列，保证「先长后短」匹配。
var dslOperators = []string{"&&", "||", "==", "!=", ">=", "<=", "=~", "!~", ">", "<", "!", "+", "-", "*", "/", "%"}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

func dslTokenize(s string) ([]dslToken, error) {
	out := make([]dslToken, 0, 32)
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
			continue
		case c == '\'' || c == '"':
			quote := c
			i++
			var b strings.Builder
			closed := false
			for i < len(s) {
				ch := s[i]
				if ch == '\\' {
					if i+1 >= len(s) {
						return nil, fmt.Errorf("字符串字面量结尾存在孤立的反斜杠")
					}
					// govaluate: 反斜杠转义紧跟的任意一个字符
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				if ch == quote {
					i++
					closed = true
					break
				}
				b.WriteByte(ch)
				i++
			}
			if !closed {
				return nil, fmt.Errorf("字符串字面量未闭合")
			}
			out = append(out, dslToken{kind: "string", text: b.String()})
			continue
		case c >= '0' && c <= '9':
			j := i
			isFloat := false
			for j < len(s) && ((s[j] >= '0' && s[j] <= '9') || s[j] == '.') {
				if s[j] == '.' {
					isFloat = true
				}
				j++
			}
			text := s[i:j]
			f, err := strconv.ParseFloat(text, 64)
			if err != nil {
				return nil, fmt.Errorf("非法数字 %q", text)
			}
			out = append(out, dslToken{kind: "number", num: f, text2: text, isFloat: isFloat})
			i = j
			continue
		case isIdentStart(c):
			j := i
			for j < len(s) && isIdentPart(s[j]) {
				j++
			}
			out = append(out, dslToken{kind: "ident", text: s[i:j]})
			i = j
			continue
		case c == '(':
			out = append(out, dslToken{kind: "lparen"})
			i++
			continue
		case c == ')':
			out = append(out, dslToken{kind: "rparen"})
			i++
			continue
		case c == ',':
			out = append(out, dslToken{kind: "comma"})
			i++
			continue
		}

		matched := false
		for _, op := range dslOperators {
			if strings.HasPrefix(s[i:], op) {
				out = append(out, dslToken{kind: "op", text: op})
				i += len(op)
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("无法识别的字符 %q（位置 %d）", string(c), i)
		}
	}
	return out, nil
}

// ---------- 语法 ----------

type dslParser struct {
	toks []dslToken
	pos  int
}

func opPrec(op string) int {
	switch op {
	case "||":
		return 1
	case "&&":
		return 2
	case "==", "!=", "=~", "!~":
		return 3
	case "<", ">", "<=", ">=":
		return 4
	case "+", "-":
		return 5
	case "*", "/", "%":
		return 6
	}
	return -1
}

func (p *dslParser) peek() *dslToken {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}

func (p *dslParser) next() *dslToken {
	t := p.peek()
	if t != nil {
		p.pos++
	}
	return t
}

func (p *dslParser) peekKind(kind string) bool {
	t := p.peek()
	return t != nil && t.kind == kind
}

func (p *dslParser) parseExpr(minPrec int) (dslNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t == nil || t.kind != "op" {
			break
		}
		prec := opPrec(t.text)
		if prec < minPrec {
			break
		}
		op := t.text
		p.next()
		right, err := p.parseExpr(prec + 1)
		if err != nil {
			return nil, err
		}
		left = &dslBinary{op: op, l: left, r: right}
	}
	return left, nil
}

func (p *dslParser) parseUnary() (dslNode, error) {
	t := p.peek()
	if t != nil && t.kind == "op" && (t.text == "!" || t.text == "-") {
		op := t.text
		p.next()
		x, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &dslUnary{op: op, x: x}, nil
	}
	return p.parsePrimary()
}

func (p *dslParser) parsePrimary() (dslNode, error) {
	t := p.next()
	if t == nil {
		return nil, fmt.Errorf("表达式意外结束")
	}
	switch t.kind {
	case "number":
		return &dslLit{kind: "number", num: t.num, text: t.text2, isFloat: t.isFloat}, nil
	case "string":
		return &dslLit{kind: "string", str: t.text}, nil
	case "ident":
		if p.peekKind("lparen") {
			p.next()
			var args []dslNode
			if !p.peekKind("rparen") {
				for {
					a, err := p.parseExpr(0)
					if err != nil {
						return nil, err
					}
					args = append(args, a)
					if p.peekKind("comma") {
						p.next()
						continue
					}
					break
				}
			}
			if !p.peekKind("rparen") {
				return nil, fmt.Errorf("%s( 缺少右括号", t.text)
			}
			p.next()
			return &dslCall{fn: t.text, args: args}, nil
		}
		switch t.text {
		case "true":
			return &dslLit{kind: "bool", b: true}, nil
		case "false":
			return &dslLit{kind: "bool", b: false}, nil
		}
		return &dslIdent{name: t.text}, nil
	case "lparen":
		e, err := p.parseExpr(0)
		if err != nil {
			return nil, err
		}
		if !p.peekKind("rparen") {
			return nil, fmt.Errorf("缺少右括号")
		}
		p.next()
		return e, nil
	}
	return nil, fmt.Errorf("意外 token %q", t.text)
}

// parseDSL 解析 nuclei DSL 表达式。
func parseDSL(s string) (dslNode, error) {
	toks, err := dslTokenize(s)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, fmt.Errorf("空表达式")
	}
	p := &dslParser{toks: toks}
	n, err := p.parseExpr(0)
	if err != nil {
		return nil, err
	}
	if p.pos != len(toks) {
		return nil, fmt.Errorf("表达式存在无法解析的残留：%q", strings.TrimSpace(s))
	}
	return n, nil
}

// ---------- 字面量 ----------

func celStringLiteral(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
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
			if c < 0x20 {
				fmt.Fprintf(&b, `\x%02x`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func celBytesLiteral(s string) string {
	return "b" + celStringLiteral(s)
}

// ---------- 视图表 ----------

// viewTable 是 nuclei DSL 变量 → afrog CEL 响应视图的映射。
var viewTable = map[string]struct {
	expr string
	kind vkind
}{
	"body":         {"response.body", kBytes},
	"all_headers":  {"response.raw_header", kBytes},
	"header":       {"response.raw_header", kBytes},
	"raw":          {"response.raw", kBytes},
	"content_type": {"response.content_type", kString},
	"status_code":  {"response.status", kInt},
	"duration":     {"response.latency", kInt},
	// nuclei 的 Host 是「无端口主机名」（variables.go: parsed.Hostname()），
	// 等价于 afrog 的 request.url.domain（host 带端口，对应 nuclei 的 Hostname）。
	"host":    {"request.url.domain", kString},
	"scheme":  {"request.url.scheme", kString},
	"port":    {"request.url.port", kString},
	"path":    {"request.url.path", kString},
	"query":   {"request.url.query", kString},
	"domain":  {"request.url.domain", kString},
	"baseurl": {`(request.url.scheme + "://" + request.url.host)`, kString},
	"rooturl": {`(request.url.scheme + "://" + request.url.host)`, kString},
	// nuclei 的 ip 是实际拨号到的 IP（无端口），由 retryhttpclient 回填
	// response.conn.destination.addr（见 connInfoFromRemoteAddr）。
	"ip": {"response.conn.destination.addr", kString},
}

// gapDSLVars 前缀命中即视为不可映射的多响应 / 反连变量。
var gapDSLVars = []string{"body_", "header_", "status_code_", "raw_", "content_length_", "interactsh_"}

// ---------- 翻译 ----------

// translateDSL 把一条 nuclei DSL 表达式翻译为 afrog CEL 表达式。
func translateDSL(s string) (string, *Warning) {
	node, err := parseDSL(s)
	if err != nil {
		return "", &Warning{Message: fmt.Sprintf("DSL 解析失败：%s（%v）", strings.TrimSpace(s), err), Gap: true}
	}
	out, w := emitDSLNode(node)
	if w != nil && w.Gap {
		return "", w
	}
	if out.kind != kBool && out.kind != kUnknown {
		return "", &Warning{Message: fmt.Sprintf("DSL 表达式 %q 不是布尔条件", strings.TrimSpace(s)), Gap: true}
	}
	return out.expr, w
}

func emitDSLNode(n dslNode) (emitted, *Warning) {
	switch v := n.(type) {
	case *dslLit:
		return emitLiteral(v)
	case *dslIdent:
		return emitIdent(v.name)
	case *dslCall:
		return emitCall(v)
	case *dslUnary:
		return emitUnary(v)
	case *dslBinary:
		return emitBinary(v)
	}
	return emitted{}, &Warning{Message: "无法识别的 DSL 节点", Gap: true}
}

func emitLiteral(l *dslLit) (emitted, *Warning) {
	switch l.kind {
	case "string":
		return emitted{expr: celStringLiteral(l.str), kind: kString}, nil
	case "number":
		if l.isFloat {
			return emitted{expr: l.text, kind: kFloat}, nil
		}
		return emitted{expr: l.text, kind: kInt}, nil
	case "bool":
		if l.b {
			return emitted{expr: "true", kind: kBool}, nil
		}
		return emitted{expr: "false", kind: kBool}, nil
	}
	return emitted{}, &Warning{Message: "无法识别的字面量", Gap: true}
}

func emitIdent(name string) (emitted, *Warning) {
	key := strings.ToLower(strings.TrimSpace(name))
	if v, ok := viewTable[key]; ok {
		e := emitted{expr: v.expr, kind: v.kind}
		if key == "duration" {
			e.duration = true
		}
		return e, nil
	}
	for _, p := range gapDSLVars {
		if strings.HasPrefix(key, p) {
			return emitted{}, &Warning{Message: fmt.Sprintf("变量 %q 在 afrog 中无对应（多响应历史/反连不可表达）", name), Gap: true}
		}
	}
	// 自定义变量（variables / payloads）直接作为 CEL 变量引用，类型未知时按 string 处理。
	return emitted{expr: sanitizeIdent(name), kind: kUnknown}, nil
}

func sanitizeIdent(name string) string {
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		if isIdentPart(c) {
			b.WriteByte(c)
		} else {
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" {
		return "v"
	}
	if !isIdentStart(s[0]) {
		s = "v" + s
	}
	return s
}

// literalString 取节点上的字符串字面量值。
func literalString(n dslNode) (string, bool) {
	if l, ok := n.(*dslLit); ok && l.kind == "string" {
		return l.str, true
	}
	return "", false
}

// toBytesExpr 保证片段是 bytes 类型。
func toBytesExpr(e emitted) string {
	if e.kind == kBytes {
		return e.expr
	}
	return "toBytes(" + e.expr + ")"
}

// toStrExpr 保证片段是 string 类型（bytes 会走 toUtf8，注意其为有损转换）。
func toStrExpr(e emitted) string {
	if e.kind == kBytes {
		return "toUtf8(" + e.expr + ")"
	}
	return e.expr
}

// toCelString 把片段强制成 CEL string，用于字符串拼接场景（set 值 / 请求文本渲染）。
// 返回 false 表示无法安全转换，调用方应判定为 gap。
func toCelString(e emitted) (string, bool) {
	switch e.kind {
	case kString:
		return e.expr, true
	case kBytes:
		return "toUtf8(" + e.expr + ")", true
	case kInt, kFloat:
		return "string(" + e.expr + ")", true
	}
	return "", false
}

func containsExpr(target emitted, needle string, ci bool) string {
	if target.kind == kBytes {
		if ci {
			return target.expr + ".ibcontains(" + celBytesLiteral(needle) + ")"
		}
		return target.expr + ".bcontains(" + celBytesLiteral(needle) + ")"
	}
	if ci {
		return target.expr + ".icontains(" + celStringLiteral(needle) + ")"
	}
	return target.expr + ".contains(" + celStringLiteral(needle) + ")"
}

func emitUnary(u *dslUnary) (emitted, *Warning) {
	x, w := emitDSLNode(u.x)
	if w != nil {
		return emitted{}, w
	}
	switch u.op {
	case "!":
		return emitted{expr: "!(" + x.expr + ")", kind: kBool}, nil
	case "-":
		return emitted{expr: "-(" + x.expr + ")", kind: kInt}, nil
	}
	return emitted{}, &Warning{Message: fmt.Sprintf("不支持的一元运算符 %q", u.op), Gap: true}
}

func emitBinary(b *dslBinary) (emitted, *Warning) {
	l, w := emitDSLNode(b.l)
	if w != nil {
		return emitted{}, w
	}
	r, w := emitDSLNode(b.r)
	if w != nil {
		return emitted{}, w
	}

	switch b.op {
	case "&&", "||":
		return emitted{expr: "(" + l.expr + " " + b.op + " " + r.expr + ")", kind: kBool}, nil
	case "=~", "!~":
		op := ""
		if b.op == "!~" {
			op = "!"
		}
		return emitted{expr: op + l.expr + ".matches(" + r.expr + ")", kind: kBool}, nil
	}

	// duration（秒）与 afrog latency（毫秒）的换算：只有另一侧是数字字面量时才安全。
	if l.duration != r.duration {
		scale := func(num *dslLit) (bool, string) {
			if !num.isFloat && num.num == 0 {
				// 整型零值也合法，走下面的通用分支
			}
			return true, num.text
		}
		switch {
		case l.duration:
			if lit, ok := b.r.(*dslLit); ok && lit.kind == "number" {
				_, txt := scale(lit)
				scaled, err := scaleNumberText(txt, 1000)
				if err != nil {
					return emitted{}, &Warning{Message: "duration 换算失败", Gap: true}
				}
				return emitted{expr: "(" + l.expr + " " + b.op + " " + scaled + ")", kind: kBool}, nil
			}
		case r.duration:
			if lit, ok := b.l.(*dslLit); ok && lit.kind == "number" {
				_, txt := scale(lit)
				scaled, err := scaleNumberText(txt, 1000)
				if err != nil {
					return emitted{}, &Warning{Message: "duration 换算失败", Gap: true}
				}
				return emitted{expr: "(" + scaled + " " + b.op + " " + r.expr + ")", kind: kBool}, nil
			}
		}
		return emitted{}, &Warning{Message: "duration 仅在直接与数字字面量比较时可换算（nuclei 秒 → afrog 毫秒）", Gap: true}
	}

	// bytes / string 混用：把 string 侧显式转成 bytes，避免 CEL 编译期类型错误。
	if l.kind == kBytes && r.kind == kString {
		r.expr = "toBytes(" + r.expr + ")"
	} else if l.kind == kString && r.kind == kBytes {
		l.expr = "toBytes(" + l.expr + ")"
	}

	switch b.op {
	case "==", "!=", "<", ">", "<=", ">=":
		return emitted{expr: "(" + l.expr + " " + b.op + " " + r.expr + ")", kind: kBool}, nil
	case "+":
		if l.kind == kBytes || r.kind == kBytes {
			return emitted{expr: "(" + toBytesExpr(l) + " + " + toBytesExpr(r) + ")", kind: kBytes}, nil
		}
		return emitted{expr: "(" + l.expr + " + " + r.expr + ")", kind: kString}, nil
	}
	return emitted{}, &Warning{Message: fmt.Sprintf("暂不支持的运算符 %q", b.op), Gap: true}
}

func scaleNumberText(text string, factor int) (string, error) {
	if !strings.Contains(text, ".") {
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return "", err
		}
		return strconv.FormatInt(n*int64(factor), 10), nil
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return "", err
	}
	return strconv.FormatFloat(f*float64(factor), 'f', -1, 64), nil
}

// ---------- 函数 ----------

func emitCall(c *dslCall) (emitted, *Warning) {
	fn := strings.ToLower(strings.TrimSpace(c.fn))

	switch fn {
	case "contains":
		return emitContains(c, false)
	case "icontains":
		return emitContains(c, true)
	case "contains_all":
		return emitContainsMulti(c, " && ")
	case "contains_any":
		return emitContainsMulti(c, " || ")
	case "regex":
		return emitRegex(c, "")
	case "regex_all":
		return emitRegex(c, " && ")
	case "regex_any":
		return emitRegex(c, " || ")
	case "tolower", "to_lower":
		return emitCaseFn(c, "toLower")
	case "toupper", "to_upper":
		return emitCaseFn(c, "toUpper")
	case "len":
		if len(c.args) != 1 {
			return gapf("len 需要 1 个参数")
		}
		x, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		return emitted{expr: "length(" + x.expr + ")", kind: kInt}, nil
	case "md5":
		if len(c.args) != 1 {
			return gapf("md5 需要 1 个参数")
		}
		x, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		return emitted{expr: "md5(" + toStrExpr(x) + ")", kind: kString}, nil
	case "sha1", "sha256", "sha512":
		if len(c.args) != 1 {
			return gapf(fn + " 需要 1 个参数")
		}
		x, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		return emitted{expr: fn + "(" + x.expr + ")", kind: kString}, nil
	case "base64":
		if len(c.args) != 1 {
			return gapf("base64 需要 1 个参数")
		}
		x, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		return emitted{expr: "base64(" + x.expr + ")", kind: kString}, nil
	case "base64_decode":
		if len(c.args) != 1 {
			return gapf("base64_decode 需要 1 个参数")
		}
		x, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		return emitted{expr: "base64Decode(" + toStrExpr(x) + ")", kind: kString}, nil
	case "hex_encode":
		if len(c.args) != 1 {
			return gapf("hex_encode 需要 1 个参数")
		}
		x, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		return emitted{expr: "hex(" + x.expr + ")", kind: kString}, nil
	case "hex_decode":
		if len(c.args) != 1 {
			return gapf("hex_decode 需要 1 个参数")
		}
		x, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		return emitted{expr: "hexdecode(" + toStrExpr(x) + ")", kind: kString}, nil
	case "url_encode":
		if len(c.args) != 1 {
			return gapf("url_encode 需要 1 个参数")
		}
		x, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		return emitted{expr: "urlencode(" + x.expr + ")", kind: kString}, nil
	case "url_decode":
		if len(c.args) != 1 {
			return gapf("url_decode 需要 1 个参数")
		}
		x, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		return emitted{expr: "urldecode(" + x.expr + ")", kind: kString}, nil
	case "concat":
		if len(c.args) < 2 {
			return gapf("concat 至少需要 2 个参数")
		}
		parts := make([]string, 0, len(c.args))
		for _, a := range c.args {
			x, w := emitDSLNode(a)
			if w != nil {
				return emitted{}, w
			}
			parts = append(parts, toStrExpr(x))
		}
		return emitted{expr: "(" + strings.Join(parts, " + ") + ")", kind: kString}, nil
	case "starts_with":
		return emitAffix(c, true)
	case "ends_with":
		return emitAffix(c, false)
	case "to_string":
		if len(c.args) != 1 {
			return gapf("to_string 需要 1 个参数")
		}
		x, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		return emitted{expr: "string(" + x.expr + ")", kind: kString}, nil
	case "to_number":
		if len(c.args) != 1 {
			return gapf("to_number 需要 1 个参数")
		}
		x, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		if s, ok := literalString(c.args[0]); ok && strings.Contains(s, ".") {
			return emitted{expr: "double(" + toStrExpr(x) + ")", kind: kFloat}, nil
		}
		return emitted{expr: "int(" + toStrExpr(x) + ")", kind: kInt}, nil
	case "compare_versions":
		return emitCompareVersions(c)
	case "rand_int":
		if len(c.args) != 2 {
			return gapf("rand_int 需要 2 个参数")
		}
		a, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		b, w := emitDSLNode(c.args[1])
		if w != nil {
			return emitted{}, w
		}
		return emitted{expr: "randomInt(" + a.expr + ", " + b.expr + ")", kind: kInt}, nil
	case "rand_text_alpha", "rand_text_alphanumeric", "rand_text_alpha_lower", "rand_text_alphanumeric_lower",
		"rand_base", "rand_char", "rand_text_numeric":
		if len(c.args) != 1 {
			return gapf(fn + " 需要 1 个参数")
		}
		x, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		return emitted{expr: "randomLowercase(" + x.expr + ")", kind: kString}, &Warning{
			Message: fmt.Sprintf("%s 的字符集与 afrog randomLowercase 不同，命中侧通常无影响", fn),
		}
	case "replace":
		if len(c.args) < 3 {
			return gapf("replace 至少需要 3 个参数")
		}
		parts := make([]string, 0, 3)
		for _, a := range c.args[:3] {
			x, w := emitDSLNode(a)
			if w != nil {
				return emitted{}, w
			}
			parts = append(parts, toStrExpr(x))
		}
		warn := (*Warning)(nil)
		if len(c.args) == 4 {
			warn = &Warning{Message: "replace 的第 4 个参数（替换次数）在 afrog replaceAll 中会丢失，改为全量替换"}
		}
		return emitted{expr: "replaceAll(" + strings.Join(parts, ", ") + ")", kind: kString}, warn
	case "repeat":
		if len(c.args) != 2 {
			return gapf("repeat 需要 2 个参数")
		}
		a, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		b, w := emitDSLNode(c.args[1])
		if w != nil {
			return emitted{}, w
		}
		return emitted{expr: "repeat(" + toStrExpr(a) + ", " + b.expr + ")", kind: kString}, nil
	case "wait_for":
		if len(c.args) != 1 {
			return gapf("wait_for 需要 1 个参数")
		}
		x, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		return emitted{expr: "sleep(" + x.expr + ")", kind: kUnknown}, nil
	case "unix_time":
		return emitted{expr: "timestamp_second()", kind: kString}, nil
	case "trim_space":
		if len(c.args) != 1 {
			return gapf("trim_space 需要 1 个参数")
		}
		x, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		return emitted{expr: "trim(" + toStrExpr(x) + ")", kind: kString}, nil
	case "substr":
		if len(c.args) != 3 {
			return gapf("substr 需要 3 个参数")
		}
		a, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		b, w := emitDSLNode(c.args[1])
		if w != nil {
			return emitted{}, w
		}
		cc, w := emitDSLNode(c.args[2])
		if w != nil {
			return emitted{}, w
		}
		return emitted{expr: "substr(" + a.expr + ", " + b.expr + ", " + cc.expr + ")", kind: kString}, nil
	case "generate_java_gadget":
		if len(c.args) != 3 {
			return gapf("generate_java_gadget 需要 3 个参数")
		}
		parts := make([]string, 0, 3)
		for _, a := range c.args {
			x, w := emitDSLNode(a)
			if w != nil {
				return emitted{}, w
			}
			parts = append(parts, x.expr)
		}
		return emitted{expr: "ysoserial(" + strings.Join(parts, ", ") + ")", kind: kString}, nil
	case "mmh3":
		return emitMmh3(c)
	case "print_debug":
		if len(c.args) != 1 {
			return gapf("print_debug 需要 1 个参数")
		}
		x, w := emitDSLNode(c.args[0])
		if w != nil {
			return emitted{}, w
		}
		return emitted{expr: x.expr, kind: x.kind}, &Warning{Message: "print_debug 已退化为原值透传"}
	case "base64_py":
		return gapf("base64_py 会输出带换行的 Base64，afrog 无等价函数")
	}

	return gapf(fmt.Sprintf("DSL 函数 %q 在 afrog CEL 中没有对应实现", c.fn))
}

func gapf(msg string) (emitted, *Warning) {
	return emitted{}, &Warning{Message: msg, Gap: true}
}

func emitContains(c *dslCall, ci bool) (emitted, *Warning) {
	if len(c.args) != 2 {
		return gapf(c.fn + " 需要 2 个参数")
	}
	target, w := emitDSLNode(c.args[0])
	if w != nil {
		return emitted{}, w
	}
	if s, ok := literalString(c.args[1]); ok {
		return emitted{expr: containsExpr(target, s, ci), kind: kBool}, nil
	}
	needle, w := emitDSLNode(c.args[1])
	if w != nil {
		return emitted{}, w
	}
	if target.kind == kBytes {
		op := ".bcontains("
		if ci {
			op = ".ibcontains("
		}
		return emitted{expr: target.expr + op + toBytesExpr(needle) + ")", kind: kBool}, nil
	}
	op := ".contains("
	if ci {
		op = ".icontains("
	}
	return emitted{expr: target.expr + op + toStrExpr(needle) + ")", kind: kBool}, nil
}

func emitContainsMulti(c *dslCall, join string) (emitted, *Warning) {
	if len(c.args) < 2 {
		return gapf(c.fn + " 至少需要 2 个参数")
	}
	target, w := emitDSLNode(c.args[0])
	if w != nil {
		return emitted{}, w
	}
	parts := make([]string, 0, len(c.args)-1)
	for _, a := range c.args[1:] {
		s, ok := literalString(a)
		if !ok {
			return gapf(c.fn + " 的匹配值必须是字符串字面量")
		}
		parts = append(parts, containsExpr(target, s, false))
	}
	return emitted{expr: "(" + strings.Join(parts, join) + ")", kind: kBool}, nil
}

func emitRegex(c *dslCall, join string) (emitted, *Warning) {
	if len(c.args) < 2 {
		return gapf(c.fn + " 至少需要 2 个参数")
	}
	target, w := emitDSLNode(c.args[len(c.args)-1])
	if w != nil {
		return emitted{}, w
	}
	useBytes := target.kind == kBytes
	single := func(re string) string {
		if useBytes {
			return celStringLiteral(re) + ".bmatches(" + target.expr + ")"
		}
		return celStringLiteral(re) + ".rmatches(" + target.expr + ")"
	}
	if join == "" {
		re, ok := literalString(c.args[0])
		if !ok {
			return gapf("regex 的正则必须是字符串字面量")
		}
		return emitted{expr: single(re), kind: kBool}, nil
	}
	parts := make([]string, 0, len(c.args)-1)
	for _, a := range c.args[:len(c.args)-1] {
		re, ok := literalString(a)
		if !ok {
			return gapf(c.fn + " 的正则必须是字符串字面量")
		}
		parts = append(parts, single(re))
	}
	return emitted{expr: "(" + strings.Join(parts, join) + ")", kind: kBool}, nil
}

func emitCaseFn(c *dslCall, fnName string) (emitted, *Warning) {
	if len(c.args) != 1 {
		return gapf(c.fn + " 需要 1 个参数")
	}
	x, w := emitDSLNode(c.args[0])
	if w != nil {
		return emitted{}, w
	}
	if fnName == "toLower" {
		if x.kind == kBytes {
			return emitted{expr: "toLower(toUtf8(" + x.expr + "))", kind: kString}, nil
		}
		return emitted{expr: "toLower(" + toStrExpr(x) + ")", kind: kString}, nil
	}
	if x.kind == kBytes {
		return emitted{expr: "toUpper(" + x.expr + ")", kind: kBytes}, nil
	}
	return emitted{expr: "toUpper(" + toStrExpr(x) + ")", kind: kString}, nil
}

func emitAffix(c *dslCall, starts bool) (emitted, *Warning) {
	if len(c.args) != 2 {
		return gapf(c.fn + " 需要 2 个参数")
	}
	target, w := emitDSLNode(c.args[0])
	if w != nil {
		return emitted{}, w
	}
	s, ok := literalString(c.args[1])
	if !ok {
		return gapf(c.fn + " 的匹配值必须是字符串字面量")
	}
	if starts {
		if target.kind == kBytes {
			return emitted{expr: target.expr + ".bstartsWith(" + celBytesLiteral(s) + ")", kind: kBool}, nil
		}
		return emitted{expr: target.expr + ".startsWith(" + celStringLiteral(s) + ")", kind: kBool}, nil
	}
	return emitted{expr: toStrExpr(target) + ".endsWith(" + celStringLiteral(s) + ")", kind: kBool}, nil
}

var reVersionSpec = regexp.MustCompile(`^\s*(>=|<=|==|!=|>|<|=|~|\^)?\s*(.+?)\s*$`)

func emitCompareVersions(c *dslCall) (emitted, *Warning) {
	if len(c.args) != 2 {
		return gapf("compare_versions 需要 2 个参数")
	}
	ver, w := emitDSLNode(c.args[0])
	if w != nil {
		return emitted{}, w
	}
	spec, ok := literalString(c.args[1])
	if !ok {
		return gapf("compare_versions 的版本约束必须是字符串字面量")
	}
	m := reVersionSpec.FindStringSubmatch(spec)
	if m == nil || m[2] == "" {
		return gapf(fmt.Sprintf("无法解析版本约束 %q", spec))
	}
	op := m[1]
	switch op {
	case "", "=":
		op = "=="
	case "~", "^":
		return gapf(fmt.Sprintf("afrog versionCompare 不支持 %q 约束", op))
	}
	// nuclei 的 compare_versions(version, '>=1.2.3') == 参数顺序与 afrog 相反
	return emitted{expr: "versionCompare(" + toStrExpr(ver) + ", " + celStringLiteral(m[2]) + ", " + celStringLiteral(op) + ")", kind: kBool}, nil
}

// emitMmh3 处理 nuclei 的 favicon 指纹特例：mmh3(base64_py(x)) → afrog faviconHash(x)。
func emitMmh3(c *dslCall) (emitted, *Warning) {
	if len(c.args) != 1 {
		return gapf("mmh3 需要 1 个参数")
	}
	inner, ok := c.args[0].(*dslCall)
	if !ok {
		return gapf("mmh3 仅支持 mmh3(base64_py(<body>)) 的 favicon 指纹特例")
	}
	if strings.ToLower(strings.TrimSpace(inner.fn)) != "base64_py" || len(inner.args) != 1 {
		return gapf("mmh3 仅支持 mmh3(base64_py(<body>)) 的 favicon 指纹特例")
	}
	x, w := emitDSLNode(inner.args[0])
	if w != nil {
		return emitted{}, w
	}
	return emitted{expr: "faviconHash(" + x.expr + ")", kind: kInt}, nil
}
