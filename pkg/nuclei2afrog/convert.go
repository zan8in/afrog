package nuclei2afrog

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/google/cel-go/checker/decls"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/runner"
	"gopkg.in/yaml.v2"
)

// 本文件是转换器的对外入口：
//
//	Convert([]byte) (*Result, error)
//
// 流程：解析 → 分档（classify）→ 翻译（translate）→ CEL 自校验 → 序列化（emit）。
// 任何一步做不到「忠实转换」都会降级为 C 类，并在 Gaps 中列出原因，
// 绝不产出「能编译但语义已经走偏」的 PoC。

// Result 是单个 nuclei 模板的转换结果。
//
// Class:
//   - A/B：翻译成功且通过 CEL 自校验，YAML 非空；
//   - C  ：需人工重写（含翻译失败与自校验失败），YAML 为空；
//   - D  ：afrog 无对应运行时；
//   - X  ：模板不含可识别的协议段。
type Result struct {
	Class    Class
	Pocs     []poc.Poc
	YAML     []byte // 单个 PoC 的序列化结果；Class 非 A/B 时为空
	Warnings []Warning
	Gaps     []string
	Report   string
}

// Convert 把一个 nuclei 模板转换为 afrog PoC。
// 返回的 error 仅表示「输入不是合法的 nuclei 模板」，语义层面的失败走 Result.Class / Gaps。
func Convert(data []byte) (*Result, error) {
	var tpl nucleiTemplate
	if err := yaml.Unmarshal(data, &tpl); err != nil {
		return nil, fmt.Errorf("解析 nuclei 模板失败: %w", err)
	}

	topKeys, err := topLevelKeys(data)
	if err != nil {
		return nil, fmt.Errorf("解析 nuclei 模板顶层结构失败: %w", err)
	}

	renameWarns := renameReservedVars(&tpl)

	cls := classify(&tpl, topKeys)

	res := &Result{}
	res.Warnings = append(res.Warnings, renameWarns...)
	res.Warnings = append(res.Warnings, cls.warns...)
	for _, r := range cls.reasonsB {
		res.Warnings = append(res.Warnings, Warning{Field: "classify", Message: r})
	}

	switch cls.class {
	case ClassA, ClassB:
		res.Class = cls.class
	case "":
		// 结构层面无阻碍：无 B 类理由即 A，否则 B
		if len(cls.reasonsB) == 0 {
			res.Class = ClassA
		} else {
			res.Class = ClassB
		}
	default:
		res.Class = cls.class
		res.Warnings = append(res.Warnings, Warning{Field: "classify", Message: cls.reason, Gap: true})
		res.Gaps = append(res.Gaps, cls.reason)
		res.Report = buildReport(res)
		return res, nil
	}

	p, warns, ok := translate(&tpl)
	res.Warnings = append(res.Warnings, warns...)
	if !ok {
		res.Class = ClassC
		res.Gaps = collectGaps(warns)
		if len(res.Gaps) == 0 {
			res.Gaps = append(res.Gaps, "翻译过程未能忠实还原模板语义")
		}
		res.Report = buildReport(res)
		return res, nil
	}

	if gaps := validatePoc(&p); len(gaps) > 0 {
		res.Class = ClassC
		res.Gaps = gaps
		res.Warnings = append(res.Warnings, Warning{
			Field:   "cel",
			Message: "生成的 CEL 表达式未通过 afrog 编译自校验，已降级为需人工重写",
			Gap:     true,
		})
		res.Report = buildReport(res)
		return res, nil
	}

	out, err := emit(&p)
	if err != nil {
		return nil, fmt.Errorf("序列化 afrog PoC 失败: %w", err)
	}

	res.Pocs = []poc.Poc{p}
	res.YAML = out
	res.Report = buildReport(res)
	return res, nil
}

// topLevelKeys 取出 YAML 顶层的键集合，供 classify 判断协议段。
func topLevelKeys(data []byte) (map[string]bool, error) {
	var root yaml.MapSlice
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(root))
	for _, item := range root {
		k, ok := item.Key.(string)
		if !ok {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(k))] = true
	}
	return out, nil
}

// ---------------- CEL 自校验 ----------------

var (
	rePlaceholder = regexp.MustCompile(`\{\{(.+?)\}\}`)
	rePlainIdent  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// validatePoc 用 afrog 自身的 CEL 编译器校验生成的每一段表达式。
//
// 校验范围：
//   - poc.expression（r0() || r1() ...）与每个 rule.expression（matcher 树翻译结果）；
//   - type=cel 的 extractor 表达式；
//   - 请求字段里由转换器生成的 {{CEL}} 占位符（纯标识符占位符是 brute/set 的运行期替换，跳过）。
//
// 注意：不能依赖 pkg/validator 的函数白名单——validator 会跳过形如标识符的调用，
// 真正的「函数不存在」只会在 CEL 编译期暴露。
func validatePoc(p *poc.Poc) []string {
	lib := runner.NewCustomLib()
	for _, rm := range p.Rules {
		lib.WriteRuleFunctionsROptions(rm.Key, true)
	}
	declareVars(lib, p)

	env, err := lib.NewCelEnv()
	if err != nil {
		return []string{fmt.Sprintf("构建 CEL 编译环境失败: %v", err)}
	}

	var gaps []string
	check := func(field, expr string) {
		if _, iss := env.Compile(expr); iss.Err() != nil {
			gaps = append(gaps, fmt.Sprintf("%s 无法编译: %v", field, iss.Err()))
		}
	}

	if p.Expression != "" {
		check("expression", p.Expression)
	}
	for _, item := range p.Set {
		k, ok := item.Key.(string)
		if !ok {
			continue
		}
		v, ok := item.Value.(string)
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		// set 值在运行期走 CustomLib.RunEval，必须能编译（否则会静默回落成字面量）。
		check("set."+k, v)
	}
	for _, rm := range p.Rules {
		check("rules."+rm.Key+".expression", rm.Value.Expression)
		for i, e := range rm.Value.Extractors {
			if strings.EqualFold(strings.TrimSpace(e.Type), "cel") && strings.TrimSpace(e.Value) != "" {
				check(fmt.Sprintf("rules.%s.extractors[%d]", rm.Key, i), e.Value)
			}
		}
		for _, ph := range requestPlaceholders(rm.Value.Request) {
			check("rules."+rm.Key+".request", ph)
		}
	}
	return gaps
}

// declareVars 把 set / brute 变量声明为动态类型，模拟运行期 afrog 的行为
// （checker 在求值 set / brute 时会 UpdateCompileOption 注册这些键）。
func declareVars(lib *runner.CustomLib, p *poc.Poc) {
	for _, item := range p.Set {
		if k, ok := item.Key.(string); ok {
			lib.UpdateCompileOption(k, decls.Dyn)
		}
	}
	for _, rm := range p.Rules {
		for _, item := range rm.Value.Brute {
			k, ok := item.Key.(string)
			if !ok || isBruteMetaKey(k) {
				continue
			}
			lib.UpdateCompileOption(k, decls.Dyn)
		}
	}
}

// isBruteMetaKey 判断 brute 里的控制键（非 payload 变量）。
func isBruteMetaKey(k string) bool {
	switch k {
	case "mode", "commit", "continue":
		return true
	}
	return false
}

// requestPlaceholders 收集请求字段里需要 CEL 求值的 {{...}} 表达式。
// 纯标识符（brute / set 变量、randstr 回落）由运行期的 setVariableMap 替换，不在校验范围。
func requestPlaceholders(r poc.RuleRequest) []string {
	var fields []string
	if r.Path != "" {
		fields = append(fields, r.Path)
	}
	if r.Host != "" {
		fields = append(fields, r.Host)
	}
	if r.Body != "" {
		fields = append(fields, r.Body)
	}
	if r.Raw != "" {
		fields = append(fields, r.Raw)
	}
	if r.Data != "" {
		fields = append(fields, r.Data)
	}
	keys := make([]string, 0, len(r.Headers))
	for k := range r.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fields = append(fields, r.Headers[k])
	}

	var out []string
	for _, f := range fields {
		for _, m := range rePlaceholder.FindAllStringSubmatch(f, -1) {
			expr := strings.TrimSpace(m[1])
			if expr == "" || rePlainIdent.MatchString(expr) {
				continue
			}
			out = append(out, expr)
		}
	}
	return out
}

// ---------------- 变量改名（规避 CEL 保留标识符） ----------------

// celIdentReserved 缓存「变量名是否与 afrog CEL 环境内置标识符冲突」的探测结果。
var celIdentReserved sync.Map // string -> bool

// reservedIdentPrefix 与转换器自己生成的变量（如 n2a_path）共用同一命名空间。
const reservedIdentPrefix = "n2a_"

// renameReservedVars 找出与 afrog CEL 内置标识符重名的 nuclei 变量并统一改名，
// 返回说明性告警（非 Gap，不影响分档）。
//
// 为什么必须改名：afrog 会把 set / brute 变量名声明进 CEL 环境
// （runner.UpdateCompileOption），名字若与内置符号冲突（nuclei 模板里常见的
// `variables: string: ...` 就是撞上内置类型 string），声明会直接失败
// （CEL: overlapping identifier for name 'string'），整个 PoC 的表达式都编译不过。
// 这是 afrog 手工编写 PoC 时同样存在的限制，不是转换器引入的。
//
// 改名只发生在「变量名出现的位置」：变量键、{{...}} 占位符内部、DSL 表达式里的标识符。
// 请求正文等字面量绝不改动，避免把正文里恰好出现的 string 之类的词改掉。
func renameReservedVars(tpl *nucleiTemplate) []Warning {
	names := collectTemplateVarNames(tpl)
	if len(names) == 0 {
		return nil
	}

	taken := make(map[string]bool, len(names))
	for _, n := range names {
		taken[strings.ToLower(n)] = true
	}

	renames := make(map[string]string)
	var warns []Warning
	for _, n := range names {
		if !isCelReservedIdent(n) {
			continue
		}
		newName := pickVarName(n, taken)
		taken[strings.ToLower(newName)] = true
		renames[strings.ToLower(n)] = newName
		warns = append(warns, Warning{
			Field:   "set",
			Message: fmt.Sprintf("变量 %q 与 afrog CEL 内置标识符重名，已改名为 %q", n, newName),
		})
	}
	if len(renames) == 0 {
		return nil
	}

	applyVarRenames(tpl, renames)
	return warns
}

// collectTemplateVarNames 收集模板里所有变量名（variables / constants / payloads 的键），
// 按小写去重并保持稳定顺序。
func collectTemplateVarNames(tpl *nucleiTemplate) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(k string) {
		name := strings.TrimSpace(k)
		if name == "" {
			return
		}
		lk := strings.ToLower(name)
		if seen[lk] {
			return
		}
		seen[lk] = true
		out = append(out, name)
	}
	for _, m := range []map[string]any{tpl.Constants, tpl.Variables} {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			add(k)
		}
	}
	for _, blocks := range [][]nucleiHTTP{tpl.HTTP, tpl.Requests} {
		for i := range blocks {
			keys := make([]string, 0, len(blocks[i].Payloads))
			for k := range blocks[i].Payloads {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				add(k)
			}
		}
	}
	return out
}

// isCelReservedIdent 判断 name 是否与 afrog CEL 环境里的内置标识符冲突。
// 判定方式：建一个只声明该名字的 afrog CEL 环境并编译一条最简表达式。
// CEL 的冲突检查发生在编译期（checker.checkDeclarations），因此必须真的编译一次：
// 声明与内置符号重名时会报 overlapping identifier for name 'xxx'。
func isCelReservedIdent(name string) bool {
	if v, ok := celIdentReserved.Load(name); ok {
		return v.(bool)
	}
	lib := runner.NewCustomLib()
	lib.UpdateCompileOption(name, decls.Dyn)
	reserved := true
	if env, err := lib.NewCelEnv(); err == nil {
		if _, iss := env.Compile("true"); iss.Err() == nil {
			reserved = false
		}
	}
	celIdentReserved.Store(name, reserved)
	return reserved
}

// pickVarName 为冲突变量挑一个不重名的新名字。
func pickVarName(orig string, taken map[string]bool) string {
	base := reservedIdentPrefix + orig
	name := base
	for i := 1; taken[strings.ToLower(name)] || isCelReservedIdent(name); i++ {
		name = fmt.Sprintf("%s_%d", base, i)
	}
	return name
}

// applyVarRenames 在模板里就地执行改名。
func applyVarRenames(tpl *nucleiTemplate, renames map[string]string) {
	renameMapKeys(tpl.Variables, renames)
	renameMapKeys(tpl.Constants, renames)
	for _, blocks := range [][]nucleiHTTP{tpl.HTTP, tpl.Requests} {
		for i := range blocks {
			renameBlockVars(&blocks[i], renames)
		}
	}
}

// renameMapKeys 改名 map 的键（variables / constants / payloads）。
func renameMapKeys(m map[string]any, renames map[string]string) {
	if len(m) == 0 {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for _, k := range keys {
		nn, ok := renames[strings.ToLower(strings.TrimSpace(k))]
		if !ok {
			continue
		}
		m[nn] = m[k]
		delete(m, k)
	}
}

// renameBlockVars 改名一个 http 请求块里的变量引用。
// 请求文本（path/body/raw/headers）只改 {{...}} 内部；DSL 表达式整条改。
func renameBlockVars(block *nucleiHTTP, renames map[string]string) {
	renameMapKeys(block.Payloads, renames)
	for i := range block.Path {
		block.Path[i] = renameVarsInText(block.Path[i], renames)
	}
	block.Body = renameVarsInText(block.Body, renames)
	for i := range block.Raw {
		block.Raw[i] = renameVarsInText(block.Raw[i], renames)
	}
	for k, v := range block.Headers {
		block.Headers[k] = renameVarsInText(v, renames)
	}
	for i := range block.Matchers {
		m := &block.Matchers[i]
		for j := range m.DSL {
			m.DSL[j] = renameVarsInExpr(m.DSL[j], renames)
		}
		for _, list := range [][]string{m.Words, m.Regex, m.Binary} {
			for j := range list {
				list[j] = renameVarsInText(list[j], renames)
			}
		}
	}
	for i := range block.Extractors {
		e := &block.Extractors[i]
		for j := range e.DSL {
			e.DSL[j] = renameVarsInExpr(e.DSL[j], renames)
		}
		for _, list := range [][]string{e.Regex, e.KVal, e.JSON, e.XPath} {
			for j := range list {
				list[j] = renameVarsInText(list[j], renames)
			}
		}
	}
}

// renameVarsInText 只在 {{...}} 占位符内部做标识符改名，占位符外的正文原样保留。
func renameVarsInText(s string, renames map[string]string) string {
	if len(renames) == 0 || !strings.Contains(s, "{{") {
		return s
	}
	return renameVarsScan(s, renames, true)
}

// renameVarsInExpr 对整个 nuclei DSL 表达式做标识符改名（字符串字面量内部不动）。
func renameVarsInExpr(s string, renames map[string]string) string {
	if len(renames) == 0 || s == "" {
		return s
	}
	return renameVarsScan(s, renames, false)
}

// renameVarsScan 扫描字符串，替换「整词」标识符。
// textOnly=true 时只在 {{...}} 内部替换（请求文本），否则整串替换（DSL 表达式）。
// 引号内的内容一律原样保留：占位符里可能出现 {{to_lower('{{randstr}}')}} 这类嵌套，
// 其引号内是字符串字面量而非变量引用。
func renameVarsScan(s string, renames map[string]string, textOnly bool) string {
	var b strings.Builder
	b.Grow(len(s))
	depth := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c == '{' && strings.HasPrefix(s[i:], "{{") {
			depth++
			b.WriteString("{{")
			i += 2
			continue
		}
		if c == '}' && strings.HasPrefix(s[i:], "}}") && depth > 0 {
			depth--
			b.WriteString("}}")
			i += 2
			continue
		}
		active := depth > 0 || !textOnly
		if active && (c == '\'' || c == '"') {
			j := i + 1
			for j < len(s) {
				if s[j] == '\\' && j+1 < len(s) {
					j += 2
					continue
				}
				if s[j] == c {
					j++
					break
				}
				j++
			}
			if j > len(s) {
				j = len(s)
			}
			b.WriteString(s[i:j])
			i = j
			continue
		}
		if active && isIdentStart(c) {
			j := i
			for j < len(s) && isIdentPart(s[j]) {
				j++
			}
			word := s[i:j]
			if nn, ok := renames[strings.ToLower(word)]; ok {
				b.WriteString(nn)
			} else {
				b.WriteString(word)
			}
			i = j
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

// ---------------- 报告 ----------------

func collectGaps(warns []Warning) []string {
	var gaps []string
	for _, w := range warns {
		if !w.Gap {
			continue
		}
		if w.Field != "" {
			gaps = append(gaps, w.Field+": "+w.Message)
			continue
		}
		gaps = append(gaps, w.Message)
	}
	return gaps
}

// buildReport 生成人类可读的转换报告（同时给 HTTP 接口与 CLI 复用）。
func buildReport(res *Result) string {
	var b strings.Builder

	fmt.Fprintf(&b, "class: %s\n", res.Class)
	switch res.Class {
	case ClassA:
		b.WriteString("说明: 逐字段直译，可直接使用\n")
	case ClassB:
		b.WriteString("说明: 机械扩展（set / brute / raw / 多 rule 合并），建议人工复核\n")
	case ClassC:
		b.WriteString("说明: 需人工重写，未产出 PoC\n")
	case ClassD:
		b.WriteString("说明: afrog 无对应运行时，不可转换\n")
	case ClassX:
		b.WriteString("说明: 模板不含可识别的协议段\n")
	}

	if len(res.Gaps) > 0 {
		b.WriteString("\n缺口:\n")
		for _, g := range res.Gaps {
			b.WriteString("- ")
			b.WriteString(g)
			b.WriteByte('\n')
		}
	}

	var notices []string
	for _, w := range res.Warnings {
		if w.Gap {
			continue
		}
		msg := w.Message
		if w.Field != "" {
			msg = w.Field + ": " + msg
		}
		notices = append(notices, msg)
	}
	if len(notices) > 0 {
		b.WriteString("\n提示:\n")
		for _, n := range notices {
			b.WriteString("- ")
			b.WriteString(n)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
