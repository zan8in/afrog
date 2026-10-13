package runner

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/gologger"
	"gopkg.in/yaml.v2"
)

// 本文件实现 output / extractors 共用的提取核心。
//
// 一个 extractor 条目有两种形态：
//   - 新写法（类型化）：Type = regex|json|kval|literal|cel，配 Name/Part/Regex/Group/All/Path/Key/Value；
//   - 旧写法：Extractor 是一个有序 map（输出名 -> CEL 表达式 / 字面量），为兼容保留。
//
// 两者由 Extractor 字段是否为空区分。所有提取最终都落到变量表，report=true 时
// 额外写入 Result.Extractor（extractors 语义；output 不写）。

// applyExtractors 是 output 与 extractors 共用的入口。
// report=true：结果同时进 Result.Extractor（extractors）；false：只进变量表（output）。
func (c *Checker) applyExtractors(entries []poc.Extractors, report bool) {
	for _, e := range entries {
		if len(e.Extractor) > 0 {
			c.applyLegacyExtractor(e.Type, e.Extractor, report)
			continue
		}
		c.applyTypedExtractor(e, report)
	}
}

// applyLegacyExtractor 处理旧写法：对 `输出名 -> 表达式` 的有序 map 逐条求值。
// type=word 时按字面量模板（替换 {{变量}}）处理，其余按 CEL 表达式处理。
func (c *Checker) applyLegacyExtractor(typ string, extMap yaml.MapSlice, report bool) {
	for _, item := range extMap {
		key, ok := item.Key.(string)
		if !ok || key == "" {
			continue
		}
		switch v := item.Value.(type) {
		case string:
			if typ == "word" {
				c.emitExtractor(key, setVariableMap(v, c.VariableMap), report)
				continue
			}
			out, err := c.CustomLib.RunEval(v, c.VariableMap)
			if err != nil {
				// output 旧行为：求值失败回退为字面量；extractors 旧行为：静默跳过。
				if !report {
					c.emitExtractor(key, v, report)
				}
				continue
			}
			c.setVariableFromEval(key, out)
			if report {
				c.appendExtractorResult(key)
			}
		default:
			// 非字符串（数字/布尔/列表等）直接落变量表。
			// 旧实现对 extractors 路径做 `.(string)` 强断言，会 panic（被顶层 recover 吞掉，表现为静默未命中），此处改为容错。
			c.emitExtractor(key, v, report)
		}
	}
}

// applyTypedExtractor 处理新写法（类型化提取器）。
func (c *Checker) applyTypedExtractor(e poc.Extractors, report bool) {
	name := strings.TrimSpace(e.Name)
	if name == "" || !isCelIdent(name) {
		c.warnExtractor("extractor: name %q 不是合法 CEL 标识符，已跳过", e.Name)
		return
	}

	typ := strings.ToLower(strings.TrimSpace(e.Type))
	if typ == "" {
		switch {
		case e.Regex != "":
			typ = "regex"
		case e.Path != "":
			typ = "json"
		case e.Key != "":
			typ = "kval"
		case e.Value != "":
			typ = "cel"
		default:
			c.warnExtractor("extractor %q: 未指定 type 且无可推断字段，已跳过", name)
			return
		}
	}

	switch typ {
	case "literal":
		c.emitExtractor(name, setVariableMap(e.Value, c.VariableMap), report)

	case "cel":
		out, err := c.CustomLib.RunEval(e.Value, c.VariableMap)
		if err != nil {
			c.warnExtractor("extractor %q: CEL 求值失败: %v", name, err)
			c.emitExtractor(name, "", report)
			return
		}
		c.setVariableFromEval(name, out)
		if report {
			c.appendExtractorResult(name)
		}

	case "regex", "regexp":
		c.extractRegex(e, name, report)

	case "json":
		c.extractJSON(e, name, report)

	case "kval", "kv":
		c.extractKval(e, name, report)

	default:
		c.warnExtractor("extractor %q: 未知 type %q，已跳过", name, e.Type)
	}
}

func (c *Checker) extractRegex(e poc.Extractors, name string, report bool) {
	if strings.TrimSpace(e.Regex) == "" {
		c.warnExtractor("extractor %q: type=regex 但缺少 regex", name)
		c.emitExtractor(name, emptyForAll(e.All), report)
		return
	}
	src, ok := c.extractorSource(e.Part)
	if !ok {
		c.warnExtractor("extractor %q: 取值来源 part=%q 不可用", name, e.Part)
		c.emitExtractor(name, emptyForAll(e.All), report)
		return
	}
	if e.All {
		c.emitExtractor(name, regexExtractAll(e.Regex, src, e.Group), report)
		return
	}
	v, matched := regexExtractFirst(e.Regex, src, e.Group)
	if !matched {
		v = ""
	}
	c.emitExtractor(name, v, report)
}

func (c *Checker) extractJSON(e poc.Extractors, name string, report bool) {
	src, ok := c.extractorSource(orDefault(e.Part, "body"))
	if !ok {
		c.warnExtractor("extractor %q: 取值来源 part=%q 不可用", name, e.Part)
		c.emitExtractor(name, "", report)
		return
	}
	var doc any
	if err := json.Unmarshal([]byte(src), &doc); err != nil {
		c.warnExtractor("extractor %q: JSON 解析失败: %v", name, err)
		c.emitExtractor(name, "", report)
		return
	}
	v, ok := jsonPathLookup(doc, e.Path)
	if !ok {
		c.emitExtractor(name, "", report)
		return
	}
	c.emitExtractor(name, normalizeJSONValue(v), report)
}

func (c *Checker) extractKval(e poc.Extractors, name string, report bool) {
	if strings.TrimSpace(e.Key) == "" {
		c.warnExtractor("extractor %q: type=kval 但缺少 key", name)
		c.emitExtractor(name, "", report)
		return
	}
	part := strings.ToLower(strings.TrimSpace(e.Part))
	if part == "" {
		part = "header"
	}

	var val string
	switch part {
	case "header", "headers":
		if resp, ok := c.VariableMap["response"].(*proto.Response); ok {
			val = headerLookup(resp.Headers, e.Key)
		}
	case "request_header":
		if req, ok := c.VariableMap["request"].(*proto.Request); ok {
			val = headerLookup(req.Headers, e.Key)
		}
	default:
		if src, ok := c.extractorSource(part); ok {
			val = kvFromText(src, e.Key)
		}
	}
	c.emitExtractor(name, val, report)
}

// extractorSource 把 part 解析成对应的文本内容。返回 (文本, 是否可用)。
func (c *Checker) extractorSource(part string) (string, bool) {
	part = strings.ToLower(strings.TrimSpace(part))
	if part == "" {
		part = "body"
	}
	switch part {
	case "body":
		if r, ok := c.VariableMap["response"].(*proto.Response); ok {
			return string(r.Body), true
		}
	case "raw", "response_raw":
		if r, ok := c.VariableMap["response"].(*proto.Response); ok {
			return string(r.Raw), true
		}
	case "header", "headers", "raw_header", "response_header":
		if r, ok := c.VariableMap["response"].(*proto.Response); ok {
			return string(r.RawHeader), true
		}
	case "text", "response_text":
		if v, ok := c.VariableMap["response_text"].(string); ok {
			return v, true
		}
	case "status", "code":
		if r, ok := c.VariableMap["response"].(*proto.Response); ok {
			return strconv.Itoa(int(r.Status)), true
		}
	case "request", "request_raw":
		if r, ok := c.VariableMap["request"].(*proto.Request); ok {
			return string(r.Raw), true
		}
	case "request_body":
		if r, ok := c.VariableMap["request"].(*proto.Request); ok {
			return string(r.Body), true
		}
	}
	return "", false
}

// emitExtractor 把提取结果写入变量表，report=true 时同时记录到结果（供报告展示）。
func (c *Checker) emitExtractor(name string, value any, report bool) {
	c.setVariableValue(name, value)
	if report {
		c.appendExtractorResult(name)
	}
}

func (c *Checker) appendExtractorResult(name string) {
	c.Result.Extractor = append(c.Result.Extractor, yaml.MapItem{Key: name, Value: c.VariableMap[name]})
}

func (c *Checker) warnExtractor(format string, args ...any) {
	gologger.Debug().Msgf(format, args...)
}

func emptyForAll(all bool) any {
	if all {
		return []string{}
	}
	return ""
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// headerLookup 大小写不敏感地取响应头。
func headerLookup(headers map[string]string, key string) string {
	if headers == nil {
		return ""
	}
	if v, ok := headers[key]; ok {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// kvFromText 从 `key: value` / `key=value` 文本里取值（大小写不敏感）。
func kvFromText(src, key string) string {
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimRight(line, "\r")
		i := strings.IndexAny(line, ":=")
		if i <= 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line[:i]), key) {
			return strings.TrimSpace(line[i+1:])
		}
	}
	return ""
}

// ---- regex 提取 ----

func regexExtractFirst(expr, raw, group string) (string, bool) {
	re, err := compileRegexp2(expr, regexp2.RE2)
	if err != nil {
		return "", false
	}
	m, _ := re.FindStringMatch(raw)
	if m == nil {
		return "", false
	}
	byIndex, byName := regexMatchGroups(m)
	return regexGroupValue(byIndex, byName, group)
}

func regexExtractAll(expr, raw, group string) []string {
	out := []string{}
	re, err := compileRegexp2(expr, regexp2.RE2)
	if err != nil {
		return out
	}
	m, _ := re.FindStringMatch(raw)
	for m != nil {
		byIndex, byName := regexMatchGroups(m)
		if v, ok := regexGroupValue(byIndex, byName, group); ok {
			out = append(out, v)
		}
		next, err := re.FindNextMatch(m)
		if err != nil {
			break
		}
		m = next
	}
	return out
}

func regexMatchGroups(m *regexp2.Match) ([]string, map[string]string) {
	gs := m.Groups()
	byIndex := make([]string, len(gs))
	byName := make(map[string]string, len(gs))
	for i, g := range gs {
		byIndex[i] = g.String()
		if g.Name != "" {
			byName[g.Name] = g.String()
		}
	}
	return byIndex, byName
}

// regexGroupValue 按 group 取值：空=整段匹配(0)，纯数字=序号，否则=命名组。
func regexGroupValue(byIndex []string, byName map[string]string, group string) (string, bool) {
	group = strings.TrimSpace(group)
	if group == "" {
		if len(byIndex) == 0 {
			return "", false
		}
		return byIndex[0], true
	}
	if n, err := strconv.Atoi(group); err == nil {
		if n >= 0 && n < len(byIndex) {
			return byIndex[n], true
		}
		return "", false
	}
	v, ok := byName[group]
	return v, ok
}

// ---- JSON 提取 ----

// jsonPathLookup 按 `$.a.b[0].c` / `a.b[0].c` 形式的路径取值。
func jsonPathLookup(doc any, path string) (any, bool) {
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "$")
	path = strings.TrimPrefix(path, ".")
	if path == "" {
		return doc, true
	}
	cur := doc
	for _, seg := range splitJSONPath(path) {
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[seg]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

func splitJSONPath(path string) []string {
	segs := make([]string, 0, 4)
	for _, part := range strings.Split(path, ".") {
		part = strings.TrimSpace(part)
		for part != "" {
			open := strings.IndexByte(part, '[')
			if open < 0 {
				segs = append(segs, part)
				break
			}
			if open > 0 {
				segs = append(segs, part[:open])
			}
			close := strings.IndexByte(part, ']')
			if close < 0 {
				segs = append(segs, part[open+1:])
				break
			}
			segs = append(segs, strings.TrimSpace(part[open+1:close]))
			part = strings.TrimSpace(part[close+1:])
		}
	}
	return segs
}

// normalizeJSONValue 把 JSON 解出的值规整成变量表友好类型。
func normalizeJSONValue(v any) any {
	switch t := v.(type) {
	case nil:
		return ""
	case []any:
		out := make([]string, 0, len(t))
		for _, it := range t {
			out = append(out, jsonScalarToString(it))
		}
		return out
	case map[string]any:
		out := make(map[string]string, len(t))
		for k, it := range t {
			out[k] = jsonScalarToString(it)
		}
		return out
	default:
		// string / float64 / bool 原样返回，交给 setVariableValue 判型
		return v
	}
}

func jsonScalarToString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}
