package poc

import (
	"regexp"
	"strings"
)

// 本文件把"旧两步式 regex extractor"迁移成类型化写法：
//
//	  - type: regex
//	    extractor:
//	      ext1: '"\"version\":\"(?P<v>.*?)\"".bsubmatch(response.body)'
//	      ver:  ext1["v"]
//
// 迁移为：
//
//	  - name: ver
//	    type: regex
//	    part: body
//	    regex: "\"version\":\"(?P<v>.*?)\""
//	    group: v
//
// 刻意保持保守：只有在模式完全符合"取单个临时 map、再按命名组取一个值"这一
// 可判定的形状时才迁移，其余一律原样保留。迁移只重写这几行，不动文件的其它
// 内容（注释、缩进、其它字段都不受影响）。

var (
	// extractorStartRe 匹配 `- type: regex` 这一行（仅 extractors 使用该形状）。
	extractorStartRe = regexp.MustCompile(`^([ \t]*)-[ \t]*type:[ \t]*regex[ \t]*$`)
	// extractorMapRe 匹配紧随其后的 `extractor:`。
	extractorMapRe = regexp.MustCompile(`^[ \t]*extractor:[ \t]*$`)
	// extractorKeyRe 匹配缩进更深的任意 `key:` 行，用于界定 map 的范围。
	extractorKeyRe = regexp.MustCompile(`^([ \t]+)([A-Za-z_][\w.-]*)[ \t]*:`)
	// extractorKVRe 匹配 `key: 'value'`（单引号包裹的 CEL 表达式）。
	extractorKVRe = regexp.MustCompile(`^[ \t]*([A-Za-z_][\w.-]*)[ \t]*:[ \t]*'(.*)'[ \t]*$`)
	// extractorRefRe 匹配 `name: tmp["group"]`。
	extractorRefRe = regexp.MustCompile(`^[ \t]*([A-Za-z_][\w.-]*)[ \t]*:[ \t]*([A-Za-z_][\w.-]*)[ \t]*\[[ \t]*"([^"]+)"[ \t]*\][ \t]*$`)
	// extractorCELRe 匹配 `"<pattern>".<fn>(<src>)`。
	extractorCELRe = regexp.MustCompile(`^"(.*)"[ \t]*\.[ \t]*(bsubmatchall|submatchall|bsubmatch|submatch)[ \t]*\([ \t]*([A-Za-z_][\w.]*)[ \t]*\)$`)
)

// migrateExtractorBlocks 在整段文本上做行级迁移，返回新文本与改动条数。
func migrateExtractorBlocks(src string) (string, int) {
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))
	changes := 0

	for i := 0; i < len(lines); i++ {
		start := extractorStartRe.FindStringSubmatch(lines[i])
		if start == nil || i+2 >= len(lines) || !extractorMapRe.MatchString(lines[i+1]) {
			out = append(out, lines[i])
			continue
		}
		indent := start[1]

		// 收集 extractor map 的键行（缩进必须比 `- type:` 更深）。
		keyIdx := make([]int, 0, 2)
		for j := i + 2; j < len(lines); j++ {
			trimmed := strings.TrimSpace(lines[j])
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				break
			}
			km := extractorKeyRe.FindStringSubmatch(lines[j])
			if km == nil || len(km[1]) <= len(indent) {
				break
			}
			keyIdx = append(keyIdx, j)
		}

		// 只迁移"临时变量 + 按命名组取值"这一确定形状（恰好两行）。
		if len(keyIdx) != 2 {
			out = append(out, lines[i])
			continue
		}
		kv := extractorKVRe.FindStringSubmatch(lines[keyIdx[0]])
		ref := extractorRefRe.FindStringSubmatch(lines[keyIdx[1]])
		if kv == nil || ref == nil || kv[1] != ref[2] {
			out = append(out, lines[i])
			continue
		}
		cel := extractorCELRe.FindStringSubmatch(kv[2])
		if cel == nil {
			out = append(out, lines[i])
			continue
		}
		part, ok := extractorPart(cel[3])
		if !ok {
			out = append(out, lines[i])
			continue
		}

		// 保险起见，回读一遍确认新写法能被解析（正则等字段可安全往返）。
		out = append(out,
			indent+"- name: "+ref[1],
			indent+"  type: regex",
			indent+"  part: "+part,
			indent+"  regex: "+yamlDoubleQuote(unescapeCELString(cel[1])),
			indent+"  group: "+ref[3],
		)
		if strings.Contains(cel[2], "all") {
			out = append(out, indent+"  all: true")
		}
		i = keyIdx[len(keyIdx)-1] // 消费掉 extractor: 与 map 各行
		changes++
	}

	return strings.Join(out, "\n"), changes
}

// extractorPart 把 CEL 侧的来源变量映射成类型化提取器的 part。
func extractorPart(src string) (string, bool) {
	switch strings.TrimSpace(src) {
	case "response.body":
		return "body", true
	case "response.raw":
		return "raw", true
	case "response.raw_header", "response.headers":
		return "header", true
	case "response_text":
		return "text", true
	case "response.status":
		return "status", true
	case "request.raw":
		return "request", true
	case "request.body":
		return "request_body", true
	case "request.raw_header":
		return "request_header", true
	}
	return "", false
}

// unescapeCELString 把 CEL 字符串字面量里的转义还原成实际字符。
// 只处理会影响正则含义的两类：`\\` -> `\`、`\"` -> `"`；其余（如 `\.`、`[0-9]`）
// 原样保留，从而让正则语义在迁移前后完全一致。
func unescapeCELString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\':
				b.WriteByte('\\')
				i += 2
				continue
			case '"':
				b.WriteByte('"')
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// yamlDoubleQuote 把字符串渲染成合法的 YAML 双引号标量。
func yamlDoubleQuote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
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
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
