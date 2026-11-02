package passive

import (
	"bytes"
	"html"
	"net/url"
	"strings"
)

// Similarity 计算两段响应正文的结构相似度，取值 [0,1]。
//
// 采用按行的多重集 Jaccard：核心用途不是"像不像"，而是判断"有没有实质变化"。
// 对布尔盲注而言，真正的信号是页面结构变化（结果集为空 / 报错页），而不是
// 反射参数的文本跳动——因此反射内容必须先经 Normalize 处理再进这里。
func Similarity(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	if len(a) == 0 || len(b) == 0 {
		return 0
	}

	la := splitLines(a)
	lb := splitLines(b)

	counts := make(map[string]int, len(la))
	for _, line := range la {
		counts[line]++
	}

	inter := 0
	for _, line := range lb {
		if counts[line] > 0 {
			counts[line]--
			inter++
		}
	}

	union := len(la) + len(lb) - inter
	if union == 0 {
		return 1
	}
	return float64(inter) / float64(union)
}

// DiffLines 返回两段正文按行多重集的对称差行数，即「有多少行对不上」。
//
// 与 Similarity 互补：相似度是相对量，短页面上 1 行差异就能把它压到阈值之下
// （N 行差 1 行，相似度恰为 (N-1)/(N+1)）；对称差行数是绝对量，能直接回答
// 「到底差了几行」，供「少量噪声行不影响结构结论」这类判定使用。
func DiffLines(a, b []byte) int {
	la := splitLines(a)
	lb := splitLines(b)

	counts := make(map[string]int, len(la))
	for _, line := range la {
		counts[line]++
	}

	inter := 0
	for _, line := range lb {
		if counts[line] > 0 {
			counts[line]--
			inter++
		}
	}
	return len(la) + len(lb) - 2*inter
}

// LineCount 返回正文的非空行数，与 Similarity / DiffLines 使用同一套切行口径。
//
// 用途是判断「这是不是一个短页面」：相似度是相对量，同样的绝对差异在短页面上
// 权重更大，判定短页需要先知道页面规模。
func LineCount(b []byte) int {
	return len(splitLines(b))
}

// Normalize 从响应正文中剔除会被原样反射的输入文本。
//
// 这是被动检测误报控制的核心步骤：当应用把参数值回显到页面时，注入后的 payload
// 本身就会让正文发生变化。若不做剔除，任何"反射型"页面都会被布尔差分误判成
// SQL 注入。这里同时覆盖原始值、URL 编码与多种 HTML/XML 转义形态。
//
// strips 中的短字符串（长度 < 3）会被忽略，避免把 "1" 这类值全局抹掉导致
// 大片正文被吞掉、进而掩盖真实差异。
func Normalize(body []byte, strips ...string) []byte {
	if len(body) == 0 || len(strips) == 0 {
		return body
	}

	out := body
	// 必须按长度降序替换：payload 通常以原始值开头（如 "abc' AND ..."），
	// 若先替换 "abc"，剩余片段就无法再被整体剔除，反射内容会残留成假差异。
	for _, s := range sortByLenDesc(strips) {
		if len(s) < 3 {
			continue
		}
		replacer := []byte("__AFROG_ECHO__")
		out = bytes.ReplaceAll(out, []byte(s), replacer)
		for _, esc := range escapeVariants(s) {
			if len(esc) < 3 || esc == s {
				continue
			}
			out = bytes.ReplaceAll(out, []byte(esc), replacer)
		}
	}
	return out
}

// escapeVariants 返回一段文本在真实站点上最常见的转义形态。
//
// 反射内容能否被剔除，直接决定布尔差分的准确性：只要漏掉一种常见转义形态，
// 反射文本就会残留在正文里，把"结构相同、仅反射不同"误判成结构差异，进而漏报
// 真实注入点（PortSwigger 靶场即把单引号转义成 XML 命名实体 &apos;，而 Go 的
// html.EscapeString 产出的是 &#39;，两者不匹配）。这里覆盖 URL 编码、十进制实体、
// XML 命名实体与十六进制实体四类。
func escapeVariants(s string) []string {
	variants := []string{url.QueryEscape(s)}
	esc := html.EscapeString(s)
	if esc != s {
		variants = append(variants, esc)
		// XML 命名实体（&apos;/&quot;）与十六进制实体（&#x27;/&#x22;）。
		named := strings.NewReplacer("&#39;", "&apos;", "&#34;", "&quot;").Replace(esc)
		hex := strings.NewReplacer("&#39;", "&#x27;", "&#34;", "&#x22;").Replace(esc)
		variants = append(variants, named, hex)
	}
	return variants
}

// sortByLenDesc 返回按长度降序排列的副本。调用方的切片顺序不应被修改。
func sortByLenDesc(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && len(out[j]) > len(out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// splitLines 按行切分响应正文，丢弃空行。
//
// 空行在 HTML 中数量巨大且不承载语义，保留会把相似度整体拉高，使真实的结构
// 变化被稀释。
func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	raw := bytes.Split(b, []byte("\n"))
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		t := bytes.TrimSpace(line)
		if len(t) == 0 {
			continue
		}
		out = append(out, string(t))
	}
	if len(out) == 0 {
		// 全空正文（如单行无换行的响应）退化为整段比较。
		return []string{string(bytes.TrimSpace(b))}
	}
	return out
}
