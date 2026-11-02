package passive

import (
	"bytes"
	"html"
	"net/url"
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

// Normalize 从响应正文中剔除会被原样反射的输入文本。
//
// 这是被动检测误报控制的核心步骤：当应用把参数值回显到页面时，注入后的 payload
// 本身就会让正文发生变化。若不做剔除，任何"反射型"页面都会被布尔差分误判成
// SQL 注入。这里同时覆盖原始值、payload、URL 编码与 HTML 转义四种形态。
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
		if esc := url.QueryEscape(s); esc != s && len(esc) >= 3 {
			out = bytes.ReplaceAll(out, []byte(esc), replacer)
		}
		if esc := html.EscapeString(s); esc != s && len(esc) >= 3 {
			out = bytes.ReplaceAll(out, []byte(esc), replacer)
		}
	}
	return out
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
