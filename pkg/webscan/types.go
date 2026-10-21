// Package webscan 提供数据驱动的 Web 指纹识别：对一次 HTTP 响应（响应头、正文、
// favicon）做规则匹配，输出结构化技术栈。
//
// 设计上与 pkg/portscan 的端口指纹保持一致：YAML 描述规则、regexp2 匹配并限制单条
// 正则耗时、四级可信度、外置目录覆盖内置。区别只在观察素材——端口指纹看的是 TCP
// banner，这里看的是 HTTP 响应。
package webscan

import (
	"strings"

	"github.com/zan8in/afrog/v3/pkg/portscan"
)

// Confidence 直接复用端口指纹的可信度标尺，使 -ps 与 -w 的输出语义完全一致。
type Confidence = portscan.Confidence

const (
	// ConfidenceUnknown 没有任何证据。
	ConfidenceUnknown = portscan.ConfidenceUnknown
	// ConfidenceProbable 弱特征命中（softmatch 或显式 probable）。
	ConfidenceProbable = portscan.ConfidenceProbable
	// ConfidenceCertain 明确特征命中（如 meta generator、专属响应头）。
	ConfidenceCertain = portscan.ConfidenceCertain
)

// Technology 是一条命中的 Web 指纹。
type Technology struct {
	Name       string
	Version    string
	Category   string
	CPE        string
	Confidence Confidence
	RuleID     string
}

// MatchTokens 返回一条 Web 指纹在 PoC requires 门控里可用的标识词，全部小写、去重。
//
// 返回规则 id、技术名的两种写法（原样小写、空格转连字符）以及分类，使 PoC 作者既能写
// requires: [wordpress]（id/name），也能写 requires: [apache-shiro]（连字符写法）或
// requires: [cms]（分类）。
func MatchTokens(ruleID, name, category string) []string {
	tokens := make([]string, 0, 4)
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			return
		}
		for _, existing := range tokens {
			if existing == s {
				return
			}
		}
		tokens = append(tokens, s)
	}
	add(ruleID)
	add(name)
	add(strings.ReplaceAll(name, " ", "-"))
	add(category)
	return tokens
}

// MatchTokens 返回该技术在 requires 门控里可用的标识词。
func (t Technology) MatchTokens() []string {
	return MatchTokens(t.RuleID, t.Name, t.Category)
}

// Response 是一次 Web 探测拿到的原始素材，也是指纹匹配的输入。
type Response struct {
	// StatusCode 是 HTTP 状态码。
	StatusCode int
	// Headers 是响应头，键名小写。
	Headers map[string]string
	// Body 是响应正文。
	Body []byte
	// Favicon 是 /favicon.ico 的内容，为空表示未抓取。
	Favicon []byte
}

// Result 是一次 Web 指纹匹配的结果。
type Result struct {
	// Technologies 按可信度从高到低排序，同名同版本只保留一条。
	Technologies []Technology
	// Confidence 是全部命中里最高的可信度。
	Confidence Confidence
	// FaviconHash 是 favicon 的 mmh3 哈希，未抓取时为空。
	FaviconHash string
}
