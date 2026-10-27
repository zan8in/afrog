package nuclei2afrog

import (
	"fmt"
	"regexp"
	"strings"
)

// Class 是转换结果的分档（见 docs/plan/afrog-nuclei-template-conversion-spec.md §4）。
type Class string

const (
	ClassA Class = "A" // 逐字段直译
	ClassB Class = "B" // 机械扩展
	ClassC Class = "C" // 需语义重写
	ClassD Class = "D" // 不可转
	ClassX Class = "X" // 无协议段
)

// Warning 记录转换过程中的降级、丢弃与缺口。
type Warning struct {
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
	Gap     bool   `json:"gap,omitempty"`
}

var (
	// afrog 无对应运行时的协议段
	deadProtocolKeys = []string{"code", "file", "headless", "javascript", "whois", "websocket"}
	// 与 afrog rules 模型语义差异大、需人工重写的协议段
	rewriteProtocolKeys = []string{"network", "tcp", "udp", "dns", "ssl", "offline-http"}
	// afrog 可直接表达的协议段
	httpProtocolKeys = []string{"http", "requests"}
)

// reMultiResponseVar 命中 nuclei 的多响应变量（body_2 / status_code_3 / header_1 ...）。
var reMultiResponseVar = regexp.MustCompile(`\b(?:body|raw|header|all_headers|status_code|content_length)_\d+\b`)

// classification 是一次模板级结构判定的结果。
type classification struct {
	class    Class // D / X / C，或空串表示「A/B 待定」
	reason   string
	reasonsB []string
	warns    []Warning
}

// classify 只做**结构层面**的判定：协议段、flow、interactsh、xpath/llm、
// internal extractor、多响应变量 → C（或 D/X）。DSL 函数缺口导致的 C 由翻译阶段追加。
func classify(tpl *nucleiTemplate, topKeys map[string]bool) classification {
	c := classification{}

	for _, k := range deadProtocolKeys {
		if topKeys[k] {
			c.class = ClassD
			c.reason = fmt.Sprintf("协议段 %q 在 afrog 中无对应运行时，无法转换", k)
			return c
		}
	}

	if topKeys["flow"] {
		c.class = ClassC
		c.reason = "含 flow，nuclei 的请求编排无法用 afrog 的 rules 表达"
		return c
	}
	for _, k := range rewriteProtocolKeys {
		if topKeys[k] {
			c.class = ClassC
			c.reason = fmt.Sprintf("协议段 %q 与 afrog rules 模型语义差异大，需人工重写", k)
			return c
		}
	}

	hasHTTP := false
	for _, k := range httpProtocolKeys {
		if topKeys[k] {
			hasHTTP = true
			break
		}
	}
	if !hasHTTP {
		c.class = ClassX
		c.reason = "模板不含任何可识别的协议段"
		return c
	}

	blocks := tpl.httpBlocks()

	if hasInteractsh(blocks) {
		c.class = ClassC
		c.reason = "含 interactsh 反连交互，afrog 需改用 oobCheck 且必须人工确认语义"
		return c
	}

	for i := range blocks {
		for _, m := range blocks[i].Matchers {
			switch strings.ToLower(strings.TrimSpace(m.Type)) {
			case "xpath", "llm":
				c.class = ClassC
				c.reason = fmt.Sprintf("matcher 类型 %q 在 afrog CEL 中无对应表达", m.Type)
				return c
			}
		}
		for _, e := range blocks[i].Extractors {
			switch strings.ToLower(strings.TrimSpace(e.Type)) {
			case "xpath", "llm":
				c.class = ClassC
				c.reason = fmt.Sprintf("extractor 类型 %q 在 afrog 中无对应", e.Type)
				return c
			}
			if e.Internal {
				c.class = ClassC
				c.reason = "含 internal: true extractor，afrog 的 rule 之间没有变量传递，请求链会断裂"
				return c
			}
		}
	}

	if v := findMultiResponseVar(blocks); v != "" {
		c.class = ClassC
		c.reason = fmt.Sprintf("引用了多响应变量 %q，afrog 每次 rule 只保留当前响应", v)
		return c
	}

	// ---- 以下为 A / B 的判定 ----
	if len(blocks) > 1 {
		c.reasonsB = append(c.reasonsB, fmt.Sprintf("含 %d 个 http 请求块，多个 rule 的结果粒度会被合并", len(blocks)))
	}
	if len(tpl.Variables) > 0 || len(tpl.Constants) > 0 {
		c.reasonsB = append(c.reasonsB, "含顶层 variables/constants，需落成 afrog set")
	}
	for i := range blocks {
		if len(blocks[i].Payloads) > 0 {
			c.reasonsB = append(c.reasonsB, fmt.Sprintf("第 %d 个 http 块含 payloads，需落成 afrog brute", i+1))
		}
		if len(blocks[i].Raw) > 0 {
			c.reasonsB = append(c.reasonsB, fmt.Sprintf("第 %d 个 http 块使用 raw 请求", i+1))
		}
		if len(blocks[i].Path) > 1 {
			c.reasonsB = append(c.reasonsB, fmt.Sprintf("第 %d 个 http 块含多条 path，需落成 afrog brute", i+1))
		}
		for _, m := range blocks[i].Matchers {
			if len(m.DSL) > 0 {
				c.reasonsB = append(c.reasonsB, fmt.Sprintf("第 %d 个 http 块含 dsl matcher，表达式必须整条重写", i+1))
				break
			}
		}
	}

	return c
}

// hasInteractsh 判断请求块中是否出现 interactsh 相关标记。
func hasInteractsh(blocks []nucleiHTTP) bool {
	for i := range blocks {
		if strings.Contains(strings.ToLower(blocks[i].Body), "interactsh") {
			return true
		}
		for _, s := range blocks[i].Path {
			if strings.Contains(strings.ToLower(s), "interactsh") {
				return true
			}
		}
		for _, s := range blocks[i].Raw {
			if strings.Contains(strings.ToLower(s), "interactsh") {
				return true
			}
		}
		for k, v := range blocks[i].Headers {
			if strings.Contains(strings.ToLower(k+v), "interactsh") {
				return true
			}
		}
		if strings.Contains(strings.ToLower(mustJSON(blocks[i].Payloads)), "interactsh") {
			return true
		}
		for _, m := range blocks[i].Matchers {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(m.Part)), "interactsh") {
				return true
			}
			for _, d := range m.DSL {
				if strings.Contains(strings.ToLower(d), "interactsh") {
					return true
				}
			}
		}
		for _, e := range blocks[i].Extractors {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(e.Part)), "interactsh") {
				return true
			}
			for _, d := range e.DSL {
				if strings.Contains(strings.ToLower(d), "interactsh") {
					return true
				}
			}
		}
	}
	return false
}

// findMultiResponseVar 返回第一个命中的多响应变量名，未命中返回空串。
func findMultiResponseVar(blocks []nucleiHTTP) string {
	var found string
	for i := 0; i < len(blocks) && found == ""; i++ {
		for _, m := range blocks[i].Matchers {
			for _, d := range m.DSL {
				if v := reMultiResponseVar.FindString(d); v != "" {
					found = v
					break
				}
			}
			for _, v := range m.Words {
				if v == "body_2" || v == "body_1" || v == "body_3" {
					found = v
				}
			}
		}
		for _, e := range blocks[i].Extractors {
			for _, d := range e.DSL {
				if v := reMultiResponseVar.FindString(d); v != "" {
					found = v
					break
				}
			}
		}
	}
	return found
}

func mustJSON(v any) string {
	if v == nil {
		return ""
	}
	var b strings.Builder
	writeAnyJSON(&b, v)
	return b.String()
}

func writeAnyJSON(b *strings.Builder, v any) {
	switch vv := v.(type) {
	case string:
		b.WriteString(vv)
	case []any:
		for _, it := range vv {
			writeAnyJSON(b, it)
			b.WriteByte(' ')
		}
	case map[string]any:
		for k, it := range vv {
			b.WriteString(k)
			b.WriteByte(' ')
			writeAnyJSON(b, it)
		}
	case map[any]any:
		for k, it := range vv {
			fmt.Fprint(b, k)
			b.WriteByte(' ')
			writeAnyJSON(b, it)
		}
	}
}
