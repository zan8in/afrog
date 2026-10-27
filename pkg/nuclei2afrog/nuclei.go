package nuclei2afrog

import (
	"sort"
	"strings"
)

// 本文件只声明「转换所需」的 nuclei 模板字段子集。
// 未列出的字段视为 afrog 无对应语义，由 classify 统一降级/告警。

// nucleiTemplate 是 nuclei HTTP 模板的解析结构。
// http / requests 两种键都接受（nuclei 历史上二者等价）。
type nucleiTemplate struct {
	ID               string         `yaml:"id"`
	Info             nucleiInfo     `yaml:"info"`
	Variables        map[string]any `yaml:"variables"`
	Constants        map[string]any `yaml:"constants"`
	HTTP             []nucleiHTTP   `yaml:"http"`
	Requests         []nucleiHTTP   `yaml:"requests"`
	Flow             string         `yaml:"flow"`
	StopAtFirstMatch bool           `yaml:"stop-at-first-match"`
}

type nucleiInfo struct {
	Name           string               `yaml:"name"`
	Author         any                  `yaml:"author"`
	Severity       string               `yaml:"severity"`
	Description    string               `yaml:"description"`
	Reference      any                  `yaml:"reference"`
	Tags           any                  `yaml:"tags"`
	Metadata       map[string]any       `yaml:"metadata"`
	Classification nucleiClassification `yaml:"classification"`
}

type nucleiClassification struct {
	CVEID          any     `yaml:"cve-id"`
	CWEID          any     `yaml:"cwe-id"`
	CVSSMetrics    string  `yaml:"cvss-metrics"`
	CVSSScore      float64 `yaml:"cvss-score"`
	CPE            string  `yaml:"cpe"`
	EPSSScore      float64 `yaml:"epss-score"`
	EPSSPercentile float64 `yaml:"epss-percentile"`
}

type nucleiHTTP struct {
	Method            string            `yaml:"method"`
	Path              []string          `yaml:"path"`
	Headers           map[string]string `yaml:"headers"`
	Body              string            `yaml:"body"`
	Raw               []string          `yaml:"raw"`
	Redirects         bool              `yaml:"redirects"`
	HostRedirects     bool              `yaml:"host-redirects"`
	MaxRedirects      int               `yaml:"max-redirects"`
	CookieReuse       bool              `yaml:"cookie-reuse"`
	Unsafe            bool              `yaml:"unsafe"`
	ReqCondition      bool              `yaml:"req-condition"`
	Race              bool              `yaml:"race"`
	RaceCount         int               `yaml:"race_count"`
	MatchersCondition string            `yaml:"matchers-condition"`
	Matchers          []nucleiMatcher   `yaml:"matchers"`
	Extractors        []nucleiExtractor `yaml:"extractors"`
	Payloads          map[string]any    `yaml:"payloads"`
	Attack            string            `yaml:"attack"`
	StopAtFirstMatch  bool              `yaml:"stop-at-first-match"`
	SelfContained     bool              `yaml:"self-contained"`
	Signature         string            `yaml:"signature"`
	IterateAll        bool              `yaml:"iterate-all"`
	Fuzzing           []any             `yaml:"fuzzing"`
	DisablePathMerge  bool              `yaml:"disable-path-automerge"`
	PipelineConns     int               `yaml:"pipeline-concurrent-connections"`
	Threads           int               `yaml:"threads"`
	MaxSize           int               `yaml:"max-size"`
	Unknown           map[string]any    `yaml:",inline"`
}

type nucleiMatcher struct {
	Type            string   `yaml:"type"`
	Name            string   `yaml:"name"`
	Part            string   `yaml:"part"`
	Condition       string   `yaml:"condition"`
	Negative        bool     `yaml:"negative"`
	Internal        bool     `yaml:"internal"`
	Status          []int    `yaml:"status"`
	Size            []int    `yaml:"size"`
	Words           []string `yaml:"words"`
	Regex           []string `yaml:"regex"`
	Binary          []string `yaml:"binary"`
	DSL             []string `yaml:"dsl"`
	XPath           []string `yaml:"xpath"`
	Encoding        string   `yaml:"encoding"`
	CaseInsensitive bool     `yaml:"case-insensitive"`
	MatchAll        bool     `yaml:"match-all"`
}

type nucleiExtractor struct {
	Type            string   `yaml:"type"`
	Name            string   `yaml:"name"`
	Part            string   `yaml:"part"`
	Regex           []string `yaml:"regex"`
	Group           int      `yaml:"group"`
	KVal            []string `yaml:"kval"`
	JSON            []string `yaml:"json"`
	XPath           []string `yaml:"xpath"`
	Attribute       string   `yaml:"attribute"`
	DSL             []string `yaml:"dsl"`
	Internal        bool     `yaml:"internal"`
	CaseInsensitive bool     `yaml:"case-insensitive"`
}

// httpBlocks 返回模板里的 HTTP 请求块（http 优先，回退 requests）。
func (t *nucleiTemplate) httpBlocks() []nucleiHTTP {
	if len(t.HTTP) > 0 {
		return t.HTTP
	}
	return t.Requests
}

// asStringList 把 nuclei 的「字符串或字符串数组」统一成 []string。
// splitComma=true 时，单个字符串会按逗号切分（author / tags 既有写法）。
func asStringList(v any, splitComma bool) []string {
	switch vv := v.(type) {
	case nil:
		return nil
	case string:
		if splitComma {
			var out []string
			for _, part := range strings.Split(vv, ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					out = append(out, part)
				}
			}
			return out
		}
		if vv == "" {
			return nil
		}
		return []string{vv}
	case []any:
		var out []string
		for _, item := range vv {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case []string:
		return vv
	default:
		return nil
	}
}

func joinComma(v any) string {
	return strings.Join(asStringList(v, true), ",")
}

// normalizeSeverity 把 nuclei 严重度映射到 afrog（validator 只接受 5 档）。
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info", "low", "medium", "high", "critical":
		return strings.ToLower(strings.TrimSpace(s))
	case "unknown", "":
		return "info"
	default:
		return "info"
	}
}

// sortedKeys 返回 map 的有序键，仅用于生成稳定输出。
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
