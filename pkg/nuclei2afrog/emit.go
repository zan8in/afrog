package nuclei2afrog

import (
	"sort"

	"github.com/zan8in/afrog/v3/pkg/poc"
	"gopkg.in/yaml.v2"
)

// 本文件把 poc.Poc 序列化成 afrog 风格的 YAML。
//
// 注意：poc.RuleMapSlice 与 poc.Rule 只实现了 UnmarshalYAML，没有 MarshalYAML，
// 直接 yaml.Marshal(poc.Poc) 会丢失 rules 的有序结构（Rule 的 order 字段是私有的，
// 且 yaml 标签与 desired 输出顺序不一致）。因此这里自建 yaml.MapSlice 转换层，
// 显式控制字段顺序，与 afrog 现有 PoC 的书写习惯保持一致。

// emit 把翻译结果序列化为 afrog PoC YAML。
func emit(p *poc.Poc) ([]byte, error) {
	root := make(yaml.MapSlice, 0, 6)
	root = append(root, yaml.MapItem{Key: "id", Value: p.Id})
	root = append(root, yaml.MapItem{Key: "info", Value: emitInfo(p.Info)})
	if len(p.Set) > 0 {
		root = append(root, yaml.MapItem{Key: "set", Value: p.Set})
	}
	if len(p.Rules) > 0 {
		root = append(root, yaml.MapItem{Key: "rules", Value: emitRules(p.Rules)})
	}
	if len(p.Extractors) > 0 {
		root = append(root, yaml.MapItem{Key: "extractors", Value: emitExtractors(p.Extractors)})
	}
	if p.Expression != "" {
		root = append(root, yaml.MapItem{Key: "expression", Value: p.Expression})
	}
	// 不输出 transport：afrog 的协议类型由 rule.request.type 表达，
	// HTTP 作为默认类型留空（afrog 自带 PoC 同样省略）。
	return yaml.Marshal(root)
}

// emitInfo 组装 info 段（顺序与 afrog 现有 PoC 一致）。
func emitInfo(i poc.Info) yaml.MapSlice {
	out := make(yaml.MapSlice, 0, 14)
	out = append(out, yaml.MapItem{Key: "name", Value: i.Name})
	if i.Author != "" {
		out = append(out, yaml.MapItem{Key: "author", Value: i.Author})
	}
	out = append(out, yaml.MapItem{Key: "severity", Value: i.Severity})
	out = append(out, yaml.MapItem{Key: "verified", Value: i.Verified})
	if i.Description != "" {
		out = append(out, yaml.MapItem{Key: "description", Value: i.Description})
	}
	if len(i.Reference) > 0 {
		out = append(out, yaml.MapItem{Key: "reference", Value: i.Reference})
	}
	if i.Affected != "" {
		out = append(out, yaml.MapItem{Key: "affected", Value: i.Affected})
	}
	if i.Solutions != "" {
		out = append(out, yaml.MapItem{Key: "solutions", Value: i.Solutions})
	}
	if i.Tags != "" {
		out = append(out, yaml.MapItem{Key: "tags", Value: i.Tags})
	}
	if len(i.Requires) > 0 {
		out = append(out, yaml.MapItem{Key: "requires", Value: i.Requires})
	}
	if i.RequiresMode != "" {
		out = append(out, yaml.MapItem{Key: "requires-mode", Value: i.RequiresMode})
	}
	if c, ok := emitClassification(i.Classification); ok {
		out = append(out, yaml.MapItem{Key: "classification", Value: c})
	}
	if i.Created != "" {
		out = append(out, yaml.MapItem{Key: "created", Value: i.Created})
	}
	return out
}

// emitClassification 仅在分类信息非空时输出。
func emitClassification(c poc.Classification) (yaml.MapSlice, bool) {
	if c.CvssMetrics == "" && c.CvssScore == 0 && c.CveId == "" && c.CweId == "" {
		return nil, false
	}
	out := make(yaml.MapSlice, 0, 4)
	if c.CvssMetrics != "" {
		out = append(out, yaml.MapItem{Key: "cvss-metrics", Value: c.CvssMetrics})
	}
	if c.CvssScore != 0 {
		out = append(out, yaml.MapItem{Key: "cvss-score", Value: c.CvssScore})
	}
	if c.CveId != "" {
		out = append(out, yaml.MapItem{Key: "cve-id", Value: c.CveId})
	}
	if c.CweId != "" {
		out = append(out, yaml.MapItem{Key: "cwe-id", Value: c.CweId})
	}
	return out, true
}

// emitRules 保持 rule 的有序结构（r0 / r1 / ...）。
func emitRules(rules poc.RuleMapSlice) yaml.MapSlice {
	out := make(yaml.MapSlice, 0, len(rules))
	for _, rm := range rules {
		out = append(out, yaml.MapItem{Key: rm.Key, Value: emitRule(rm.Value)})
	}
	return out
}

// emitRule 输出单个 rule：brute / request / expression / extractors。
func emitRule(r poc.Rule) yaml.MapSlice {
	out := make(yaml.MapSlice, 0, 5)
	if len(r.Brute) > 0 {
		out = append(out, yaml.MapItem{Key: "brute", Value: r.Brute})
	}
	out = append(out, yaml.MapItem{Key: "request", Value: emitRequest(r.Request)})
	if r.Expression != "" {
		out = append(out, yaml.MapItem{Key: "expression", Value: r.Expression})
	}
	if len(r.Expressions) > 0 {
		out = append(out, yaml.MapItem{Key: "expressions", Value: r.Expressions})
	}
	if len(r.Output) > 0 {
		out = append(out, yaml.MapItem{Key: "output", Value: r.Output})
	}
	if len(r.Extractors) > 0 {
		out = append(out, yaml.MapItem{Key: "extractors", Value: emitExtractors(r.Extractors)})
	}
	if r.StopIfMatch {
		out = append(out, yaml.MapItem{Key: "stop_if_match", Value: true})
	}
	if r.StopIfMismatch {
		out = append(out, yaml.MapItem{Key: "stop_if_mismatch", Value: true})
	}
	if r.BeforeSleep != 0 {
		out = append(out, yaml.MapItem{Key: "before_sleep", Value: r.BeforeSleep})
	}
	return out
}

// emitRequest 输出 rule 的 request 段。raw 与 method/path 互斥。
func emitRequest(r poc.RuleRequest) yaml.MapSlice {
	out := make(yaml.MapSlice, 0, 10)
	if r.Type != "" {
		out = append(out, yaml.MapItem{Key: "type", Value: r.Type})
	}

	if r.Raw != "" {
		out = append(out, yaml.MapItem{Key: "raw", Value: r.Raw})
	} else {
		if r.Method != "" {
			out = append(out, yaml.MapItem{Key: "method", Value: r.Method})
		}
		if r.Path != "" {
			out = append(out, yaml.MapItem{Key: "path", Value: r.Path})
		}
		if len(r.Headers) > 0 {
			out = append(out, yaml.MapItem{Key: "headers", Value: sortedStringMap(r.Headers)})
		}
		if r.Body != "" {
			out = append(out, yaml.MapItem{Key: "body", Value: r.Body})
		}
	}

	// 网络类字段（本转换器目前不产出，保留以支持后续扩展）
	if r.Host != "" {
		out = append(out, yaml.MapItem{Key: "host", Value: r.Host})
	}
	if r.Port != 0 {
		out = append(out, yaml.MapItem{Key: "port", Value: r.Port})
	}
	if r.Data != "" {
		out = append(out, yaml.MapItem{Key: "data", Value: r.Data})
	}
	if r.DataType != "" {
		out = append(out, yaml.MapItem{Key: "data-type", Value: r.DataType})
	}
	if len(r.Steps) > 0 {
		out = append(out, yaml.MapItem{Key: "steps", Value: r.Steps})
	}

	if r.FollowRedirects {
		out = append(out, yaml.MapItem{Key: "follow_redirects", Value: true})
	}
	return out
}

// emitExtractors 输出提取器列表。
func emitExtractors(list []poc.Extractors) []yaml.MapSlice {
	out := make([]yaml.MapSlice, 0, len(list))
	for _, e := range list {
		out = append(out, emitExtractor(e))
	}
	return out
}

// emitExtractor 输出单个提取器；旧写法（Extractor 非空）原样输出有序 map。
func emitExtractor(e poc.Extractors) yaml.MapSlice {
	if len(e.Extractor) > 0 {
		out := make(yaml.MapSlice, 0, 2)
		if e.Name != "" {
			out = append(out, yaml.MapItem{Key: "name", Value: e.Name})
		}
		if e.Type != "" {
			out = append(out, yaml.MapItem{Key: "type", Value: e.Type})
		}
		out = append(out, yaml.MapItem{Key: "extractor", Value: e.Extractor})
		return out
	}

	out := make(yaml.MapSlice, 0, 9)
	if e.Name != "" {
		out = append(out, yaml.MapItem{Key: "name", Value: e.Name})
	}
	if e.Type != "" {
		out = append(out, yaml.MapItem{Key: "type", Value: e.Type})
	}
	if e.Part != "" {
		out = append(out, yaml.MapItem{Key: "part", Value: e.Part})
	}
	if e.Regex != "" {
		out = append(out, yaml.MapItem{Key: "regex", Value: e.Regex})
	}
	if e.Group != "" {
		out = append(out, yaml.MapItem{Key: "group", Value: e.Group})
	}
	if e.All {
		out = append(out, yaml.MapItem{Key: "all", Value: true})
	}
	if e.Path != "" {
		out = append(out, yaml.MapItem{Key: "path", Value: e.Path})
	}
	if e.Key != "" {
		out = append(out, yaml.MapItem{Key: "key", Value: e.Key})
	}
	if e.Value != "" {
		out = append(out, yaml.MapItem{Key: "value", Value: e.Value})
	}
	return out
}

// sortedStringMap 把 map 转成键有序的 yaml.MapSlice，保证输出可复现。
func sortedStringMap(m map[string]string) yaml.MapSlice {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(yaml.MapSlice, 0, len(keys))
	for _, k := range keys {
		out = append(out, yaml.MapItem{Key: k, Value: m[k]})
	}
	return out
}
