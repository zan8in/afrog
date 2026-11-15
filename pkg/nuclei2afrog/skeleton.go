package nuclei2afrog

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/poc"
	"gopkg.in/yaml.v2"
)

// 本文件为 C 类（需人工重写）模板生成「结构骨架 + TODO」文本。
//
// 骨架是给人工 / AI 补全的草稿，**绝不保证可用**：
//   - 只机械还原「能确定的结构」：id / info，http 请求行，非 http 协议块的 type/host/port/data；
//   - 语义无法确定的地方一律留 TODO 注释，并写入一个空的 expression（永不命中），
//     从结构上保证它不会是一个「看起来能用」的 PoC。
//
// 骨架走 Result.Skeleton 独立字段，绝不写入 Result.YAML，
// 因此不会被 /api/pocs/create 当成可用 PoC 保存。

// reInteractshURL 命中 nuclei 的 interactsh 占位符 {{interactsh-url}}。
var reInteractshURL = regexp.MustCompile(`(?i)\{\{\s*interactsh-url\s*\}\}`)

// buildSkeleton 生成骨架文本。data 为原始模板（用于解析 tcp/ssl/dns 等非 http 协议块），
// tpl 为已解析的 http 结构，class 目前恒为 ClassC，gaps 为降级原因。
func buildSkeleton(data []byte, tpl *nucleiTemplate, class Class, gaps []string) []byte {
	var b strings.Builder

	b.WriteString("# nuclei2afrog 骨架（class: " + string(class) + "）——不可直接使用\n")
	b.WriteString("# 本文件由 nuclei 模板自动生成，只是「结构骨架 + TODO」：\n")
	b.WriteString("# 只机械还原能确定的结构，缺失 / 需重写的语义必须由人工或 AI 补全。\n")
	if len(gaps) > 0 {
		b.WriteString("#\n# 缺口:\n")
		for _, g := range gaps {
			b.WriteString("#   - " + oneLine(g) + "\n")
		}
	}
	b.WriteString("\n")

	b.WriteString("id: " + yamlScalar(strings.TrimSpace(tpl.ID)) + "\n\n")

	b.WriteString("info:\n")
	if out, err := yaml.Marshal(emitInfo(buildInfo(tpl))); err == nil {
		writeIndented(&b, 2, string(out))
	}
	b.WriteString("\n")

	b.WriteString("rules:\n")
	writeSkeletonRules(&b, data, tpl)

	return []byte(b.String())
}

// writeSkeletonRules 写出骨架的 rules 段：http 块在前，非 http 协议块在后。
func writeSkeletonRules(b *strings.Builder, data []byte, tpl *nucleiTemplate) {
	idx := 0

	blocks := tpl.httpBlocks()
	for i := range blocks {
		b.WriteString(fmt.Sprintf("  r%d:\n", idx))
		if tpl.Flow != "" {
			writeComment(b, 4, "flow 需人工重写："+oneLine(tpl.Flow))
		}
		writeSkeletonHTTPRequest(b, blocks[i])
		writeComment(b, 4, "补全 expression（nuclei matchers 无法机械映射）")
		b.WriteString("    expression: \"\"\n")
		idx++
	}

	for _, pb := range protocolBlocks(data) {
		for _, raw := range pb.blocks {
			b.WriteString(fmt.Sprintf("  r%d:\n", idx))
			writeComment(b, 4, fmt.Sprintf("%s 协议块需人工重写（与 afrog rules 语义差异大）", pb.kind))
			writeSkeletonProtocolRequest(b, pb.kind, raw)
			writeComment(b, 4, "补全 expression（matchers / extractors 无法机械映射）")
			b.WriteString("    expression: \"\"\n")
			idx++
		}
	}

	if idx == 0 {
		writeComment(b, 2, "未识别到可还原的请求块，请参照原 nuclei 模板手工编写")
	}
}

// writeSkeletonHTTPRequest 尽力还原一个 http 请求块为 afrog request。
func writeSkeletonHTTPRequest(b *strings.Builder, blk nucleiHTTP) {
	req := poc.RuleRequest{}
	if len(blk.Raw) > 0 {
		req.Raw = oobSubst(blk.Raw[0])
		if len(blk.Raw) > 1 {
			writeComment(b, 6, fmt.Sprintf("原模板含 %d 条 raw 请求（请求链），需人工补全", len(blk.Raw)))
		}
	} else {
		req.Method = strings.ToUpper(strings.TrimSpace(blk.Method))
		if len(blk.Path) > 0 {
			req.Path = oobSubst(blk.Path[0])
		}
		if len(blk.Headers) > 0 {
			req.Headers = make(map[string]string, len(blk.Headers))
			for k, v := range blk.Headers {
				req.Headers[oobSubst(k)] = oobSubst(v)
			}
		}
		if blk.Body != "" {
			req.Body = oobSubst(blk.Body)
		}
		if len(blk.Path) > 1 {
			writeComment(b, 6, fmt.Sprintf("原模板含 %d 条 path，需改用 brute", len(blk.Path)))
		}
	}

	b.WriteString("    request:\n")
	out, err := yaml.Marshal(emitRequest(req))
	if err != nil {
		writeComment(b, 6, "request 序列化失败："+oneLine(err.Error()))
		return
	}
	writeIndented(b, 6, string(out))

	if hasInteractshBlock(blk) {
		writeComment(b, 6, "interactsh 反连：afrog 用 {{oob.HTTP}} / {{oob.DNS}} 配合 oobCheck，需人工确认协议类型")
	}
}

// writeSkeletonProtocolRequest 尽力还原一个非 http 协议块（tcp/udp/ssl/dns/network）。
func writeSkeletonProtocolRequest(b *strings.Builder, kind string, raw any) {
	m, _ := asAnyMap(raw)
	req := skeletonProtocolRequest(kind, m)

	b.WriteString("    request:\n")
	out, err := yaml.Marshal(emitRequest(req))
	if err != nil {
		writeComment(b, 6, "request 序列化失败："+oneLine(err.Error()))
		return
	}
	writeIndented(b, 6, string(out))

	if kind == "dns" {
		writeComment(b, 6, "afrog 无 dns 运行时：需改用 tcp/udp，或先补齐引擎能力")
	}
}

// skeletonProtocolRequest 从协议块字段里尽力抽出 afrog request。
//
// nuclei 的 tcp/udp/network 用 inputs[].data + host/port，
// ssl 用 address，dns 用 name；这里只做「有则填、无则留空」的机械搬运。
func skeletonProtocolRequest(kind string, m map[string]any) poc.RuleRequest {
	req := poc.RuleRequest{Type: kind}
	if kind == "network" {
		// nuclei 的 network 就是裸 tcp 交互。
		req.Type = "tcp"
	}

	if hosts := asAnyList(getAny(m, "host")); len(hosts) > 0 {
		req.Host = strings.TrimSpace(asString(hosts[0]))
	}
	if req.Host == "" {
		if addr := strings.TrimSpace(asString(getAny(m, "address"))); addr != "" {
			// ssl 的 address 形如 "{{Host}}:{{Port}}"，整串保留交人工处理。
			req.Host = addr
		}
	}
	if p, ok := asInt(getAny(m, "port")); ok {
		req.Port = p
	}
	if inputs := asAnyList(getAny(m, "inputs")); len(inputs) > 0 {
		if im, ok := asAnyMap(inputs[0]); ok {
			req.Data = asString(getAny(im, "data"))
		}
	}
	return req
}

// ---------------- 非 http 协议块解析 ----------------

// protoBlock 是一类非 http 协议段（tcp / udp / ssl / dns / network）的全部块。
type protoBlock struct {
	kind   string
	blocks []any
}

// protoKindOrder 固定协议段的输出顺序，保证骨架可复现。
var protoKindOrder = []string{"network", "tcp", "udp", "ssl", "dns"}

// protocolBlocks 从原始模板里泛化地取出非 http 协议块。
//
// 刻意不从 nucleiTemplate 结构里取：这些协议段的字段形态差异大且 afrog 侧要靠人工重写，
// 用泛型 map 承接可以避免「多一个字段就解析失败」，也更贴近「尽力还原」的定位。
func protocolBlocks(data []byte) []protoBlock {
	var root yaml.MapSlice
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil
	}

	found := map[string][]any{}
	for _, item := range root {
		k, ok := item.Key.(string)
		if !ok {
			continue
		}
		lk := strings.ToLower(strings.TrimSpace(k))
		switch lk {
		case "network", "tcp", "udp", "ssl", "dns":
			found[lk] = append(found[lk], asAnyList(item.Value)...)
		}
	}

	var out []protoBlock
	for _, k := range protoKindOrder {
		if len(found[k]) > 0 {
			out = append(out, protoBlock{kind: k, blocks: found[k]})
		}
	}
	return out
}

// ---------------- 通用取值助手 ----------------

// getAny 按大小写不敏感取键。
func getAny(m map[string]any, key string) any {
	if m == nil {
		return nil
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return nil
}

// asAnyMap 把 yaml.v2 解出的各种 map 形态统一成 map[string]any。
func asAnyMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[interface{}]interface{}:
		out := make(map[string]any, len(m))
		for k, vv := range m {
			if ks, ok := k.(string); ok {
				out[ks] = vv
			}
		}
		return out, true
	case yaml.MapSlice:
		out := make(map[string]any, len(m))
		for _, it := range m {
			if ks, ok := it.Key.(string); ok {
				out[ks] = it.Value
			}
		}
		return out, true
	}
	return nil, false
}

// asAnyList 把「单个值或列表」统一成列表；不是列表时包成单元素列表。
func asAnyList(v any) []any {
	switch vv := v.(type) {
	case nil:
		return nil
	case []any:
		return vv
	case map[string]any, map[interface{}]interface{}, yaml.MapSlice:
		return []any{vv}
	}
	return nil
}

// asString 把标量转成字符串；非标量返回空串。
func asString(v any) string {
	switch s := v.(type) {
	case nil:
		return ""
	case string:
		return s
	case fmt.Stringer:
		return s.String()
	case int, int64, float64, bool:
		return fmt.Sprintf("%v", s)
	}
	return ""
}

// asInt 把标量转成 int。
func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case string:
		var out int
		if _, err := fmt.Sscanf(strings.TrimSpace(n), "%d", &out); err == nil {
			return out, true
		}
	}
	return 0, false
}

// ---------------- 文本输出助手 ----------------

// oneLine 把多行文本压成一行，避免注释把骨架结构撑乱。
func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
}

// oobSubst 把 nuclei 的 interactsh 占位符换成 afrog 的 oob 占位符。
func oobSubst(s string) string {
	return reInteractshURL.ReplaceAllString(s, "{{oob.HTTP}}")
}

// hasInteractshBlock 判断单个 http 块里是否出现 interactsh 标记。
func hasInteractshBlock(blk nucleiHTTP) bool {
	lower := func(s string) bool { return strings.Contains(strings.ToLower(s), "interactsh") }
	if lower(blk.Body) {
		return true
	}
	for _, s := range blk.Path {
		if lower(s) {
			return true
		}
	}
	for _, s := range blk.Raw {
		if lower(s) {
			return true
		}
	}
	for k, v := range blk.Headers {
		if lower(k + v) {
			return true
		}
	}
	return false
}

// yamlScalar 把一个字符串序列化成单行 YAML 标量（保证引号/转义正确）。
func yamlScalar(s string) string {
	out, err := yaml.Marshal(s)
	if err != nil {
		return `""`
	}
	return strings.TrimRight(string(out), "\n")
}

// writeComment 写一行指定缩进的注释。
func writeComment(b *strings.Builder, indent int, s string) {
	b.WriteString(strings.Repeat(" ", indent))
	b.WriteString("# ")
	b.WriteString(s)
	b.WriteByte('\n')
}

// writeIndented 把多行文本整体加 indent 个空格缩进后写出。
func writeIndented(b *strings.Builder, indent int, s string) {
	pad := strings.Repeat(" ", indent)
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if line == "" {
			b.WriteByte('\n')
			continue
		}
		b.WriteString(pad)
		b.WriteString(line)
		b.WriteByte('\n')
	}
}
