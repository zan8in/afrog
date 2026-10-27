package nuclei2afrog

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/poc"
	"gopkg.in/yaml.v2"
)

func convert(t *testing.T, src string) *Result {
	t.Helper()
	res, err := Convert([]byte(src))
	if err != nil {
		t.Fatalf("Convert 返回错误: %v", err)
	}
	return res
}

func TestConvertClassA(t *testing.T) {
	src := `
id: sample-a
info:
  name: Sample A
  author: tester
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "root:x:0:0"
`
	res := convert(t, src)
	if res.Class != ClassA {
		t.Fatalf("期望 A 类，实际 %s（gaps=%v）", res.Class, res.Gaps)
	}
	if len(res.YAML) == 0 {
		t.Fatal("A 类应产出 YAML")
	}

	var p poc.Poc
	if err := yaml.Unmarshal(res.YAML, &p); err != nil {
		t.Fatalf("产出的 YAML 无法反序列化: %v\n%s", err, res.YAML)
	}
	if p.Id != "sample-a" {
		t.Errorf("id 应为 sample-a，实际 %q", p.Id)
	}
	if len(p.Rules) != 1 || p.Rules[0].Key != "r0" {
		t.Fatalf("应含单个 rule r0，实际 %+v", p.Rules)
	}
	if got := p.Rules[0].Value.Request.Path; got != "/admin" {
		t.Errorf("path 应为 /admin，实际 %q", got)
	}
	if p.Expression != "r0()" {
		t.Errorf("expression 应为 r0()，实际 %q", p.Expression)
	}
	expr := p.Rules[0].Value.Expression
	for _, want := range []string{"response.status == 200", "response.body.bcontains(", "root:x:0:0"} {
		if !strings.Contains(expr, want) {
			t.Errorf("rule expression 缺少 %q：%s", want, expr)
		}
	}
	if !strings.Contains(expr, " || ") {
		t.Errorf("matchers-condition 缺省应为 OR：%s", expr)
	}
}

func TestConvertClassAAndCondition(t *testing.T) {
	src := `
id: sample-and
info:
  name: Sample AND
  severity: medium
http:
  - method: GET
    path:
      - "/ping"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: regex
        regex:
          - "v[0-9]+\\.[0-9]+"
`
	res := convert(t, src)
	if res.Class != ClassA {
		t.Fatalf("期望 A 类，实际 %s（gaps=%v）", res.Class, res.Gaps)
	}
	var p poc.Poc
	if err := yaml.Unmarshal(res.YAML, &p); err != nil {
		t.Fatalf("反序列化失败: %v\n%s", err, res.YAML)
	}
	expr := p.Rules[0].Value.Expression
	if !strings.Contains(expr, " && ") {
		t.Errorf("matchers-condition=and 应生成 &&：%s", expr)
	}
	if got := p.Rules[0].Value.Request.Path; got != "^/ping" {
		t.Errorf("裸 /ping 应按绝对路径 ^/ping 映射，实际 %q", got)
	}
}

func TestConvertClassBWithPayloads(t *testing.T) {
	src := `
id: sample-b
info:
  name: Sample B
  severity: low
variables:
  token: abc123
http:
  - method: POST
    path:
      - "{{BaseURL}}/login"
    body: "u={{username}}&t={{token}}"
    payloads:
      username:
        - admin
        - root
    attack: clusterbomb
    matchers:
      - type: word
        words:
          - "welcome"
`
	res := convert(t, src)
	if res.Class != ClassB {
		t.Fatalf("期望 B 类，实际 %s（gaps=%v）", res.Class, res.Gaps)
	}
	var p poc.Poc
	if err := yaml.Unmarshal(res.YAML, &p); err != nil {
		t.Fatalf("反序列化失败: %v\n%s", err, res.YAML)
	}
	brute := p.Rules[0].Value.Brute
	if len(brute) == 0 {
		t.Fatal("应产出 brute 段")
	}
	// 顺序：commit / continue / payloads
	if brute[0].Key != "commit" || brute[1].Key != "continue" {
		t.Errorf("brute 头部应为 commit/continue，实际 %v", brute)
	}
	var hasUser bool
	for _, item := range brute {
		if item.Key == "username" {
			hasUser = true
		}
	}
	if !hasUser {
		t.Errorf("brute 应含 username payload：%v", brute)
	}
	if len(p.Set) == 0 {
		t.Error("variables 应落成 set")
	}
}

// TestConvertSetWithDSL 校验带函数占位符 / 变量引用的 variables 能落成可求值的 CEL。
func TestConvertSetWithDSL(t *testing.T) {
	src := `
id: sample-set
info:
  name: Sample Set
  severity: medium
variables:
  prefix: "pre-{{rand_int(1000, 9999)}}"
  full: "{{prefix}}-{{to_lower(suffix)}}"
  suffix: "{{rand_text_alpha(5)}}"
  literal: admin
http:
  - method: GET
    path:
      - "{{BaseURL}}/x?p={{full}}"
    matchers:
      - type: status
        status: [200]
`
	res := convert(t, src)
	if res.Class != ClassB {
		t.Fatalf("期望 B 类，实际 %s（gaps=%v）", res.Class, res.Gaps)
	}
	var p poc.Poc
	if err := yaml.Unmarshal(res.YAML, &p); err != nil {
		t.Fatalf("反序列化失败: %v\n%s", err, res.YAML)
	}
	got := map[string]string{}
	var order []string
	for _, item := range p.Set {
		k := item.Key.(string)
		got[k] = item.Value.(string)
		order = append(order, k)
	}
	if got["literal"] != `"admin"` {
		t.Errorf("字面量应输出为 CEL 字符串字面量，实际 %q", got["literal"])
	}
	if !strings.Contains(got["prefix"], "string(randomInt(1000, 9999))") {
		t.Errorf("rand_int 应译成 string(randomInt(...))，实际 %q", got["prefix"])
	}
	if !strings.Contains(got["suffix"], "randomLowercase(5)") {
		t.Errorf("rand_text_alpha 应译成 randomLowercase，实际 %q", got["suffix"])
	}
	// full 依赖 prefix / suffix，二者必须排在它之前。
	idx := map[string]int{}
	for i, k := range order {
		idx[k] = i
	}
	if idx["prefix"] > idx["full"] || idx["suffix"] > idx["full"] {
		t.Errorf("set 未按依赖排序（出现即求值失败）：%v", order)
	}
	if expr := p.Rules[0].Value.Request.Path; !strings.Contains(expr, "{{full}}") {
		t.Errorf("请求里的变量引用应保留为占位符，实际 %q", expr)
	}
}

func TestConvertReservedVarRename(t *testing.T) {
	src := `
id: sample-reserved
info:
  name: Sample Reserved
  severity: medium
variables:
  string: "injection"
http:
  - method: GET
    path:
      - "{{BaseURL}}/x?p={{string}}"
    matchers:
      - type: word
        part: body
        words:
          - "{{md5(string)}}"
`
	res := convert(t, src)
	if res.Class != ClassB {
		t.Fatalf("期望 B 类，实际 %s（gaps=%v）", res.Class, res.Gaps)
	}
	var p poc.Poc
	if err := yaml.Unmarshal(res.YAML, &p); err != nil {
		t.Fatalf("反序列化失败: %v\n%s", err, res.YAML)
	}
	// 变量名与 CEL 内置类型 string 重名，必须改名，否则整个 PoC 编译不过。
	if len(p.Set) != 1 || p.Set[0].Key.(string) != "n2a_string" {
		t.Fatalf("set 键应改名为 n2a_string，实际 %+v", p.Set)
	}
	if expr := p.Rules[0].Value.Request.Path; !strings.Contains(expr, "{{n2a_string}}") {
		t.Errorf("请求占位符应同步改名，实际 %q", expr)
	}
	if expr := p.Rules[0].Value.Expression; !strings.Contains(expr, "md5(n2a_string)") {
		t.Errorf("matcher 里的变量引用应同步改名，实际 %q", expr)
	}
}

func TestConvertSetUnknownPlaceholder(t *testing.T) {
	src := `
id: sample-set-bad
info:
  name: Sample Set Bad
  severity: low
variables:
  a: "{{nope(1)}}"
http:
  - method: GET
    path:
      - "{{BaseURL}}/x"
    matchers:
      - type: status
        status: [200]
`
	res := convert(t, src)
	if res.Class != ClassC {
		t.Fatalf("变量值引用无法解析的占位符应降级 C，实际 %s（gaps=%v）", res.Class, res.Gaps)
	}
}

func TestConvertClassDHeadless(t *testing.T) {
	src := `
id: sample-d
info:
  name: Sample D
  severity: info
headless:
  - steps:
      - action: navigate
    matchers:
      - type: word
        words: ["x"]
`
	res := convert(t, src)
	if res.Class != ClassD {
		t.Fatalf("期望 D 类，实际 %s", res.Class)
	}
	if len(res.YAML) != 0 {
		t.Error("D 类不应产出 YAML")
	}
}

func TestConvertClassCFlow(t *testing.T) {
	src := `
id: sample-c
info:
  name: Sample C
  severity: info
flow: http(1) && http(2)
http:
  - method: GET
    path: ["/a"]
    matchers:
      - type: status
        status: [200]
  - method: GET
    path: ["/b"]
    matchers:
      - type: status
        status: [200]
`
	res := convert(t, src)
	if res.Class != ClassC {
		t.Fatalf("期望 C 类，实际 %s", res.Class)
	}
	if len(res.YAML) != 0 {
		t.Error("C 类不应产出 YAML")
	}
	if len(res.Gaps) == 0 {
		t.Error("C 类应给出缺口说明")
	}
}

func TestConvertDSLMatcher(t *testing.T) {
	src := `
id: sample-dsl
info:
  name: Sample DSL
  severity: high
http:
  - method: GET
    path: ["/x"]
    matchers:
      - type: dsl
        dsl:
          - "status_code == 200 && contains(body, 'admin')"
`
	res := convert(t, src)
	// dsl matcher 属于 B 类：表达式必须整条重写，需要人工复核
	if res.Class != ClassB {
		t.Fatalf("期望 B 类，实际 %s（gaps=%v）", res.Class, res.Gaps)
	}
	var p poc.Poc
	if err := yaml.Unmarshal(res.YAML, &p); err != nil {
		t.Fatalf("反序列化失败: %v\n%s", err, res.YAML)
	}
	expr := p.Rules[0].Value.Expression
	if !strings.Contains(expr, "response.status == 200") {
		t.Errorf("DSL status_code 应映射为 response.status：%s", expr)
	}
	if !strings.Contains(expr, "response.body.bcontains(") && !strings.Contains(expr, "response.body.contains(") {
		t.Errorf("DSL contains(body, ...) 应映射到 response.body：%s", expr)
	}
}

func TestConvertExtractors(t *testing.T) {
	src := `
id: sample-ext
info:
  name: Sample Ext
  severity: medium
http:
  - method: GET
    path: ["/x"]
    matchers:
      - type: status
        status: [200]
    extractors:
      - type: regex
        name: version
        part: body
        group: 1
        regex:
          - "ver=([0-9.]+)"
`
	res := convert(t, src)
	if res.Class != ClassA {
		t.Fatalf("期望 A 类，实际 %s（gaps=%v）", res.Class, res.Gaps)
	}
	var p poc.Poc
	if err := yaml.Unmarshal(res.YAML, &p); err != nil {
		t.Fatalf("反序列化失败: %v\n%s", err, res.YAML)
	}
	exts := p.Rules[0].Value.Extractors
	if len(exts) != 1 {
		t.Fatalf("应含 1 个 extractor，实际 %d", len(exts))
	}
	if exts[0].Name != "version" || exts[0].Type != "regex" || exts[0].Group != "1" {
		t.Errorf("extractor 映射不正确：%+v", exts[0])
	}
	if !strings.Contains(exts[0].Regex, "ver=(") {
		t.Errorf("extractor regex 不正确：%q", exts[0].Regex)
	}
}

func TestConvertUnresolvablePathDowngrades(t *testing.T) {
	src := `
id: sample-path-gap
info:
  name: Path Gap
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/{{custom}}/x"
    matchers:
      - type: status
        status: [200]
`
	res := convert(t, src)
	if res.Class != ClassC {
		t.Fatalf("含无法映射的 path 变量应降级 C，实际 %s（gaps=%v）", res.Class, res.Gaps)
	}
}

// TestConvertCorpus 是可选的规模回归：对本地 nuclei-templates 全量跑一遍，
// 断言「无 panic」，并统计 A/B 类的产出率与 CEL 编译通过率。
//
// 打开方式：N2A_SCALE=1 go test ./pkg/nuclei2afrog/ -run TestConvertCorpus -v
func TestConvertCorpus(t *testing.T) {
	if os.Getenv("N2A_SCALE") != "1" {
		t.Skip("设置 N2A_SCALE=1 以运行全量规模回归")
	}
	root := os.Getenv("N2A_TEMPLATES")
	if root == "" {
		root = "/Users/zanbin/gowork/github/projectdiscovery/nuclei-templates"
	}
	if _, err := os.Stat(root); err != nil {
		t.Skipf("nuclei-templates 不存在：%s", root)
	}

	var total, classA, classB, classC, classD, classX, translated, badParse int
	reasons := map[string]int{}
	msgs := map[string]int{}
	msgSample := map[string][]string{}
	samples := map[string]string{}
	bucketSample := map[string][]string{}
	record := func(path string, gaps []string) {
		b := gapBucket(gaps)
		reasons[b]++
		if len(bucketSample[b]) < 3 && len(gaps) > 0 {
			bucketSample[b] = append(bucketSample[b], strings.TrimPrefix(path, root)+" :: "+truncateRunes(gaps[0], 110))
		}
		for _, g := range gaps {
			k := truncateRunes(g, 90)
			msgs[k]++
			if len(msgSample[k]) < 3 {
				msgSample[k] = append(msgSample[k], strings.TrimPrefix(path, root))
			}
		}
		if b == otherBucket && len(samples) < 5 && len(gaps) > 0 {
			samples[truncateRunes(gaps[0], 70)] = ""
		}
	}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() || !(strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		total++
		res, err := Convert(data)
		if err != nil {
			badParse++
			return nil
		}
		switch res.Class {
		case ClassA:
			classA++
		case ClassB:
			classB++
		case ClassC:
			classC++
			record(path, res.Gaps)
		case ClassD:
			classD++
			record(path, res.Gaps)
		case ClassX:
			classX++
			record(path, res.Gaps)
		}
		if len(res.YAML) == 0 {
			return nil
		}
		translated++
		var p poc.Poc
		if err := yaml.Unmarshal(res.YAML, &p); err != nil {
			t.Errorf("%s: 产出 YAML 无法反序列化: %v", path, err)
			return nil
		}
		if gaps := validatePoc(&p); len(gaps) > 0 {
			t.Errorf("%s: 产出 PoC 未通过 CEL 自校验: %v", path, gaps)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("模板总数=%d 解析失败=%d A=%d B=%d C=%d D=%d X=%d 产出=%d",
		total, badParse, classA, classB, classC, classD, classX, translated)
	for _, line := range topBuckets(reasons, 20) {
		t.Logf("未产出归因: %s", line)
	}
	for _, line := range topBuckets(reasons, 20) {
		key := strings.SplitN(line, "=", 2)[0]
		t.Logf("归因样例: %s ← %v", key, bucketSample[key])
	}
	for _, line := range topBuckets(msgs, 40) {
		t.Logf("具体缺口: %s", line)
	}
	for _, line := range topBuckets(msgs, 25) {
		key := strings.SplitN(line, "=", 2)[0]
		t.Logf("缺口样例: %s ← %v", key, msgSample[key])
	}
	for s := range samples {
		t.Logf("未归类样例: %s", s)
	}
	if translated == 0 {
		t.Fatal("全量模板没有任何产出，转换器显然失效")
	}
}

// gapBucket 把一份转换缺口归入便于统计的主因桶。
// 桶名按「最具体优先」的顺序匹配，命中即返回。
func gapBucket(gaps []string) string {
	buckets := []struct {
		name string
		keys []string
	}{
		{"interactsh 反连", []string{"interactsh", "反连"}},
		{"flow 请求编排", []string{"含 flow"}},
		{"internal extractor 请求链", []string{"internal: true"}},
		{"多响应变量", []string{"多响应变量"}},
		{"set 值含 nuclei 模板表达式", []string{"的 set 无法直接求值", "值不是字符串"}},
		{"非 http 协议段(C)", []string{"语义差异大"}},
		{"协议段无运行时(D)", []string{"无对应运行时"}},
		{"不含协议段(X)", []string{"不含任何可识别的协议段"}},
		{"无可用 http 请求块", []string{"不含可转换的 http 请求块"}},
		{"多 raw 请求（请求链）", []string{"条 raw 请求"}},
		{"http 块无 matcher", []string{"没有任何 matcher"}},
		{"headless/浏览器", []string{"headless"}},
		{"javascript 协议", []string{"javascript"}},
		{"CEL 自校验失败", []string{"无法编译"}},
		{"path 变量/形态", []string{"path"}},
		{"part 无对应视图", []string{"无对应视图", "无对应取值来源"}},
		{"payloads/brute 表达", []string{"payload", "batteringram", "attack"}},
		{"extractor 类型无对应", []string{"extractor"}},
		{"请求占位符无来源", []string{"占位符"}},
		{"模板变量无法映射", []string{"模板变量", "无法映射"}},
		{"DSL 节点无法识别", []string{"DSL", "运算符"}},
	}
	for _, b := range buckets {
		for _, g := range gaps {
			for _, k := range b.keys {
				if strings.Contains(g, k) {
					return b.name
				}
			}
		}
	}
	if len(gaps) > 0 {
		return otherBucket
	}
	return "未给出缺口说明"
}

const otherBucket = "其它（未归类）"

// topBuckets 按计数降序返回 Top N 归因行。
func topBuckets(reasons map[string]int, n int) []string {
	keys := make([]string, 0, len(reasons))
	for k := range reasons {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if reasons[keys[i]] != reasons[keys[j]] {
			return reasons[keys[i]] > reasons[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%s=%d", k, reasons[k]))
	}
	return out
}

func truncateRunes(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n]) + "…"
}
