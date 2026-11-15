package nuclei2afrog

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

// TestSkeletonFlow 含 flow 的 C 类必须产出骨架：不能有 YAML、Usable=false，
// 但 Skeleton 非空且带 TODO，并标明 flow 需人工重写。
func TestSkeletonFlow(t *testing.T) {
	src := `
id: sample-flow
info:
  name: Sample Flow
  severity: high
flow: http(0) && http(1)
http:
  - method: GET
    path: ["/first"]
    matchers:
      - type: status
        status: [200]
  - method: POST
    path: ["/second"]
    body: "a=1"
    matchers:
      - type: word
        words: ["ok"]
`
	res := convert(t, src)
	if res.Class != ClassC {
		t.Fatalf("期望 C 类，实际 %s", res.Class)
	}
	if res.Usable {
		t.Error("C 类 Usable 必须为 false")
	}
	if len(res.YAML) != 0 {
		t.Error("C 类不应产出 YAML")
	}
	sk := string(res.Skeleton)
	if sk == "" {
		t.Fatal("C 类应产出骨架")
	}
	for _, want := range []string{
		"# nuclei2afrog 骨架（class: C）",
		"不可直接使用",
		"flow 需人工重写",
		"r0:", "r1:",
		"path: /first",
	} {
		if !strings.Contains(sk, want) {
			t.Errorf("骨架缺少 %q\n---\n%s", want, sk)
		}
	}
	assertParsesAsYAML(t, sk)
}

// TestSkeletonInteractsh interactsh 占位符要换成 afrog 的 oob 占位符，并提示人工确认协议类型。
func TestSkeletonInteractsh(t *testing.T) {
	src := `
id: sample-oob
info:
  name: Sample OOB
  severity: critical
http:
  - method: GET
    path: ["{{BaseURL}}/x?u={{interactsh-url}}"]
    matchers:
      - type: word
        part: interactsh_protocol
        words: ["dns"]
`
	res := convert(t, src)
	if res.Class != ClassC {
		t.Fatalf("期望 C 类，实际 %s", res.Class)
	}
	sk := string(res.Skeleton)
	if !strings.Contains(sk, "{{oob.HTTP}}") {
		t.Errorf("骨架应把 interactsh-url 换成 oob 占位符\n---\n%s", sk)
	}
	if !strings.Contains(sk, "oobCheck") {
		t.Errorf("骨架应提示 oobCheck 需人工确认\n---\n%s", sk)
	}
	assertParsesAsYAML(t, sk)
}

// TestSkeletonProtocolBlocks 非 http 协议块（tcp / dns）要落成带 type 的骨架。
func TestSkeletonProtocolBlocks(t *testing.T) {
	src := `
id: sample-tcp
info:
  name: Sample TCP
  severity: info
tcp:
  - inputs:
      - data: "PING\r\n"
    host:
      - "{{Hostname}}"
    port: 6379
    matchers:
      - type: word
        words: ["PONG"]
dns:
  - name: "{{FQDN}}"
    type: A
    matchers:
      - type: word
        words: ["1.2.3.4"]
`
	res := convert(t, src)
	if res.Class != ClassC {
		t.Fatalf("期望 C 类，实际 %s", res.Class)
	}
	sk := string(res.Skeleton)
	for _, want := range []string{"type: tcp", "port: 6379", "PING", "type: dns", "afrog 无 dns 运行时"} {
		if !strings.Contains(sk, want) {
			t.Errorf("骨架缺少 %q\n---\n%s", want, sk)
		}
	}
	assertParsesAsYAML(t, sk)
}

// TestSkeletonOnlyForClassC 只有 C 类才产出骨架；A 类可用的 PoC、D/X 类都不得有骨架。
func TestSkeletonOnlyForClassC(t *testing.T) {
	a := convert(t, `
id: sample-a
info:
  name: Sample A
  severity: low
http:
  - method: GET
    path: ["/x"]
    matchers:
      - type: status
        status: [200]
`)
	if a.Class != ClassA {
		t.Fatalf("前置用例应为 A 类，实际 %s", a.Class)
	}
	if !a.Usable {
		t.Error("A 类 Usable 必须为 true")
	}
	if len(a.Skeleton) != 0 {
		t.Errorf("A 类不应产出骨架，got:\n%s", a.Skeleton)
	}

	d := convert(t, `
id: sample-d
info:
  name: Sample D
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}"
`)
	if d.Class != ClassD {
		t.Fatalf("前置用例应为 D 类，实际 %s", d.Class)
	}
	if len(d.Skeleton) != 0 {
		t.Errorf("D 类不应产出骨架，got:\n%s", d.Skeleton)
	}
}

// assertParsesAsYAML 断言骨架至少是一份可解析的 YAML（避免生成结构被注释撑坏）。
func assertParsesAsYAML(t *testing.T, sk string) {
	t.Helper()
	var doc any
	if err := yaml.Unmarshal([]byte(sk), &doc); err != nil {
		t.Fatalf("骨架不是合法 YAML: %v\n---\n%s", err, sk)
	}
}
