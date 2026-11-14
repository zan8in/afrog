package mcp

import (
	"strings"
	"testing"
)

func TestEstimatePocRequests(t *testing.T) {
	plain := []byte(`
id: demo
info:
  name: demo
  severity: info
rules:
  r0:
    request:
      type: http
      path: /a
    expression: response.status == 200
  r1:
    request:
      type: http
      path: /b
    expression: response.status == 200
`)
	if got := estimatePocRequests(plain); got != 2 {
		t.Fatalf("estimate = %d, want 2", got)
	}

	brute := []byte(`
id: brute
info:
  name: brute
  severity: high
rules:
  r0:
    brute:
      mode: clusterbomb
      commit: winner
      username:
        - admin
        - root
        - test
      password:
        - 123456
        - admin
    request:
      type: http
      path: /login
    expression: response.status == 200
`)
	if got := estimatePocRequests(brute); got != 6 {
		t.Fatalf("estimate = %d, want 6", got)
	}

	if got := estimatePocRequests(nil); got != defaultVerifyReserve {
		t.Fatalf("empty estimate = %d, want default", got)
	}
	if got := estimatePocRequests([]byte("not: [valid")); got != defaultVerifyReserve {
		t.Fatalf("invalid estimate = %d, want default", got)
	}
}

func TestReserveForBrute(t *testing.T) {
	literal := []byte(`
id: brute
info:
  name: brute
  severity: high
rules:
  r0:
    brute:
      username:
        - admin
        - root
        - test
      password:
        - "123456"
        - admin
    request:
      type: http
      path: /login
    expression: true
`)
	if got := reserveForBrute(literal, 100); got != 6 {
		t.Fatalf("literal reserve = %d, want 6", got)
	}
	if got := reserveForBrute(literal, 3); got != 3 {
		t.Fatalf("literal reserve capped = %d, want 3", got)
	}

	// 字典由 CEL 表达式提供：无法静态计数，按调用方上限预留。
	cel := []byte(`
id: cel-brute
info:
  name: cel
  severity: high
rules:
  r0:
    brute:
      password: redis_weak_passwords()
    request:
      type: http
      path: /login
    expression: true
`)
	if est := analyzePoc(cel); !est.HasBrute || !est.Uncountable {
		t.Fatalf("cel brute should be uncountable: %+v", est)
	}
	if got := reserveForBrute(cel, 4); got != 4 {
		t.Fatalf("cel reserve = %d, want 4", got)
	}

	// JS PoC 内部自行循环发包：外部数不出次数，按调用方上限预留。
	script := []byte(`
id: js-brute
info:
  name: js
  severity: high
rules:
  r0:
    request:
      type: javascript
      code: |
        // 15 次尝试写死在脚本里
    expression: true
`)
	if est := analyzePoc(script); !est.Script {
		t.Fatalf("js poc should be marked as script: %+v", est)
	}
	if got := reserveForBrute(script, 7); got != 7 {
		t.Fatalf("script reserve = %d, want 7", got)
	}
}

func TestEstimateRespectsCap(t *testing.T) {
	// 组合数超过上限时收敛到 maxVerifyReserve，避免预留过大的预算。
	var b strings.Builder
	b.WriteString("id: big\ninfo:\n  name: big\n  severity: info\nrules:\n  r0:\n    brute:\n      p:\n")
	for i := 0; i < 600; i++ {
		b.WriteString("        - x\n")
	}
	b.WriteString("    request:\n      type: http\n      path: /\n    expression: true\n")

	got := estimatePocRequests([]byte(b.String()))
	if got != maxVerifyReserve {
		t.Fatalf("estimate = %d, want %d", got, maxVerifyReserve)
	}
}
