package mcp

import (
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/scanstream"
)

// scanRunResult 必须显式区分三种结论，否则模型会把「本机没有该技术栈的 PoC」
// 读成「目标没有漏洞」。
func TestScanRunResultConclusions(t *testing.T) {
	hit := scanRunResult("http://t", "thinkphp", &scanRun{
		Status:  "completed",
		Results: []map[string]any{{"poc_id": "thinkphp-rce"}},
		Summary: &scanstream.Summary{Executed: 3, Found: 1},
	}, 3)
	if hit["conclusion"] != "hit" {
		t.Fatalf("hit conclusion = %v", hit["conclusion"])
	}

	// 本机有 PoC 且已执行，但均未命中。
	noFind := scanRunResult("http://t", "thinkphp", &scanRun{
		Status:  "completed",
		Summary: &scanstream.Summary{Executed: 3},
	}, 3)
	if noFind["conclusion"] != "no_finding" {
		t.Fatalf("no_finding conclusion = %v", noFind["conclusion"])
	}
	if _, ok := noFind["guidance"]; !ok {
		t.Fatal("no_finding must carry guidance")
	}

	// 有 PoC，但被 severity 全部过滤、一条都没执行。
	filtered := scanRunResult("http://t", "thinkphp", &scanRun{
		Status:  "completed",
		Summary: &scanstream.Summary{Executed: 0},
	}, 5)
	if filtered["conclusion"] != "no_finding" {
		t.Fatalf("filtered conclusion = %v", filtered["conclusion"])
	}

	// 本机根本没有这个关键词的 PoC——最容易被误读成「无漏洞」的一种。
	noPoc := scanRunResult("http://t", "no-such-tech", &scanRun{
		Status:  "completed",
		Summary: &scanstream.Summary{},
	}, 0)
	if noPoc["conclusion"] != "no_poc_for_keyword" {
		t.Fatalf("no_poc conclusion = %v", noPoc["conclusion"])
	}
	lib, ok := noPoc["library"].(map[string]any)
	if !ok {
		t.Fatalf("library missing: %+v", noPoc)
	}
	if lib["matched_pocs"] != 0 {
		t.Fatalf("library matched_pocs = %v, want 0", lib["matched_pocs"])
	}
}

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
