package policy

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// 只读档位下写动作必须被拒，且拒绝不消耗预算——否则 Agent 光靠被拒就能把额度打空。
func TestGateDeniesWithoutConsumingBudget(t *testing.T) {
	g := NewGate(Default(), NewBudget(Limits{Requests: 100}, time.Now()), nil)

	err := g.Take(Action{Name: "probe.http", Target: "http://example.com"}, 1)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("readonly should deny probe.http, got %v", err)
	}
	// 错误文本仍要可被日志/调用方 grep 到，保持既有口径。
	if !strings.Contains(err.Error(), "policy denied") {
		t.Fatalf("denial message must stay greppable, got %q", err.Error())
	}
	if got := g.Budget().Remaining(); got != 100 {
		t.Fatalf("denied action must not consume budget, remaining = %d", got)
	}
}

// safe 档位放行写动作，并按动作声明的请求数扣减预算；超限时返回 ErrBudgetExceeded。
func TestGateAllowsAndConsumesBudget(t *testing.T) {
	p := &Policy{Mode: ModeSafe, Limits: Limits{Requests: 5, Duration: Duration(time.Minute)}}
	g := NewGate(p, NewBudget(p.Limits, time.Now()), nil)

	if err := g.Take(Action{Name: "probe.http", Target: "http://example.com"}, 3); err != nil {
		t.Fatalf("safe mode must allow probe.http: %v", err)
	}
	if got := g.Budget().Remaining(); got != 2 {
		t.Fatalf("remaining = %d, want 2", got)
	}
	if err := g.Take(Action{Name: "probe.http"}, 3); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("want ErrBudgetExceeded, got %v", err)
	}
}

// 零成本动作（读库、校验草稿）只校验时间预算，不消耗请求额度。
func TestGateZeroCostAction(t *testing.T) {
	p := &Policy{Mode: ModeReadOnly, Limits: Limits{Requests: 3, Duration: Duration(time.Minute)}}
	g := NewGate(p, NewBudget(p.Limits, time.Now()), nil)

	for i := 0; i < 10; i++ {
		if err := g.Take(Action{Name: "observe.findings"}, 0); err != nil {
			t.Fatalf("read-only action must not be budgeted: %v", err)
		}
	}
	if got := g.Budget().Remaining(); got != 3 {
		t.Fatalf("zero-cost actions changed budget, remaining = %d", got)
	}
}

// 开启审计时，放行与拒绝都要落一条记录，且带上真实剩余额度。
func TestGateRecordsAudit(t *testing.T) {
	var buf bytes.Buffer
	p := &Policy{Mode: ModeReadOnly, Audit: true, Limits: Limits{Requests: 10, Duration: Duration(time.Minute)}}
	g := NewGate(p, NewBudget(p.Limits, time.Now()), NewAuditor(&buf))

	_ = g.Take(Action{Name: "probe.http", Target: "http://example.com"}, 1)

	out := buf.String()
	if !strings.Contains(out, `"action":"probe.http"`) || !strings.Contains(out, `"allow":false`) {
		t.Fatalf("audit record missing or wrong: %q", out)
	}
	if !strings.Contains(out, `"rule":"readonly"`) {
		t.Fatalf("audit record should carry the deciding rule: %q", out)
	}
}
