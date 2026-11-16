package policy

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/capability"
)

func TestDefaultIsReadOnly(t *testing.T) {
	p := Default()
	if p.Mode != ModeReadOnly {
		t.Fatalf("default mode = %q, want readonly", p.Mode)
	}
	if v := p.Evaluate(Action{Name: "observe.evidence"}); !v.Allow {
		t.Fatalf("observe must be allowed: %+v", v)
	}
	if v := p.Evaluate(Action{Name: "probe.http", Target: "http://example.com"}); v.Allow {
		t.Fatalf("probe must be denied in readonly mode: %+v", v)
	}
}

func TestSafeMode(t *testing.T) {
	p := &Policy{Mode: ModeSafe}

	for _, name := range []string{"probe.http", "scan.start", "observe.findings", "poc.search"} {
		if v := p.Evaluate(Action{Name: name, Target: "http://example.com"}); !v.Allow {
			t.Fatalf("%s must be allowed in safe mode: %+v", name, v)
		}
	}
	if v := p.Evaluate(Action{Name: "act.brute", Target: "http://example.com"}); v.Allow {
		t.Fatalf("act.* must be denied in safe mode: %+v", v)
	}
	if v := p.Evaluate(Action{Name: "scan.start", Target: "http://example.com", Destructive: true}); v.Allow {
		t.Fatalf("destructive action must be denied by default: %+v", v)
	}
}

func TestFullModeStillRequiresDestructiveFlag(t *testing.T) {
	p := &Policy{Mode: ModeFull}
	if v := p.Evaluate(Action{Name: "act.brute", Target: "http://example.com", Capability: capability.Exec}); v.Allow {
		t.Fatalf("exec capability must require destructive=true: %+v", v)
	}

	p.Destructive = true
	if v := p.Evaluate(Action{Name: "act.brute", Target: "http://example.com", Capability: capability.Exec}); !v.Allow {
		t.Fatalf("full mode with destructive=true must allow act: %+v", v)
	}
}

func TestDenyWinsOverAllow(t *testing.T) {
	p := &Policy{Mode: ModeFull, Allow: []string{"*"}, Deny: []string{"act.*"}}
	if v := p.Evaluate(Action{Name: "act.brute"}); v.Allow || v.Rule != "deny" {
		t.Fatalf("deny must win: %+v", v)
	}
}

func TestAllowlistRestricts(t *testing.T) {
	p := &Policy{Mode: ModeFull, Allow: []string{"observe.*", "scan.start"}}
	if v := p.Evaluate(Action{Name: "probe.http", Target: "http://example.com"}); v.Allow {
		t.Fatalf("action outside allowlist must be denied: %+v", v)
	}
	if v := p.Evaluate(Action{Name: "scan.start", Target: "http://example.com"}); !v.Allow {
		t.Fatalf("allowlisted action must be allowed: %+v", v)
	}
}

func TestScope(t *testing.T) {
	p := &Policy{
		Mode: ModeSafe,
		Scope: Scope{
			AllowHosts: []string{"10.0.0.0/8", "*.corp.example", "api.example.com"},
			DenyHosts:  []string{"10.0.0.1"},
			DenyPaths:  []string{"/logout"},
		},
	}

	cases := []struct {
		target string
		allow  bool
	}{
		{"http://10.1.2.3/a", true},
		{"http://10.0.0.1/a", false},
		{"http://evil.example.com/a", false},
		{"https://api.corp.example/a", true},
		{"https://api.example.com/user/logout", false},
		{"https://api.example.com/users", true},
	}
	for _, c := range cases {
		if v := p.Evaluate(Action{Name: "probe.http", Target: c.target}); v.Allow != c.allow {
			t.Fatalf("target %q: allow=%v want %v (%+v)", c.target, v.Allow, c.allow, v)
		}
	}
}

func TestParsePolicyWrapperAndDuration(t *testing.T) {
	p, err := Parse([]byte(`
policy:
  mode: full
  deny: ["act.brute"]
  scope:
    allow_hosts: ["10.0.0.0/8"]
  budget:
    requests: 100
    duration: 2m
  destructive: true
  audit: true
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Mode != ModeFull || !p.Destructive || !p.Audit {
		t.Fatalf("unexpected policy: %+v", p)
	}
	if p.Limits.Requests != 100 || p.Limits.Duration.Duration() != 2*time.Minute {
		t.Fatalf("unexpected limits: %+v", p.Limits)
	}
}

func TestParseBarePolicyAppliesDefaults(t *testing.T) {
	p, err := Parse([]byte("mode: safe\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Mode != ModeSafe || p.Limits.Requests != DefaultRequests {
		t.Fatalf("defaults not applied: %+v", p)
	}
}

func TestBudget(t *testing.T) {
	b := NewBudget(Limits{Requests: 2, Duration: Duration(time.Minute)}, time.Now())
	if err := b.Take(1); err != nil {
		t.Fatalf("take 1: %v", err)
	}
	if err := b.Take(1); err != nil {
		t.Fatalf("take 2: %v", err)
	}
	if err := b.Take(1); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("expected budget exceeded, got %v", err)
	}
	if b.Remaining() != 0 {
		t.Fatalf("remaining = %d, want 0", b.Remaining())
	}
}

// 空闲超过 Duration 即视为上个会话结束：下一次消耗额度的调用自动开新会话、把额度
// 补满，而不是把长驻服务整体拒掉。
func TestBudgetIdleResetsSession(t *testing.T) {
	b := NewBudget(Limits{Requests: 2, Duration: Duration(time.Minute)}, time.Now().Add(-time.Hour))
	if err := b.Take(1); err != nil {
		t.Fatalf("idle-expired session must start a fresh one, got %v", err)
	}
	if got := b.Remaining(); got != 1 {
		t.Fatalf("remaining = %d, want 1 (fresh session of 2)", got)
	}
	if err := b.Take(1); err != nil {
		t.Fatalf("take 2: %v", err)
	}
	if err := b.Take(1); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("exhausted session must reject, got %v", err)
	}
}

// 不产生网络请求的动作（读库、取证据、校验草稿）传 0：不扣请求额度，也不受空闲
// 超时影响——查证据不该被「额度」挡住。
func TestBudgetZeroCostActions(t *testing.T) {
	b := NewBudget(Limits{Requests: 2, Duration: Duration(time.Minute)}, time.Now())
	for i := 0; i < 5; i++ {
		if err := b.Take(0); err != nil {
			t.Fatalf("take 0 #%d: %v", i, err)
		}
	}
	if b.Remaining() != 2 {
		t.Fatalf("remaining = %d, want 2", b.Remaining())
	}

	expired := NewBudget(Limits{Requests: 2, Duration: Duration(time.Minute)}, time.Now().Add(-time.Hour))
	if err := expired.Take(0); err != nil {
		t.Fatalf("zero-cost action must never be budgeted, got %v", err)
	}
}

// 只读调用不顺延空闲窗口：额度用尽后靠轮询只读结果「续命」是不成立的，窗口照常
// 推进，到点自动开新会话。
func TestBudgetZeroCostDoesNotExtendWindow(t *testing.T) {
	b := NewBudget(Limits{Requests: 1, Duration: Duration(50 * time.Millisecond)}, time.Now())
	if err := b.Take(1); err != nil {
		t.Fatalf("first take: %v", err)
	}
	time.Sleep(80 * time.Millisecond) // 让空闲窗口过期

	if err := b.Take(0); err != nil {
		t.Fatalf("read-only call must stay allowed: %v", err)
	}
	// 只读调用若顺延了窗口，这里会被判成「会话还活着但额度已用光」。
	if err := b.Take(1); err != nil {
		t.Fatalf("read-only calls must not keep the session alive, got %v", err)
	}
}

func TestAuditorWritesJSONL(t *testing.T) {
	var buf bytes.Buffer
	a := NewAuditor(&buf)
	if err := a.Record(Record{Action: "probe.http", Target: "http://x", Allow: true, Rule: "allow"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"action":"probe.http"`) || !strings.HasSuffix(out, "\n") {
		t.Fatalf("unexpected audit line: %q", out)
	}
}
