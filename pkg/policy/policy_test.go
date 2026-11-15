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

	for _, name := range []string{"probe.http", "verify.poc", "observe.findings", "poc.search"} {
		if v := p.Evaluate(Action{Name: name, Target: "http://example.com"}); !v.Allow {
			t.Fatalf("%s must be allowed in safe mode: %+v", name, v)
		}
	}
	if v := p.Evaluate(Action{Name: "act.brute", Target: "http://example.com"}); v.Allow {
		t.Fatalf("act.* must be denied in safe mode: %+v", v)
	}
	if v := p.Evaluate(Action{Name: "verify.poc", Target: "http://example.com", Destructive: true}); v.Allow {
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
	p := &Policy{Mode: ModeFull, Allow: []string{"observe.*", "verify.poc"}}
	if v := p.Evaluate(Action{Name: "probe.http", Target: "http://example.com"}); v.Allow {
		t.Fatalf("action outside allowlist must be denied: %+v", v)
	}
	if v := p.Evaluate(Action{Name: "verify.poc", Target: "http://example.com"}); !v.Allow {
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

func TestBudgetExpiry(t *testing.T) {
	now := time.Now().Add(-time.Hour)
	b := NewBudget(Limits{Requests: 10, Duration: Duration(time.Minute)}, now)
	if err := b.Take(1); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("expired budget must reject, got %v", err)
	}
}

// 不产生网络请求的动作（读库、取证据、校验草稿）传 0，不能扣请求额度；
// 但会话时间预算到期后仍然要拒绝。
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
	if err := expired.Take(0); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("expired session must reject even zero-cost actions, got %v", err)
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
