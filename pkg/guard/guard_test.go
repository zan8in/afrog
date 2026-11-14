package guard

import (
	"strings"
	"testing"
)

// TestDefaultAllow 锁定「默认不改变既有行为」：没配置就等于全放行。
func TestDefaultAllow(t *testing.T) {
	p := NewPolicy(nil, nil)
	d := p.Check(ActionClusterDispatch, "10.0.0.5")
	if !d.Allowed || d.Mode != ModeAllow {
		t.Fatalf("默认裁决 = %+v, want allow", d)
	}
	// 空白名单必须序列化为 []，否则前端读 .length 会直接抛错（曾导致抽屉卡在加载中）。
	if v := p.Snapshot(); v.AllowTargets == nil {
		t.Fatalf("空白名单不应是 nil")
	}
	if s := p.Summary(); s.AllowTargets == nil {
		t.Fatalf("概览里的空白名单不应是 nil")
	}
}

// TestDenyAndAsk 锁定两种拦截语义：deny 是策略拒绝，ask 是待人工确认。
func TestDenyAndAsk(t *testing.T) {
	p := NewPolicy(map[string]string{
		"cluster-dispatch": "deny",
		"exposure-probe":   "ask",
	}, nil)

	if d := p.Check(ActionClusterDispatch, "a.example"); d.Allowed {
		t.Fatalf("deny 模式下不应放行: %+v", d)
	}
	d := p.Check(ActionExposureProbe, "a.example")
	if d.Allowed || !strings.Contains(d.Reason, "人工确认") {
		t.Fatalf("ask 必须拦截并说明原因: %+v", d)
	}
}

// TestAllowTargets 锁定白名单的三种写法与「硬边界」语义。
func TestAllowTargets(t *testing.T) {
	p := NewPolicy(map[string]string{"cluster-dispatch": "allow"}, []string{
		"a.example",
		"*.corp.example",
		"10.0.0.0/24",
	})

	allowed := []string{
		"a.example",
		"https://a.example/login",
		"a.example:8443",
		"corp.example",
		"api.corp.example",
		"https://api.corp.example:8443/x",
		"10.0.0.5",
		"http://10.0.0.5:8080/api",
	}
	for _, target := range allowed {
		if d := p.Check(ActionClusterDispatch, target); !d.Allowed {
			t.Fatalf("%s 应命中白名单: %+v", target, d)
		}
	}

	denied := []string{
		"b.example",
		"a.example.evil.com",
		"evilcorp.example",
		"10.0.1.5",
		"https://10.0.1.5/x",
		"",
	}
	for _, target := range denied {
		d := p.Check(ActionClusterDispatch, target)
		if d.Allowed {
			t.Fatalf("%s 不应放行: %+v", target, d)
		}
		if !strings.Contains(d.Reason, "白名单") {
			t.Fatalf("%s 的拒绝原因应指向白名单: %+v", target, d)
		}
	}
}

// TestAuditNewestFirst 锁定审计可读性：最新在前，且不会无限增长。
func TestAuditNewestFirst(t *testing.T) {
	p := NewPolicy(map[string]string{"cluster-dispatch": "deny"}, nil)
	for i := 0; i < auditLimit+10; i++ {
		p.Check(ActionClusterDispatch, "a.example")
	}

	view := p.Snapshot()
	if len(view.Audit) != auditLimit {
		t.Fatalf("审计条数 = %d, want %d", len(view.Audit), auditLimit)
	}
	if view.Actions["cluster-dispatch"] != "deny" {
		t.Fatalf("快照未包含配置: %+v", view.Actions)
	}
	if view.Audit[0].Time.Before(view.Audit[len(view.Audit)-1].Time) {
		t.Fatalf("审计应按时间倒序")
	}
}
