package poc

import (
	"testing"
	"time"

	"gopkg.in/yaml.v2"
)

func TestEstimateTaskTimeout_SniperBruteAndExpression(t *testing.T) {
	p := Poc{
		Id:         "springboot-actuator-unauth",
		Expression: "r0() || r1()",
		Rules: RuleMapSlice{
			{
				Key: "r0",
				Value: Rule{
					Brute: yaml.MapSlice{
						{Key: "mode", Value: "sniper"},
						{Key: "p", Value: []any{"/env", "/appenv", "/env%72", "/appenv%72", ";;/env;.css"}},
					},
				},
			},
			{
				Key: "r1",
				Value: Rule{
					Brute: yaml.MapSlice{
						{Key: "mode", Value: "sniper"},
						{Key: "p", Value: []any{"/actuator", "/api/actuator", "/nacos/actuator", "/prod-api/actuator", "/dev-api/actuator", "/actuato%72", "/api/actuato%72", "/nacos/actuato%72", "/prod-api/actuato%72", "/dev-api/actuato%72"}},
					},
				},
			},
		},
	}

	got := EstimateTaskTimeout(p, TaskTimeoutPolicy{
		VisibleCapSec: 300,
		NetCapSec:     360,
		GoCapSec:      420,
	})

	if got.TimeoutSec != 160 {
		t.Fatalf("expected 160s, got %ds (%s)", got.TimeoutSec, got.Reason)
	}
}

func TestEstimateTaskTimeout_ClusterbombBrute(t *testing.T) {
	p := Poc{
		Id: "druid-default-login",
		Rules: RuleMapSlice{
			{
				Key: "r0",
				Value: Rule{
					Brute: yaml.MapSlice{
						{Key: "mode", Value: "clusterbomb"},
						{Key: "p", Value: []any{1, 2, 3, 4, 5, 6, 7}},
						{Key: "username", Value: []any{"admin", "ruoyi", "druid"}},
						{Key: "password", Value: []any{"admin", "123456", "druid", "admin123", "admin888"}},
					},
				},
			},
		},
	}

	got := EstimateTaskTimeout(p, TaskTimeoutPolicy{
		VisibleCapSec: 300,
		NetCapSec:     360,
		GoCapSec:      420,
	})

	if got.TimeoutSec != 240 {
		t.Fatalf("expected 240s, got %ds (%s)", got.TimeoutSec, got.Reason)
	}
}

func TestEstimateTaskTimeout_GoPocUsesGoBonus(t *testing.T) {
	p := Poc{
		Id:    "backup-files",
		Gopoc: "backup-files",
		Rules: RuleMapSlice{
			{Key: "r0", Value: Rule{}},
		},
	}

	got := EstimateTaskTimeout(p, TaskTimeoutPolicy{
		VisibleCapSec: 300,
		NetCapSec:     360,
		GoCapSec:      420,
	})

	if got.TimeoutSec != 240 {
		t.Fatalf("expected 240s, got %ds (%s)", got.TimeoutSec, got.Reason)
	}
}

func TestEstimateTaskTimeout_JSPocUsesNetBonus(t *testing.T) {
	p := Poc{
		Id: "js-demo-ssh-banner",
		Rules: RuleMapSlice{
			{Key: "r0", Value: Rule{Request: RuleRequest{Type: JS_Type}}},
		},
	}

	got := EstimateTaskTimeout(p, TaskTimeoutPolicy{
		VisibleCapSec: 300,
		NetCapSec:     360,
		GoCapSec:      420,
	})

	if got.TimeoutSec != 120 {
		t.Fatalf("expected 120s, got %ds (%s)", got.TimeoutSec, got.Reason)
	}
}

func TestTaskTimeoutDuration_UsesLargerFallback(t *testing.T) {
	p := &Poc{EstimatedTaskTimeoutSec: 160}
	got := TaskTimeoutDuration(p, 180)
	if got != 180*time.Second {
		t.Fatalf("expected 180s, got %s", got)
	}
}
