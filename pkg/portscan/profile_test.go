package portscan

import (
	"testing"
	"time"
)

func TestTargetsArePrivate(t *testing.T) {
	cases := []struct {
		name  string
		hosts []string
		want  bool
	}{
		{"rfc1918", []string{"172.16.10.52", "10.0.0.1", "192.168.1.1"}, true},
		{"loopback", []string{"127.0.0.1"}, true},
		{"ipv6 loopback", []string{"::1"}, true},
		{"host:port", []string{"172.16.10.52:80"}, true},
		{"ipv6 host:port", []string{"[::1]:443"}, true},
		{"public", []string{"8.8.8.8"}, false},
		{"mixed", []string{"172.16.10.52", "8.8.8.8"}, false},
		{"hostname", []string{"example.com"}, false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := targetsArePrivate(tc.hosts); got != tc.want {
				t.Fatalf("targetsArePrivate(%v) = %v, want %v", tc.hosts, got, tc.want)
			}
		})
	}
}

// 内网全端口扫描的时间预算必须是分钟级而不是二十分钟级：速率由端口数反推，
// 并被「在飞池 / 超时预算」这一可持续吞吐上限收敛。
func TestDeriveSpeedProfileLANFullPort(t *testing.T) {
	p := deriveSpeedProfile(true, 0, 65535, 500, time.Second)
	if p.class != speedLAN {
		t.Fatalf("class = %v, want lan", p.class)
	}
	if p.target != autoLANSeconds*time.Second {
		t.Fatalf("target = %v, want %v", p.target, autoLANSeconds*time.Second)
	}
	// pool/timeout = 500/s 是可静默丢包场景下的可持续上限，速率必须收敛到它。
	if p.globalCPS != 500 {
		t.Fatalf("cps = %d, want 500 (pool/timeout cap)", p.globalCPS)
	}
	if p.perHostCPS != p.globalCPS {
		t.Fatalf("per-host cps = %d, want %d", p.perHostCPS, p.globalCPS)
	}
	if p.concurrency != 500 {
		t.Fatalf("concurrency = %d, want the pool cap 500", p.concurrency)
	}
}

// 即使网关不回包，私网目标也走内网档位：扫描 172.16.0.0/12 不该按公网预算慢跑。
func TestDeriveSpeedProfilePrivateWithoutBaseline(t *testing.T) {
	p := deriveSpeedProfile(true, 0, 65535, 500, time.Second)
	if p.class != speedLAN {
		t.Fatalf("class = %v, want lan for private targets", p.class)
	}
}

// 私网目标如果实测链路很慢（例如跨 VPN），仍应以观测到的 RTT 为准，
// 不能被「私网」二字强行套进内网高吞吐档。
func TestDeriveSpeedProfilePrivateSlowLink(t *testing.T) {
	metro := deriveSpeedProfile(true, 10*time.Millisecond, 65535, 500, time.Second)
	if metro.class != speedMetro {
		t.Fatalf("class = %v, want metro for a 10ms path", metro.class)
	}
	wan := deriveSpeedProfile(true, 100*time.Millisecond, 65535, 500, time.Second)
	if wan.class != speedWAN {
		t.Fatalf("class = %v, want wan for a 100ms path", wan.class)
	}
}

// 公网目标按网关空载 RTT 分档：低 RTT 仍可走内网预算，高 RTT 必须留出更长预算。
func TestDeriveSpeedProfilePublicByBaseline(t *testing.T) {
	lan := deriveSpeedProfile(false, 1*time.Millisecond, 65535, 500, time.Second)
	if lan.class != speedLAN {
		t.Fatalf("1ms baseline: class = %v, want lan", lan.class)
	}

	metro := deriveSpeedProfile(false, 10*time.Millisecond, 65535, 500, time.Second)
	if metro.class != speedMetro {
		t.Fatalf("10ms baseline: class = %v, want metro", metro.class)
	}
	if metro.target != autoMetroSeconds*time.Second {
		t.Fatalf("metro target = %v", metro.target)
	}
	if metro.globalCPS != (65535+autoMetroSeconds-1)/autoMetroSeconds {
		t.Fatalf("metro cps = %d, want %d", metro.globalCPS, (65535+autoMetroSeconds-1)/autoMetroSeconds)
	}

	wan := deriveSpeedProfile(false, 100*time.Millisecond, 65535, 500, time.Second)
	if wan.class != speedWAN {
		t.Fatalf("100ms baseline: class = %v, want wan", wan.class)
	}
	if wan.target != autoWANSeconds*time.Second {
		t.Fatalf("wan target = %v", wan.target)
	}
	if wan.globalCPS != (65535+autoWANSeconds-1)/autoWANSeconds {
		t.Fatalf("wan cps = %d", wan.globalCPS)
	}
}

func TestDeriveSpeedProfileUnknownBaselineIsWAN(t *testing.T) {
	p := deriveSpeedProfile(false, 0, 65535, 500, time.Second)
	if p.class != speedWAN {
		t.Fatalf("class = %v, want wan without a link baseline", p.class)
	}
}

// 小端口集不能被「端口数/预算」反推成极低速率（600 个端口按 120s 算只有 5/s），
// 必须有下限。
func TestDeriveSpeedProfileFloorForSmallPortSets(t *testing.T) {
	p := deriveSpeedProfile(true, 0, 600, 500, time.Second)
	if p.globalCPS != autoLANFloorCPS {
		t.Fatalf("cps = %d, want floor %d", p.globalCPS, autoLANFloorCPS)
	}
}

// 低 fd 预算的机器上，可持续吞吐上限必须压住速率，否则限速器会虚标、进度条照样慢。
func TestDeriveSpeedProfileRespectsPoolBudget(t *testing.T) {
	p := deriveSpeedProfile(true, 0, 65535, 100, time.Second)
	if p.globalCPS != 100 {
		t.Fatalf("cps = %d, want 100", p.globalCPS)
	}
	if p.concurrency != 100 {
		t.Fatalf("concurrency = %d, want 100", p.concurrency)
	}
}

// pool=0 表示 fd 无实质限制：不应套用可持续上限，按时间预算反推即可。
func TestDeriveSpeedProfileUnboundedPool(t *testing.T) {
	p := deriveSpeedProfile(true, 0, 65535, 0, time.Second)
	want := (65535 + autoLANSeconds - 1) / autoLANSeconds
	if p.globalCPS != want {
		t.Fatalf("cps = %d, want %d", p.globalCPS, want)
	}
	if p.concurrency > autoConcurrencyCeiling {
		t.Fatalf("concurrency = %d, exceeds ceiling", p.concurrency)
	}
}

func TestDeriveHostConcurrency(t *testing.T) {
	if got := deriveHostConcurrency(800, 500, time.Second); got != 500 {
		t.Fatalf("concurrency = %d, want pool cap 500", got)
	}
	if got := deriveHostConcurrency(100, 500, time.Second); got < 100 {
		t.Fatalf("concurrency = %d, want at least the rate", got)
	}
	// 显式不限速时不再叠加单目标闸，交给全局池约束。
	if got := deriveHostConcurrency(0, 500, time.Second); got != 0 {
		t.Fatalf("concurrency = %d, want 0 (unlimited)", got)
	}
}
