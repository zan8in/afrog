package portscan

import (
	"net"
	"strings"
	"time"
)

// speedClass 是本机到目标的链路档位。它决定全端口扫描的时间预算：
// 内网链路稳定、RTT 极低，可以用高吞吐快速铺开；公网链路抖动大、丢包多，
// 必须放慢节奏、留出更长的探测预算，避免把「链路慢」误判成「端口关」。
type speedClass int

const (
	speedLAN speedClass = iota
	speedMetro
	speedWAN
)

func (c speedClass) String() string {
	switch c {
	case speedLAN:
		return "lan"
	case speedMetro:
		return "metro"
	default:
		return "wan"
	}
}

// 各档位的时间预算与速率边界。
//
// 预算的语义是「单主机全端口扫描的目标耗时」：速率由端口数除以预算反推，
// 而不是拍一个固定 CPS。这样 top 扫描不会被固定速率拖慢，全端口扫描也不会
// 因为速率太低而跑到二十分钟以上。
//
// 上限用于防止小端口集被反推成离谱的瞬时速率；下限保证短扫描不会因为预算
// 太大而变得比必要还慢。
const (
	autoLANSeconds   = 120 // 内网：2 分钟量级扫完 65535 端口
	autoMetroSeconds = 180
	autoWANSeconds   = 300 // 公网：5 分钟量级，兼顾链路与丢包

	autoLANFloorCPS   = 300
	autoLANMaxCPS     = 4000
	autoMetroFloorCPS = 200
	autoMetroMaxCPS   = 2500
	autoWANFloorCPS   = 120
	autoWANMaxCPS     = 800

	// autoRTTLAN / autoRTTMetro 是网关空载 RTT 的档位分界。网关离本机只有
	// 一跳，它的 RTT 只反映本地出口链路，不受目标侧防火墙影响。
	autoRTTLAN   = 3 * time.Millisecond
	autoRTTMetro = 20 * time.Millisecond

	// autoConcurrencyHeadroom 是单目标并发的余量系数：并发要能覆盖一次完整
	// 超时预算内持续发起的探测，才不会被超时端口卡住吞吐。
	autoConcurrencyHeadroom = 1.2
	autoConcurrencyFloor    = 32
	autoConcurrencyCeiling  = 2048
)

// speedProfile 是本次扫描实际采用的速率与并发。
type speedProfile struct {
	class       speedClass
	target      time.Duration
	globalCPS   int
	perHostCPS  int
	concurrency int
}

// targetsArePrivate 判断目标是否全部为私网/回环/链路本地地址。私网目标即使
// 拿不到网关基线（很多网关不响应 80/443），也应走内网档位：用户扫 172.16.0.0/12
// 时不该被当成公网目标按五分钟预算慢跑。
func targetsArePrivate(hosts []string) bool {
	if len(hosts) == 0 {
		return false
	}
	for _, h := range hosts {
		host := h
		// 目标可能以 host:port 形式传入；先剥掉端口，否则 IP 解析永远失败、
		// 私网目标会被误判成公网目标。
		if hh, _, err := net.SplitHostPort(h); err == nil {
			host = hh
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil {
			return false
		}
		if !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return false
		}
	}
	return true
}

// deriveSpeedProfile 按链路档位、端口数与在飞池容量推导本次扫描的速率与并发。
//
// 关键约束是「被静默丢弃的端口」：每次探测要占用一个 fd 直到超时（默认 1s），
// 因此可持续吞吐的上限是 pool/timeout。速率必须收敛到这个上限以内，否则
// 限速器会把任务堆在池外，进度条照样走得慢。反过来，只要并发放得下，
// 关闭端口（RST）的吞吐就只受速率限制。
func deriveSpeedProfile(private bool, baseline time.Duration, portTotal, pool int, timeout time.Duration) speedProfile {
	class := speedWAN
	switch {
	case baseline > 0 && baseline <= autoRTTLAN:
		class = speedLAN
	case baseline > 0 && baseline <= autoRTTMetro:
		class = speedMetro
	case private && baseline <= 0:
		// 私网目标拿不到网关基线时按内网档位处理：很多网关不响应 80/443，
		// 但扫 172.16.0.0/12 显然不该套用公网的五分钟预算。
		class = speedLAN
	}

	var seconds, floorCPS, maxCPS int
	switch class {
	case speedLAN:
		seconds, floorCPS, maxCPS = autoLANSeconds, autoLANFloorCPS, autoLANMaxCPS
	case speedMetro:
		seconds, floorCPS, maxCPS = autoMetroSeconds, autoMetroFloorCPS, autoMetroMaxCPS
	default:
		seconds, floorCPS, maxCPS = autoWANSeconds, autoWANFloorCPS, autoWANMaxCPS
	}

	if portTotal <= 0 {
		portTotal = 1
	}
	cps := (portTotal + seconds - 1) / seconds
	if cps < floorCPS {
		cps = floorCPS
	}
	if cps > maxCPS {
		cps = maxCPS
	}

	// 超时端口的可持续吞吐 = 池容量 / 单次超时预算。池是所有主机共享的，
	// 因此这里也是全局速率的物理上限：速率超过它只会在池外排队，不会更快。
	if pool > 0 && timeout > 0 {
		sustainable := int(float64(pool) * float64(time.Second) / float64(timeout))
		if sustainable > 0 && cps > sustainable {
			cps = sustainable
		}
	}
	if cps < 1 {
		cps = 1
	}

	concurrency := int(float64(cps)*timeout.Seconds()*autoConcurrencyHeadroom) + autoConcurrencyFloor
	if concurrency < autoConcurrencyFloor {
		concurrency = autoConcurrencyFloor
	}
	if concurrency > autoConcurrencyCeiling {
		concurrency = autoConcurrencyCeiling
	}
	if pool > 0 && concurrency > pool {
		concurrency = pool
	}
	if concurrency < 1 {
		concurrency = 1
	}

	return speedProfile{
		class:       class,
		target:      time.Duration(seconds) * time.Second,
		globalCPS:   cps,
		perHostCPS:  cps,
		concurrency: concurrency,
	}
}

// deriveHostConcurrency 在用户显式给定速率（未启用 AutoRate）时，仍按速率
// 反推单目标并发。固定 50 并发会让 800/s 的配置在超时端口上退化成 50/s，
// 速率配置形同虚设。
func deriveHostConcurrency(perHostCPS int, pool int, timeout time.Duration) int {
	if perHostCPS <= 0 {
		// 显式不限速：交给全局池约束，不再叠加单目标闸。
		return 0
	}
	concurrency := int(float64(perHostCPS)*timeout.Seconds()*autoConcurrencyHeadroom) + autoConcurrencyFloor
	if concurrency < autoConcurrencyFloor {
		concurrency = autoConcurrencyFloor
	}
	if concurrency > autoConcurrencyCeiling {
		concurrency = autoConcurrencyCeiling
	}
	if pool > 0 && concurrency > pool {
		concurrency = pool
	}
	return concurrency
}
