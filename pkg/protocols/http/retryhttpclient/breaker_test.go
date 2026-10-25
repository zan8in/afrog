package retryhttpclient

import (
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/poc"
)

// withBreakerTuning 压缩阈值与冷却时长，让状态机能在毫秒级跑完。
func withBreakerTuning(t *testing.T, threshold int, cooldown time.Duration) {
	t.Helper()
	oldThreshold, oldCooldown := hostBreakerThreshold, hostBreakerCooldown
	hostBreakerThreshold, hostBreakerCooldown = threshold, cooldown
	ResetHostBreaker()
	t.Cleanup(func() {
		hostBreakerThreshold, hostBreakerCooldown = oldThreshold, oldCooldown
		ResetHostBreaker()
	})
}

func TestHostBreakerTripsAfterThreshold(t *testing.T) {
	withBreakerTuning(t, 5, time.Second)

	for i := 0; i < 4; i++ {
		reqBreaker.observe("1.2.3.4:80", false, false)
		if err := reqBreaker.wait("1.2.3.4:80"); err != nil {
			t.Fatalf("第 %d 次失败后不该熔断: %v", i+1, err)
		}
	}

	reqBreaker.observe("1.2.3.4:80", false, false)
	err := reqBreaker.wait("1.2.3.4:80")
	if err == nil {
		t.Fatal("达到阈值后应熔断")
	}
	if !IsHostBreakerSuppressed(err) {
		t.Fatalf("错误类型不可识别: %v", err)
	}
	// 其它 host:port 不受影响。
	if err := reqBreaker.wait("1.2.3.4:443"); err != nil {
		t.Fatalf("熔断不该波及其它端口: %v", err)
	}
}

func TestHostBreakerResetsOnResponse(t *testing.T) {
	withBreakerTuning(t, 5, time.Second)

	for i := 0; i < 4; i++ {
		reqBreaker.observe("1.2.3.4:80", false, false)
	}
	// 任何 HTTP 响应（哪怕是 500）都说明目标可达，失败计数清零。
	reqBreaker.observe("1.2.3.4:80", true, false)

	for i := 0; i < 4; i++ {
		reqBreaker.observe("1.2.3.4:80", false, false)
	}
	if err := reqBreaker.wait("1.2.3.4:80"); err != nil {
		t.Fatalf("成功一次后应重新计数: %v", err)
	}
}

func TestHostBreakerHalfOpenAllowsSingleProbe(t *testing.T) {
	withBreakerTuning(t, 1, 20*time.Millisecond)

	reqBreaker.observe("1.2.3.4:80", false, false)
	if !IsHostBreakerSuppressed(reqBreaker.wait("1.2.3.4:80")) {
		t.Fatal("阈值 1 时应立即熔断")
	}

	time.Sleep(30 * time.Millisecond)

	// 冷却到期只放行一个探测名额。
	if err := reqBreaker.wait("1.2.3.4:80"); err != nil {
		t.Fatalf("冷却到期应放行一次探测: %v", err)
	}
	if !IsHostBreakerSuppressed(reqBreaker.wait("1.2.3.4:80")) {
		t.Fatal("探测名额已被占用，后续请求应继续被挡")
	}

	// 探测失败后立即重新熔断，无需再攒满阈值。
	reqBreaker.observe("1.2.3.4:80", false, false)
	if !IsHostBreakerSuppressed(reqBreaker.wait("1.2.3.4:80")) {
		t.Fatal("探测失败后应立即重新熔断")
	}
}

func TestHostBreakerHalfOpenRecoversOnResponse(t *testing.T) {
	withBreakerTuning(t, 1, 20*time.Millisecond)

	reqBreaker.observe("1.2.3.4:80", false, false)
	time.Sleep(30 * time.Millisecond)
	if err := reqBreaker.wait("1.2.3.4:80"); err != nil {
		t.Fatalf("冷却到期应放行一次探测: %v", err)
	}
	reqBreaker.observe("1.2.3.4:80", true, false)

	if err := reqBreaker.wait("1.2.3.4:80"); err != nil {
		t.Fatalf("探测成功后应完全恢复: %v", err)
	}
}

func TestHostBreakerIgnoresCanceledRequests(t *testing.T) {
	withBreakerTuning(t, 2, time.Second)

	// 被上层取消（中断/任务硬超时）不能算作目标不可达。
	for i := 0; i < 10; i++ {
		reqBreaker.observe("1.2.3.4:80", false, true)
	}
	if err := reqBreaker.wait("1.2.3.4:80"); err != nil {
		t.Fatalf("取消的请求不该触发熔断: %v", err)
	}
}

func TestHostBreakerReportsFirstTripOnly(t *testing.T) {
	withBreakerTuning(t, 1, 20*time.Millisecond)

	var trips int
	SetHostBreakerReporter(func(string, time.Time, int) { trips++ })
	t.Cleanup(func() { SetHostBreakerReporter(nil) })

	reqBreaker.observe("1.2.3.4:80", false, false)
	time.Sleep(30 * time.Millisecond)
	_ = reqBreaker.wait("1.2.3.4:80")
	reqBreaker.observe("1.2.3.4:80", false, false)

	if trips != 1 {
		t.Fatalf("同一次失联只应提示一次，实际 %d 次", trips)
	}
}

func TestRequestCanceledOnlyForCanceledContext(t *testing.T) {
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if requestCanceled(req) {
		t.Fatal("存活上下文不该判定为取消")
	}
	if requestCanceled(nil) {
		t.Fatal("nil 请求不该判定为取消")
	}
}

func TestResetHostBreaker(t *testing.T) {
	withBreakerTuning(t, 1, time.Second)

	reqBreaker.observe("1.2.3.4:80", false, false)
	if !IsHostBreakerSuppressed(reqBreaker.wait("1.2.3.4:80")) {
		t.Fatal("应先熔断")
	}
	ResetHostBreaker()
	if err := reqBreaker.wait("1.2.3.4:80"); err != nil {
		t.Fatalf("重置后应完全恢复: %v", err)
	}
}

// TestHostBreakerSkipsRequestsToDeadHost 走真实 socket：一个只收连接、永不回包的
// 监听器，验证熔断生效后请求确实不再建连（而不是等满超时再失败）。
func TestHostBreakerSkipsRequestsToDeadHost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var accepted int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&accepted, 1)
			go func() {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn) // 收下请求，永不回包
			}()
		}
	}()

	if err := Init(&Options{Timeout: 1, Retries: 0, MaxRespBodySize: 1}); err != nil {
		t.Fatalf("init: %v", err)
	}
	oldTimeout := defaultTimeout
	defaultTimeout = 200 * time.Millisecond
	t.Cleanup(func() { defaultTimeout = oldTimeout })

	withBreakerTuning(t, 3, time.Minute)

	target := "http://" + ln.Addr().String() + "/"
	rule := poc.Rule{Request: poc.RuleRequest{Method: http.MethodGet, Path: "/"}}

	for i := 0; i < 3; i++ {
		if err := Request(target, nil, rule, map[string]any{}); err == nil {
			t.Fatalf("第 %d 次请求不该成功", i+1)
		}
	}

	before := atomic.LoadInt32(&accepted)
	if before == 0 {
		t.Fatal("熔断前应产生真实连接")
	}

	for i := 0; i < 10; i++ {
		err := Request(target, nil, rule, map[string]any{})
		if err == nil {
			t.Fatalf("熔断期第 %d 次请求不该成功", i+1)
		}
	}
	if after := atomic.LoadInt32(&accepted); after != before {
		t.Fatalf("熔断期的请求不该再建连: before=%d after=%d", before, after)
	}
}
