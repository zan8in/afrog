package retryhttpclient

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// withAutoReqLimiter 把一个可控的限速器装到包级变量上，并在用例结束后恢复。
func withAutoReqLimiter(t *testing.T, rate int) *hostPortLimiter {
	t.Helper()
	old := reqLimiter
	l := newHostPortLimiter(rate)
	reqLimiter = l
	t.Cleanup(func() { reqLimiter = old })
	return l
}

// resetAutoReqLimitSignals 清零所有参与判定的原子计数，避免用例间相互污染。
func resetAutoReqLimitSignals(t *testing.T) {
	t.Helper()
	atomic.StoreInt64(&httpAttemptTotal, 0)
	atomic.StoreInt64(&httpAttemptFailure, 0)
	atomic.StoreInt64(&httpLatencyNs, 0)
	atomic.StoreInt64(&reqLimitWaitNs, 0)
	atomic.StoreInt64(&reqLimitWaitCount, 0)
	t.Cleanup(func() {
		atomic.StoreInt64(&httpAttemptTotal, 0)
		atomic.StoreInt64(&httpAttemptFailure, 0)
		atomic.StoreInt64(&httpLatencyNs, 0)
		atomic.StoreInt64(&reqLimitWaitNs, 0)
		atomic.StoreInt64(&reqLimitWaitCount, 0)
	})
}

// primeController 造一个已完成预热的控制器，prev 指向当前（已清零的）计数快照。
func primeController(minRate, maxRate int) *autoReqLimitController {
	return &autoReqLimitController{
		limiter: reqLimiter,
		minRate: minRate,
		maxRate: maxRate,
		prev:    GetLiveMetrics(),
	}
}

// feed 累加一个窗口内的观测：attempts 次往返，其中 failures 次没拿到响应，
// 平均时延 avgLatency，限速器平均排队 avgWait。累加语义让 prev 快照天然构成差分。
func feed(attempts, failures int64, avgLatency, avgWait time.Duration) {
	atomic.AddInt64(&httpAttemptTotal, attempts)
	atomic.AddInt64(&httpAttemptFailure, failures)
	atomic.AddInt64(&httpLatencyNs, int64(avgLatency)*attempts)
	if avgWait > 0 {
		atomic.AddInt64(&reqLimitWaitCount, attempts)
		atomic.AddInt64(&reqLimitWaitNs, int64(avgWait)*attempts)
	}
}

// 高失败率应触发乘性降速：30 -> 21（30*0.7）。
func TestAutoReqLimitDecreasesOnNoResponse(t *testing.T) {
	withAutoReqLimiter(t, 30)
	resetAutoReqLimitSignals(t)
	c := primeController(5, 30)

	feed(40, 30, 10*time.Millisecond, 0) // 失败率 75%
	c.tick()

	if got := GetReqLimitPerTarget(); got != 21 {
		t.Fatalf("高失败率应降到 21，实际 %d", got)
	}
}

// 时延相对空载基线抬升 3 倍以上应触发降速。第一轮先建立基线，第二轮才劣化。
func TestAutoReqLimitDecreasesOnLatency(t *testing.T) {
	withAutoReqLimiter(t, 30)
	resetAutoReqLimitSignals(t)
	c := primeController(5, 30)

	feed(40, 0, 10*time.Millisecond, 0)
	c.tick() // 建立基线（下限 50ms），此时不该动
	if got := GetReqLimitPerTarget(); got != 30 {
		t.Fatalf("建立基线阶段不该调速，实际 %d", got)
	}

	feed(40, 0, 200*time.Millisecond, 0) // 倍率 4x
	c.tick()

	if got := GetReqLimitPerTarget(); got != 21 {
		t.Fatalf("时延劣化应降到 21，实际 %d", got)
	}
}

// 健康目标且限速器确实在排队时才加性升速：10 -> 12（+1/5）。
func TestAutoReqLimitIncreasesWhenHealthyAndQueued(t *testing.T) {
	withAutoReqLimiter(t, 10)
	resetAutoReqLimitSignals(t)
	c := primeController(5, 30)

	feed(40, 0, 10*time.Millisecond, 300*time.Millisecond)
	c.tick()

	if got := GetReqLimitPerTarget(); got != 12 {
		t.Fatalf("健康且排队时应升到 12，实际 %d", got)
	}
}

// 没有排队说明瓶颈不在限速器上，即使目标健康也不该提额度。
func TestAutoReqLimitDoesNotIncreaseWithoutQueue(t *testing.T) {
	withAutoReqLimiter(t, 10)
	resetAutoReqLimitSignals(t)
	c := primeController(5, 30)

	feed(40, 0, 10*time.Millisecond, 10*time.Millisecond)
	c.tick()

	if got := GetReqLimitPerTarget(); got != 10 {
		t.Fatalf("未排队时不该升速，实际 %d", got)
	}
}

// 样本不足时不做任何判定，避免起步抖动带偏。
func TestAutoReqLimitSkipsWhenSamplesInsufficient(t *testing.T) {
	withAutoReqLimiter(t, 30)
	resetAutoReqLimitSignals(t)
	c := primeController(5, 30)

	feed(5, 5, 10*time.Millisecond, 0) // 样本低于阈值
	c.tick()

	if got := GetReqLimitPerTarget(); got != 30 {
		t.Fatalf("样本不足时不该调速，实际 %d", got)
	}
}

// 降速不得击穿地板。
func TestAutoReqLimitClampsToMinRate(t *testing.T) {
	withAutoReqLimiter(t, 6)
	resetAutoReqLimitSignals(t)
	c := primeController(5, 30)

	feed(40, 40, 10*time.Millisecond, 0)
	c.tick()

	if got := GetReqLimitPerTarget(); got != 5 {
		t.Fatalf("应钳制到地板 5，实际 %d", got)
	}
}

// 降速只在方向翻转时告警一次；持续劣化在告警间隔内保持静默。
func TestAutoReqLimitReportsFirstDecreaseOnly(t *testing.T) {
	withAutoReqLimiter(t, 30)
	resetAutoReqLimitSignals(t)
	c := primeController(5, 30)

	var events []AutoReqLimitEvent
	SetAutoReqLimitReporter(func(ev AutoReqLimitEvent) { events = append(events, ev) })
	t.Cleanup(func() { SetAutoReqLimitReporter(nil) })

	feed(40, 40, 10*time.Millisecond, 0)
	c.tick()
	feed(40, 40, 10*time.Millisecond, 0)
	c.tick()

	if len(events) != 1 {
		t.Fatalf("连续降速只应告警一次，实际 %d 次", len(events))
	}
	if events[0].Reason != "no-response" || events[0].NewRate >= events[0].OldRate {
		t.Fatalf("告警内容不对: %+v", events[0])
	}
}

// 从降速切回升速时给出一次 Recovered 提示。
func TestAutoReqLimitReportsRecovery(t *testing.T) {
	withAutoReqLimiter(t, 30)
	resetAutoReqLimitSignals(t)
	c := primeController(5, 30)

	var recovered []AutoReqLimitEvent
	SetAutoReqLimitReporter(func(ev AutoReqLimitEvent) {
		if ev.Recovered {
			recovered = append(recovered, ev)
		}
	})
	t.Cleanup(func() { SetAutoReqLimitReporter(nil) })

	feed(40, 40, 10*time.Millisecond, 0)
	c.tick() // 降到 21

	feed(40, 0, 10*time.Millisecond, 300*time.Millisecond)
	c.tick() // 健康且排队，回升

	if len(recovered) != 1 {
		t.Fatalf("应有一次恢复提示，实际 %d 次", len(recovered))
	}
	if got := GetReqLimitPerTarget(); got <= 21 {
		t.Fatalf("恢复后速率应高于降速后的 21，实际 %d", got)
	}
}

// observeHTTPAttempt 记录真实往返，但被上层取消的请求不计入。
func TestObserveHTTPAttemptIgnoresCanceled(t *testing.T) {
	resetAutoReqLimitSignals(t)

	canceled, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled = canceled.WithContext(ctx)

	observeHTTPAttempt(canceled, nil, 10*time.Millisecond)
	if atomic.LoadInt64(&httpAttemptTotal) != 0 {
		t.Fatal("取消的请求不该计入判定样本")
	}

	live, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	observeHTTPAttempt(live, nil, 10*time.Millisecond)

	if atomic.LoadInt64(&httpAttemptTotal) != 1 {
		t.Fatalf("存活请求应计入样本，实际 %d", atomic.LoadInt64(&httpAttemptTotal))
	}
	if atomic.LoadInt64(&httpAttemptFailure) != 1 {
		t.Fatal("无响应应计为失败")
	}
	if atomic.LoadInt64(&httpLatencyNs) != int64(10*time.Millisecond) {
		t.Fatal("时延应被累计")
	}
}
