package retryhttpclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// 漏洞扫描真正拖慢整体速率的往往不是限速，而是少数「连得上但不再回包」的
// host:port：落在它们身上的每个 HTTP PoC 都要等满 -timeout 才返回，后面的
// 上千个 PoC 只能排队撞超时，整体速率被拉到个位数。
//
// 这里按 host:port 记录「连续多少次连响应头都没拿到」，达到阈值即熔断一小段
// 时间——期间直接返回错误、不产生任何网络开销；冷却到期后只放行一次探测，
// 仍失败就再次熔断。判定口径只看「有没有拿到 HTTP 响应」：404/403/500 都算
// 拿到了响应，它们只说明服务在跑，与可达性无关。
// 阈值与冷却时长保持可变，便于测试压缩时间；生产路径只用默认值。
var (
	// hostBreakerThreshold 连续多少次无响应即熔断。
	hostBreakerThreshold = 5
	// hostBreakerCooldown 熔断时长；到期放行一次探测，成功即恢复。
	hostBreakerCooldown = 30 * time.Second
)

// hostBreakerSuppressedError 表示请求因 host:port 处于熔断期而被跳过。
type hostBreakerSuppressedError struct {
	host  string
	until time.Time
}

func (e *hostBreakerSuppressedError) Error() string {
	if e == nil {
		return "host breaker suppressed"
	}
	return fmt.Sprintf("host %s unreachable, requests skipped until %s",
		e.host, e.until.UTC().Format(time.RFC3339Nano))
}

// IsHostBreakerSuppressed 判断错误是否来自熔断跳过，而不是真实的网络失败。
func IsHostBreakerSuppressed(err error) bool {
	var se *hostBreakerSuppressedError
	return errors.As(err, &se)
}

type hostBreakerState struct {
	failures int
	// until 非零表示该 host 已被熔断过（冷却截止时间）。它同时充当「已熔断」的
	// 标记：冷却到期后再失败一次就立即重新熔断，不必再攒满阈值。
	until time.Time
	// probing / probeAt 实现半开状态：冷却到期后只放出一次探测，避免冷却一结束
	// 就放大批请求再次集体撞超时。probeAt 是自愈用的——探测方若因上层取消而
	// 没有回报结果，超过一个冷却周期后名额自动重新放出。
	probing bool
	probeAt time.Time
}

type hostBreaker struct {
	mu     sync.Mutex
	states map[string]*hostBreakerState
}

var reqBreaker = &hostBreaker{states: make(map[string]*hostBreakerState)}

var (
	breakerReporterMu sync.Mutex
	breakerReporter   func(host string, until time.Time, failures int)
)

// SetHostBreakerReporter 注册熔断提示回调。本包不直接输出日志，展示口径由上层
// 决定（CLI 只在 -debug 下打一行警告，SDK 可以静默）。
func SetHostBreakerReporter(fn func(host string, until time.Time, failures int)) {
	breakerReporterMu.Lock()
	breakerReporter = fn
	breakerReporterMu.Unlock()
}

func reportHostBreakerTrip(host string, until time.Time, failures int) {
	breakerReporterMu.Lock()
	fn := breakerReporter
	breakerReporterMu.Unlock()
	if fn != nil {
		fn(host, until, failures)
	}
}

// ResetHostBreaker 清空熔断状态。和 ResetCheckProtocolCache 同理：包级全局状态
// 不能跨扫描复用，否则上一轮的网络抖动会把目标压制到下一轮。
func ResetHostBreaker() {
	reqBreaker.mu.Lock()
	reqBreaker.states = make(map[string]*hostBreakerState)
	reqBreaker.mu.Unlock()
}

// wait 在 host:port 处于熔断期时返回 hostBreakerSuppressedError，调用方据此直接
// 跳过本次请求。
func (b *hostBreaker) wait(key string) error {
	if b == nil || key == "" {
		return nil
	}
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()

	st, ok := b.states[key]
	if !ok || st == nil || st.until.IsZero() {
		return nil
	}
	if now.Before(st.until) {
		return &hostBreakerSuppressedError{host: key, until: st.until}
	}
	if st.probing && now.Sub(st.probeAt) < hostBreakerCooldown {
		// 半开状态：探测名额已被别人拿走，继续挡。
		return &hostBreakerSuppressedError{host: key, until: st.until}
	}
	st.probing = true
	st.probeAt = now
	return nil
}

// observe 记录一次真实请求的结果。reachable 表示拿到了 HTTP 响应（任何状态码都算）；
// canceled 表示请求是被上层主动取消的（用户中断、任务硬超时），这种情况不能当作
// 目标不可达的证据。
func (b *hostBreaker) observe(key string, reachable, canceled bool) {
	if b == nil || key == "" {
		return
	}
	b.mu.Lock()
	st, existed := b.states[key]

	if reachable {
		// 拿到任何响应都说明目标可达，摘掉条目重新计数；条目不常驻，map 不会无界增长。
		if existed {
			delete(b.states, key)
		}
		b.mu.Unlock()
		return
	}

	if !existed {
		if canceled {
			b.mu.Unlock()
			return
		}
		st = &hostBreakerState{}
		b.states[key] = st
	} else {
		// 无论这次探测结果如何，名额已经用掉，先还回去。
		st.probing = false
		if canceled {
			b.mu.Unlock()
			return
		}
	}

	st.failures++
	alreadyTripped := !st.until.IsZero()
	if !alreadyTripped && st.failures < hostBreakerThreshold {
		b.mu.Unlock()
		return
	}

	until := time.Now().Add(hostBreakerCooldown)
	failures := st.failures
	st.until = until
	st.probing = false
	st.failures = 0
	b.mu.Unlock()

	if !alreadyTripped {
		// 同一次「失联」只提示一次：重新熔断不再重复刷屏。
		reportHostBreakerTrip(key, until, failures)
	}
}

// observeRoundTrip 把一次 RoundTrip 的结果折算成熔断器可用的观测。
func observeRoundTrip(key string, resp *http.Response, req *http.Request) {
	reqBreaker.observe(key, resp != nil, requestCanceled(req))
}

// requestCanceled 判断请求上下文是否被上层主动取消（而不是等目标超时）。
// 若没有这层区分，用户中断或任务硬超时会被误当成目标不可达，进而把可达的目标熔断掉。
func requestCanceled(req *http.Request) bool {
	if req == nil {
		return false
	}
	return errors.Is(req.Context().Err(), context.Canceled)
}
