package runner

import (
	"runtime"
	"testing"
	"time"
)

// waitGoroutinesStable 等待 goroutine 数量稳定后返回当前数量，避免把调度抖动当成泄漏。
func waitGoroutinesStable(within time.Duration) int {
	deadline := time.Now().Add(within)
	prev := runtime.NumGoroutine()
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		cur := runtime.NumGoroutine()
		if cur == prev {
			return cur
		}
		prev = cur
	}
	return prev
}

// TestRunEvalNoGoroutineLeak 覆盖 RunEval 的两种提前返回路径：
//   - 正常求值：主协程收到结果后返回；
//   - 编译失败：主协程收到错误后立即返回，此时求值 goroutine 可能还没结束。
//
// 旧实现使用无缓冲 channel 且发送端无退出判断，第二种情况下求值 goroutine
// 会永久阻塞在 chan send 上，每次调用泄漏一个 goroutine（并一直持有 variablemap），
// 大规模扫描时会持续吃内存直至 OOM。该测试确保不再发生泄漏。
func TestRunEvalNoGoroutineLeak(t *testing.T) {
	lib := NewCustomLib()

	// 预热：让 CEL 环境构建等一次性开销先发生
	if _, err := lib.RunEval("1 + 1 == 2", map[string]any{}); err != nil {
		t.Fatalf("warmup eval failed: %v", err)
	}

	base := waitGoroutinesStable(2 * time.Second)

	const rounds = 200
	for i := 0; i < rounds; i++ {
		out, err := lib.RunEval("1 + 1 == 2", map[string]any{})
		if err != nil {
			t.Fatalf("round %d: unexpected eval error: %v", i, err)
		}
		if !out.Value().(bool) {
			t.Fatalf("round %d: unexpected eval result: %v", i, out.Value())
		}

		if _, err := lib.RunEval("this is not a valid expression", map[string]any{}); err == nil {
			t.Fatalf("round %d: expected error for invalid expression", i)
		}
	}

	// 允许少量调度抖动，但不应随迭代次数增长
	limit := base + rounds/10
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := runtime.NumGoroutine()
		if got <= limit {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine leak detected: base=%d now=%d limit=%d after %d rounds", base, got, limit, rounds)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
