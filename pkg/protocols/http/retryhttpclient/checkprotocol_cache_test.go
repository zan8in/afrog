package retryhttpclient

import (
	"errors"
	"testing"
	"time"
)

// probeMemos 是包级全局状态，跨扫描复用会让上一轮的结论与失败冷却污染下一轮。
// 这里只验证缓存读路径与重置语义，不发起真实探测。
func TestCheckProtocolMemoCacheAndReset(t *testing.T) {
	const key = "reset-test.local:8080"
	ResetCheckProtocolCache()
	t.Cleanup(ResetCheckProtocolCache)

	seed := func(m *probeMemo) {
		probeMu.Lock()
		probeMemos[key] = m
		probeMu.Unlock()
	}

	// 1. 命中过的 URL 直接复用，不再发起探测。
	seed(&probeMemo{okURL: HTTP_PREFIX + key, okAt: time.Now()})
	got, err := CheckProtocol(key)
	if err != nil || got != HTTP_PREFIX+key {
		t.Fatalf("CheckProtocol = (%q, %v), want the cached url", got, err)
	}

	// 2. 失败冷却期内返回 suppressed 错误，调用方据此不把主机计入错误数。
	seed(&probeMemo{failUntil: time.Now().Add(time.Minute)})
	_, err = CheckProtocol(key)
	if !IsCheckProtocolSuppressed(err) {
		t.Fatalf("CheckProtocol error = %v, want suppressed", err)
	}
	var se *checkProtocolSuppressedError
	if !errors.As(err, &se) || se.host != key {
		t.Fatalf("unexpected suppressed error payload: %#v", err)
	}

	// 3. 重置后缓存清空，新的一轮扫描不受上一轮影响。
	ResetCheckProtocolCache()
	probeMu.Lock()
	_, ok := probeMemos[key]
	probeMu.Unlock()
	if ok {
		t.Fatal("expected probeMemos to be cleared by ResetCheckProtocolCache")
	}
}
