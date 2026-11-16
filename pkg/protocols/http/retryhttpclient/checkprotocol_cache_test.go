package retryhttpclient

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestCheckProtocolDirectCorrectsHTTPSOnly 钉住协议试探的「内容纠正」：
// 明文 HTTP 打到 TLS 端口时服务端会回「The plain HTTP request was sent to HTTPS port」，
// 无论候选带不带显式 http:// 前缀，都应按响应内容纠正到 https。
func TestCheckProtocolDirectCorrectsHTTPSOnly(t *testing.T) {
	if err := Init(&Options{Timeout: 5, Retries: 0, MaxRespBodySize: 2}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("<html><head><title>400 The plain HTTP request was sent to HTTPS port</title></head></html>"))
	}))
	defer srv.Close()

	hostPort := strings.TrimPrefix(srv.URL, "http://")
	want := "https://" + hostPort

	// 显式 http:// 前缀：以前会原样返回 http，站点只认 https 则全部 PoC 空跑。
	if got, err := checkProtocolDirect("http://" + hostPort); err != nil || got != want {
		t.Fatalf("explicit http: got (%q, %v), want %q", got, err, want)
	}

	// 裸 host:port（端口非 80/443）走 default 分支，同样纠正。
	if got, err := checkProtocolDirect(hostPort); err != nil || got != want {
		t.Fatalf("bare host:port: got (%q, %v), want %q", got, err, want)
	}
}
