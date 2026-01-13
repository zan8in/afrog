package retryhttpclient

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckProtocolSingleflight(t *testing.T) {
	if err := Init(&Options{Timeout: 5, Retries: 0, MaxRespBodySize: 2}); err != nil {
		t.Fatalf("init retryhttpclient: %v", err)
	}

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer srv.Close()

	hostport := strings.TrimPrefix(srv.URL, "http://")

	var wg sync.WaitGroup
	n := 50
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, _ = CheckProtocol(hostport)
		}()
	}
	wg.Wait()

	if got := hits.Load(); got != 1 {
		t.Fatalf("expected 1 probe request, got %d", got)
	}
}

func TestCheckProtocolCachesSuccess(t *testing.T) {
	if err := Init(&Options{Timeout: 5, Retries: 0, MaxRespBodySize: 2}); err != nil {
		t.Fatalf("init retryhttpclient: %v", err)
	}

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer srv.Close()

	hostport := strings.TrimPrefix(srv.URL, "http://")

	u1, err := CheckProtocol(hostport)
	if err != nil || !strings.HasPrefix(u1, "http://") {
		t.Fatalf("expected http url, got url=%q err=%v", u1, err)
	}
	u2, err := CheckProtocol(hostport)
	if err != nil || u2 != u1 {
		t.Fatalf("expected cached url %q, got url=%q err=%v", u1, u2, err)
	}

	if got := hits.Load(); got != 1 {
		t.Fatalf("expected 1 probe request, got %d", got)
	}
}

func TestCheckProtocolSuppressedAfterFailure(t *testing.T) {
	if err := Init(&Options{Timeout: 5, Retries: 0, MaxRespBodySize: 2}); err != nil {
		t.Fatalf("init retryhttpclient: %v", err)
	}

	oldBase := checkProtocolFailCooldownBase
	oldMax := checkProtocolFailCooldownMax
	oldMaxAttempts := checkProtocolMaxAttemptsPerWindow
	oldWindow := checkProtocolAttemptWindow
	checkProtocolFailCooldownBase = 200 * time.Millisecond
	checkProtocolFailCooldownMax = 200 * time.Millisecond
	checkProtocolMaxAttemptsPerWindow = 10
	checkProtocolAttemptWindow = time.Second
	defer func() {
		checkProtocolFailCooldownBase = oldBase
		checkProtocolFailCooldownMax = oldMax
		checkProtocolMaxAttemptsPerWindow = oldMaxAttempts
		checkProtocolAttemptWindow = oldWindow
	}()

	target := "127.0.0.1:0"
	_, _ = CheckProtocol(target)

	_, err := CheckProtocol(target)
	if err == nil || !IsCheckProtocolSuppressed(err) {
		t.Fatalf("expected suppressed error, got %v", err)
	}
}
