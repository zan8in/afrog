package retryhttpclient

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
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

