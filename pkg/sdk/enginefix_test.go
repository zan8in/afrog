package sdk

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// time.Second/rate truncates to zero once the rate limit reaches one billion,
// and time.NewTicker panics on a non-positive interval. The panic surfaced as
// a crashed scan goroutine rather than an error.
func TestScanner_ExtremeRateLimitDoesNotPanic(t *testing.T) {
	for _, rate := range []int{1_000_000_000, 2_000_000_000} {
		t.Run(strconv.Itoa(rate), func(t *testing.T) {
			scanner, _ := newTestScanner(t, WithRateLimit(rate))

			if err := scanner.Execute(context.Background()); err != nil {
				t.Fatalf("Execute with rate limit %d: %v", rate, err)
			}
			// A panicking scan goroutine is recovered into the run error, so a
			// clean Execute plus a real finding proves the scan actually ran.
			if got := scanner.ResultCount(); got != 1 {
				t.Fatalf("found %d results at rate limit %d, want 1", got, rate)
			}
		})
	}
}

// PoC execution failures used to be swallowed: a request error or a broken
// expression produced no result and no signal, so callers could not tell a
// clean "not vulnerable" from a PoC that never ran.
func TestScanner_FailureHandlerObservesRequestErrors(t *testing.T) {
	// Bind then release a port so connections to it are refused outright.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	dir := t.TempDir()
	writePoc(t, dir, "fail.yaml", "sdk-test-failure")

	var mu sync.Mutex
	var failures []Failure

	scanner, err := New(context.Background(),
		WithTargets("http://"+addr),
		WithPocPaths(dir),
		WithPocPathsOnly(),
		WithFingerprintDisabled(),
		WithTimeout(3),
		WithRetries(0),
		WithFailureHandler(func(f Failure) {
			mu.Lock()
			failures = append(failures, f)
			mu.Unlock()
		}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = scanner.Close() })

	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(failures) == 0 {
		t.Fatal("no failure reported for a target that refuses every connection")
	}
	f := failures[0]
	if f.Err == nil {
		t.Error("Failure.Err is nil")
	}
	if f.PocID != "sdk-test-failure" {
		t.Errorf("Failure.PocID = %q, want sdk-test-failure", f.PocID)
	}
	if strings.TrimSpace(f.Error()) == "" {
		t.Error("Failure.Error() is empty")
	}
}

// A response larger than MaxRespBodySize is cut short, and callers have to be
// able to tell that the body they received is not the whole server response.
func TestScanner_BodyTruncatedIsReportedOnLargeResponse(t *testing.T) {
	const maxMB = 1
	// Comfortably past the 1 MB ceiling so the read stops mid-body.
	payload := strings.Repeat("A", 3*1024*1024)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// The token has to land before the cut so the PoC still matches.
		_, _ = w.Write([]byte(magicToken))
		_, _ = w.Write([]byte(payload))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	writePoc(t, dir, "big.yaml", "sdk-test-truncate")

	scanner, err := New(context.Background(),
		WithTargets(srv.URL),
		WithPocPaths(dir),
		WithPocPathsOnly(),
		WithFingerprintDisabled(),
		WithTimeout(20),
		WithMaxRespBodySize(maxMB),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = scanner.Close() })

	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	results := scanner.Results()
	if len(results) == 0 {
		t.Fatal("no result to inspect")
	}
	if len(results[0].Exchanges) == 0 {
		t.Fatal("result carries no exchange")
	}

	ex := results[0].Exchanges[0]
	if !ex.BodyTruncated {
		t.Errorf("BodyTruncated = false for a %d byte body read with a %d MB limit",
			len(payload), maxMB)
	}
	if len(ex.ResponseBody) >= len(payload) {
		t.Errorf("response body is %d bytes, so it was not actually truncated", len(ex.ResponseBody))
	}
}

// The counterpart: a small response must not be flagged, otherwise the flag
// would be useless noise.
func TestScanner_BodyTruncatedIsFalseForSmallResponse(t *testing.T) {
	scanner, _ := newTestScanner(t, WithMaxRespBodySize(2))

	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	results := scanner.Results()
	if len(results) == 0 || len(results[0].Exchanges) == 0 {
		t.Fatal("no exchange to inspect")
	}
	if results[0].Exchanges[0].BodyTruncated {
		t.Error("BodyTruncated = true for a response well under the limit")
	}
}
