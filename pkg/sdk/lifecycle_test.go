package sdk

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

// Close must be safe at every lifecycle point, including before a scan was
// ever started and while one is still running.
func TestScanner_CloseAtEveryLifecyclePoint(t *testing.T) {
	tests := []struct {
		name   string
		before func(s *Scanner)
	}{
		{name: "before start", before: func(*Scanner) {}},
		{name: "after stop without start", before: func(s *Scanner) { s.Stop() }},
		{name: "after execute", before: func(s *Scanner) { _ = s.Execute(context.Background()) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, _ := newTestScanner(t)
			tt.before(scanner)

			done := make(chan error, 1)
			go func() { done <- scanner.Close() }()

			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Close: %v", err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("Close blocked")
			}
		})
	}
}

// Close called while a scan is running must stop it and return promptly.
func TestScanner_CloseWhileRunning(t *testing.T) {
	scanner, _ := newTestScanner(t)

	if err := scanner.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- scanner.Close() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Close blocked while a scan was running")
	}
}

// Concurrent Stop and Close calls must not panic or deadlock.
func TestScanner_ConcurrentStopAndClose(t *testing.T) {
	scanner, _ := newTestScanner(t)

	if err := scanner.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); scanner.Stop() }()
		go func() { defer wg.Done(); _ = scanner.Close() }()
	}

	done := make(chan struct{})
	go func() { defer close(done); wg.Wait() }()

	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("concurrent Stop/Close deadlocked")
	}
}

// A scan that finishes cleanly must report 100% progress even though the
// pre-execution task estimate rarely matches the exact number of tasks run.
func TestScanner_ProgressReaches100OnCleanFinish(t *testing.T) {
	scanner, _ := newTestScanner(t)

	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := scanner.Progress(); got != 100 {
		t.Fatalf("Progress() = %.2f after a clean finish, want 100", got)
	}
}

// A New that fails after the runner was already built must not leak the
// runner's background goroutines, and must put the curated environment
// variables back the way it found them. The caller gets no Scanner on that
// path, so it has no way to clean up itself.
func TestNew_ReleasesResourcesWhenConstructionFails(t *testing.T) {
	t.Setenv(envCuratedDisabled, "sentinel")

	srv := newTestServer(t)
	dir := t.TempDir()
	writePoc(t, dir, "info.yaml", "abandon-check")

	// Warm up the lazily-initialised shared state so it is not counted below.
	failedNew := func() error {
		_, err := New(context.Background(),
			WithTargets(srv.URL),
			WithPocPaths(dir),
			WithPocPathsOnly(),
			WithFingerprintDisabled(),
			// The PoC is "info", so nothing survives the filter and
			// construction fails only after the runner exists.
			WithSeverity("critical"),
		)
		return err
	}
	if err := failedNew(); !errors.Is(err, ErrNoPocs) {
		t.Fatalf("New error = %v, want ErrNoPocs", err)
	}

	before := waitGoroutines(t, 0)
	for i := 0; i < 3; i++ {
		if err := failedNew(); !errors.Is(err, ErrNoPocs) {
			t.Fatalf("New error = %v, want ErrNoPocs", err)
		}
	}
	if after := waitGoroutines(t, before); after > before+5 {
		t.Fatalf("goroutine count grew from %d to %d across 3 failed constructions", before, after)
	}

	if got := os.Getenv(envCuratedDisabled); got != "sentinel" {
		t.Fatalf("%s = %q after a failed New, want the original %q", envCuratedDisabled, got, "sentinel")
	}
}

// Double Start must be rejected rather than launching two scans.
func TestScanner_DoubleStart(t *testing.T) {
	scanner, _ := newTestScanner(t)

	if err := scanner.Start(context.Background()); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	err := scanner.Start(context.Background())
	if err == nil {
		t.Fatal("second Start should have failed")
	}
	<-scanner.Done()
}
