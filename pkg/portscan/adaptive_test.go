package portscan

import (
	"context"
	"testing"
	"time"
)

func TestAttemptTimeoutFor(t *testing.T) {
	base := 1000 * time.Millisecond

	// Adaptive disabled: always the full budget.
	s := &Scanner{options: &Options{Timeout: base, AdaptiveTimeout: false}}
	if got := s.attemptTimeoutFor(&hostScanStat{srttNs: int64(100 * time.Millisecond)}, base); got != base {
		t.Fatalf("adaptive off: got=%s want=%s", got, base)
	}

	s = &Scanner{options: &Options{Timeout: base, AdaptiveTimeout: true}}

	// No RTT measured yet: keep the full budget.
	if got := s.attemptTimeoutFor(&hostScanStat{}, base); got != base {
		t.Fatalf("unknown rtt: got=%s want=%s", got, base)
	}

	// Very fast host: 4x a 1ms RTT is below the floor, so the floor applies.
	if got := s.attemptTimeoutFor(&hostScanStat{srttNs: int64(1 * time.Millisecond)}, base); got != 200*time.Millisecond {
		t.Fatalf("fast host floor: got=%s want=%s", got, 200*time.Millisecond)
	}

	// Mid RTT: 4x the measured RTT.
	if got := s.attemptTimeoutFor(&hostScanStat{srttNs: int64(100 * time.Millisecond)}, base); got != 400*time.Millisecond {
		t.Fatalf("mid rtt: got=%s want=%s", got, 400*time.Millisecond)
	}

	// Slow host: never exceed the user budget.
	if got := s.attemptTimeoutFor(&hostScanStat{srttNs: int64(1 * time.Second)}, base); got != base {
		t.Fatalf("slow host cap: got=%s want=%s", got, base)
	}
}

func TestObserveRTT(t *testing.T) {
	s := &Scanner{options: &Options{AdaptiveTimeout: true}}
	st := &hostScanStat{}

	// First sample seeds the estimate directly.
	s.observeRTT(st, 100*time.Millisecond)
	if st.srttNs != int64(100*time.Millisecond) {
		t.Fatalf("seed: got=%d want=%d", st.srttNs, int64(100*time.Millisecond))
	}

	// Subsequent samples are folded in (EWMA, alpha = 1/8).
	s.observeRTT(st, 200*time.Millisecond)
	want := int64(100*time.Millisecond) - int64(100*time.Millisecond)/8 + int64(200*time.Millisecond)/8
	if st.srttNs != want {
		t.Fatalf("ewma: got=%d want=%d", st.srttNs, want)
	}

	// Disabled adaptive timeout must not record anything.
	off := &Scanner{options: &Options{AdaptiveTimeout: false}}
	st2 := &hostScanStat{}
	off.observeRTT(st2, 50*time.Millisecond)
	if st2.srttNs != 0 {
		t.Fatalf("adaptive off should not record: got=%d", st2.srttNs)
	}
}

func TestAcquireHostSlot(t *testing.T) {
	s := &Scanner{options: &Options{MaxHostConcurrency: 2}}
	ctx := context.Background()

	// Unbounded when the limit is disabled.
	unlimited := &Scanner{options: &Options{MaxHostConcurrency: 0}}
	rel := unlimited.acquireHostSlot(ctx, "h")
	if rel == nil {
		t.Fatal("unlimited acquire returned nil")
	}
	rel()

	r1 := s.acquireHostSlot(ctx, "h")
	r2 := s.acquireHostSlot(ctx, "h")
	if r1 == nil || r2 == nil {
		t.Fatal("expected to acquire the two available slots")
	}

	// Third probe must block until a slot frees; cancel to avoid hanging.
	blockedCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if rel := s.acquireHostSlot(blockedCtx, "h"); rel != nil {
		t.Fatal("expected the third acquire to block and return nil")
	}

	// A different host has its own independent budget.
	r3 := s.acquireHostSlot(ctx, "other")
	if r3 == nil {
		t.Fatal("other host should have its own slots")
	}
	r3()

	r1()
	r2()
	rel = s.acquireHostSlot(ctx, "h")
	if rel == nil {
		t.Fatal("slot should be free after release")
	}
	rel()
}
