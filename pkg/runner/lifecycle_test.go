package runner

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/config"
)

// settleGoroutines returns the goroutine count once it stops shrinking, so a
// just-signalled goroutine is not counted as still running.
func settleGoroutines(t *testing.T, target int) int {
	t.Helper()
	n := runtime.NumGoroutine()
	for i := 0; i < 40; i++ {
		runtime.GC()
		time.Sleep(25 * time.Millisecond)
		n = runtime.NumGoroutine()
		if target > 0 && n <= target {
			return n
		}
	}
	return n
}

// The poll loop used to outlive every completed scan, because the runner
// context is only cancelled by an explicit Stop. Stop must terminate it and
// wait for the goroutine to be gone, not merely signal it.
func TestOOBManager_StopTerminatesPollLoop(t *testing.T) {
	before := settleGoroutines(t, 0)

	for i := 0; i < 5; i++ {
		m := NewOOBManager(context.Background(), nil, 10*time.Millisecond, time.Minute)
		m.Stop()

		// Stop waits for the loop to exit, so the goroutine must already be
		// gone rather than merely scheduled to stop.
		select {
		case <-m.done:
		default:
			t.Fatal("Stop returned before the poll loop exited")
		}
	}

	if after := settleGoroutines(t, before); after > before+2 {
		t.Fatalf("goroutine count grew from %d to %d across 5 manager lifecycles", before, after)
	}
}

// Stop must be safe to call repeatedly and from several goroutines at once.
func TestOOBManager_StopIsIdempotentAndConcurrencySafe(t *testing.T) {
	m := NewOOBManager(context.Background(), nil, 10*time.Millisecond, time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); m.Stop() }()
	}

	done := make(chan struct{})
	go func() { defer close(done); wg.Wait() }()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent Stop deadlocked")
	}
}

// A nil manager must be inert so callers need no nil checks.
func TestOOBManager_StopOnNilIsSafe(t *testing.T) {
	var m *OOBManager
	m.Stop()
}

// Installing a manager has to stop the previous one, otherwise a second scan
// in the same process leaks the first scan's poller.
func TestEngine_SetOOBManagerStopsThePrevious(t *testing.T) {
	e := &Engine{}

	first := NewOOBManager(context.Background(), nil, 10*time.Millisecond, time.Minute)
	e.setOOBManager(first)
	if e.OOBMgr() != first {
		t.Fatal("setOOBManager did not install the manager")
	}

	second := NewOOBManager(context.Background(), nil, 10*time.Millisecond, time.Minute)
	e.setOOBManager(second)

	select {
	case <-first.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the replaced manager's poll loop is still running")
	}
	if e.OOBMgr() != second {
		t.Fatal("setOOBManager did not install the replacement")
	}

	e.stopOOBManager()
	select {
	case <-second.done:
	case <-time.After(5 * time.Second):
		t.Fatal("stopOOBManager left the poll loop running")
	}
	if e.OOBMgr() != nil {
		t.Fatal("stopOOBManager did not clear the reference")
	}
}

// stopOOBManager runs from Stop, from Release and from Execute's defer, so it
// must tolerate being called with nothing installed and more than once.
func TestEngine_StopOOBManagerIsSafeWhenIdle(t *testing.T) {
	var nilEngine *Engine
	nilEngine.stopOOBManager()
	if nilEngine.OOBMgr() != nil {
		t.Fatal("a nil engine should report no manager")
	}

	e := &Engine{}
	e.stopOOBManager()
	e.stopOOBManager()
}

// The ticker and the OOB manager are written while scheduling and read from
// Stop on another goroutine. Before they became atomic this raced; the test is
// meaningful under -race.
func TestEngine_ConcurrentTickerAndStopIsRaceFree(t *testing.T) {
	e := NewEngine(&config.Options{})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			e.setTicker(time.NewTicker(time.Millisecond))
		}()
		go func() {
			defer wg.Done()
			e.waitTick()
		}()
		go func() {
			defer wg.Done()
			e.stopTicker()
		}()
	}

	// Stop closes e.quit, which releases any waitTick blocked on the ticker.
	wg.Add(1)
	go func() { defer wg.Done(); e.Stop() }()

	done := make(chan struct{})
	go func() { defer close(done); wg.Wait() }()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent ticker access deadlocked")
	}

	// Stop must leave nothing installed for a later Release to trip over.
	e.stopTicker()
}

// Stop must also release the OOB poller: it is the path an interrupted scan
// takes, and the poller would otherwise survive the scan.
func TestEngine_StopReleasesTheOOBPoller(t *testing.T) {
	e := NewEngine(&config.Options{})
	m := NewOOBManager(context.Background(), nil, 10*time.Millisecond, time.Minute)
	e.setOOBManager(m)

	e.Stop()

	select {
	case <-m.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop left the OOB poll loop running")
	}
}
