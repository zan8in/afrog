package passive

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type fakeDetector struct {
	name     string
	interest bool
	findings []Finding
	err      error
	panicOn  bool
}

func (f *fakeDetector) Name() string { return f.name }

func (f *fakeDetector) Interest(*CapturedTransaction) bool { return f.interest }

func (f *fakeDetector) Detect(context.Context, *CapturedTransaction, Prober) ([]Finding, error) {
	if f.panicOn {
		panic("boom")
	}
	return f.findings, f.err
}

func newTestTransaction() *CapturedTransaction {
	return &CapturedTransaction{
		ID:      "tx",
		Request: &CapturedRequest{Method: "GET", Headers: nil},
	}
}

func TestEngineFiltersLowConfidence(t *testing.T) {
	var reported int32
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{&fakeDetector{
			name:     "fake",
			interest: true,
			findings: []Finding{{
				Detector:   "fake",
				VulnType:   "sqli",
				Confidence: ConfidenceProbable,
				Target:     "http://example.com/",
				Location:   "query:id",
			}},
		}},
		Prober:    &noopProber{},
		Workers:   1,
		OnFinding: func(Finding) { atomic.AddInt32(&reported, 1) },
	})
	eng.Start(context.Background())
	defer eng.Close()

	eng.Submit(newTestTransaction())
	waitFor(t, func() bool { return eng.Stats().Filtered == 1 })

	if atomic.LoadInt32(&reported) != 0 {
		t.Fatalf("low-confidence finding must not be reported")
	}
	if got := eng.Stats().Reported; got != 0 {
		t.Fatalf("Reported = %d, want 0", got)
	}
}

func TestEngineDeduplicates(t *testing.T) {
	var reported int32
	finding := Finding{
		Detector:   "fake",
		VulnType:   "sqli",
		Severity:   "high",
		Confidence: ConfidenceCertain,
		Target:     "http://example.com/list",
		Location:   "query:id",
	}
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{&fakeDetector{name: "fake", interest: true, findings: []Finding{finding}}},
		Prober:    &noopProber{},
		Workers:   1,
		OnFinding: func(Finding) { atomic.AddInt32(&reported, 1) },
	})
	eng.Start(context.Background())
	defer eng.Close()

	eng.Submit(newTestTransaction())
	waitFor(t, func() bool { return eng.Stats().Reported == 1 })
	eng.Submit(newTestTransaction())
	waitFor(t, func() bool { return eng.Stats().Duplicated == 1 })

	if got := atomic.LoadInt32(&reported); got != 1 {
		t.Fatalf("reported = %d, want 1 (duplicate must be suppressed)", got)
	}
}

func TestEngineIsolatesDetectorPanic(t *testing.T) {
	var gotErr int32
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{&fakeDetector{name: "boom", interest: true, panicOn: true}},
		Prober:    &noopProber{},
		Workers:   1,
		OnError:   func(string, error) { atomic.AddInt32(&gotErr, 1) },
	})
	eng.Start(context.Background())
	defer eng.Close()

	eng.Submit(newTestTransaction())
	waitFor(t, func() bool { return eng.Stats().Errors == 1 })

	if atomic.LoadInt32(&gotErr) != 1 {
		t.Fatalf("panic must be surfaced as detector error")
	}
}

func TestEngineReportsDetectorError(t *testing.T) {
	var gotErr int32
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{&fakeDetector{name: "err", interest: true, err: errors.New("x")}},
		Prober:    &noopProber{},
		Workers:   1,
		OnError:   func(string, error) { atomic.AddInt32(&gotErr, 1) },
	})
	eng.Start(context.Background())
	defer eng.Close()

	eng.Submit(newTestTransaction())
	waitFor(t, func() bool { return atomic.LoadInt32(&gotErr) == 1 })
}

func TestEngineDropsWhenQueueFull(t *testing.T) {
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{&fakeDetector{name: "fake", interest: false}},
		Prober:    &noopProber{},
		Workers:   1,
		QueueSize: 1,
	})
	// 未 Start，所有提交都应被丢弃。
	accepted := 0
	for i := 0; i < 5; i++ {
		if eng.Submit(newTestTransaction()) {
			accepted++
		}
	}
	if accepted != 0 {
		t.Fatalf("accepted = %d, want 0 before Start", accepted)
	}
	if got := eng.Stats().Dropped; got != 5 {
		t.Fatalf("Dropped = %d, want 5", got)
	}
}

type noopProber struct{}

func (n *noopProber) Replay(context.Context, *CapturedTransaction) (*CapturedResponse, error) {
	return &CapturedResponse{Status: 200}, nil
}

func (n *noopProber) Mutate(context.Context, *CapturedTransaction, Mutation) (*CapturedResponse, error) {
	return &CapturedResponse{Status: 200}, nil
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met before deadline")
}
