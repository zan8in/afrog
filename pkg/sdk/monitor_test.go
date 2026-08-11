package sdk

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// --- execution monitor ------------------------------------------------------

// The monitor's reports must reach the registered handler.
func TestScanner_ExecutionMonitorReportsThroughHandler(t *testing.T) {
	var mu sync.Mutex
	var lines []string

	scanner, _ := newTestScanner(t,
		WithExecutionMonitor(ExecutionMonitorOptions{LogLimit: 10}),
		WithMonitorHandler(func(line string) {
			mu.Lock()
			lines = append(lines, line)
			mu.Unlock()
		}),
	)

	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	mu.Lock()
	got := len(lines)
	mu.Unlock()
	if got == 0 {
		t.Fatal("execution monitor produced no reports")
	}
}

// The engine prints monitor output itself when no hook is installed. The SDK
// must keep the console clean whether or not a handler is registered.
func TestScanner_ExecutionMonitorStaysSilent(t *testing.T) {
	tests := []struct {
		name  string
		extra []Option
	}{
		{name: "without handler", extra: nil},
		{name: "with handler", extra: []Option{WithMonitorHandler(func(string) {})}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := append([]Option{
				WithExecutionMonitor(ExecutionMonitorOptions{LogLimit: 10}),
			}, tt.extra...)
			scanner, _ := newTestScanner(t, options...)

			stdout, r, w := captureStdout(t)
			execErr := scanner.Execute(context.Background())
			output := restoreStdout(t, stdout, r, w)

			if execErr != nil {
				t.Fatalf("Execute: %v", execErr)
			}
			if output != "" {
				t.Fatalf("scanner wrote to stdout:\n%s", output)
			}
		})
	}
}

func TestWithExecutionMonitor_KeepsDefaultsAndValidates(t *testing.T) {
	o := NewOptions()
	if err := WithExecutionMonitor(ExecutionMonitorOptions{LogLimit: 5})(o); err != nil {
		t.Fatalf("WithExecutionMonitor: %v", err)
	}
	if !o.EnableMonitor {
		t.Error("WithExecutionMonitor did not enable the monitor")
	}
	if o.Monitor.SlowThresholdSec != DefaultMonitorSlowThresholdSec {
		t.Errorf("SlowThresholdSec = %d, want %d", o.Monitor.SlowThresholdSec, DefaultMonitorSlowThresholdSec)
	}
	if o.Monitor.SummaryTop != DefaultMonitorSummaryTop {
		t.Errorf("SummaryTop = %d, want %d", o.Monitor.SummaryTop, DefaultMonitorSummaryTop)
	}
	if o.Monitor.SummaryBy != MonitorSummaryByMax {
		t.Errorf("SummaryBy = %q, want %q", o.Monitor.SummaryBy, MonitorSummaryByMax)
	}

	if err := WithExecutionMonitor(ExecutionMonitorOptions{SummaryBy: "bogus"})(NewOptions()); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("unknown summary key = %v, want ErrInvalidOptions", err)
	}
	if err := WithExecutionMonitor(ExecutionMonitorOptions{LogLimit: -1})(NewOptions()); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("negative LogLimit = %v, want ErrInvalidOptions", err)
	}
}

// --- per-task timeout -------------------------------------------------------

func TestWithTaskTimeout_KeepsDefaultCapsAndValidates(t *testing.T) {
	o := NewOptions()
	if err := WithTaskTimeout(TaskTimeoutOptions{HardSec: 30, Smart: true})(o); err != nil {
		t.Fatalf("WithTaskTimeout: %v", err)
	}
	caps := map[string][2]int{
		"VisibleCapSec": {o.TaskTimeout.VisibleCapSec, DefaultTaskTimeoutVisibleCapSec},
		"NetCapSec":     {o.TaskTimeout.NetCapSec, DefaultTaskTimeoutNetCapSec},
		"GoCapSec":      {o.TaskTimeout.GoCapSec, DefaultTaskTimeoutGoCapSec},
	}
	for name, v := range caps {
		if v[0] != v[1] {
			t.Errorf("%s = %d, want the default %d", name, v[0], v[1])
		}
	}

	if err := WithTaskTimeout(TaskTimeoutOptions{HardSec: -1})(NewOptions()); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("negative HardSec = %v, want ErrInvalidOptions", err)
	}
	if err := WithTaskTimeout(TaskTimeoutOptions{NetCapSec: -5})(NewOptions()); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("negative NetCapSec = %v, want ErrInvalidOptions", err)
	}
}

// A hard task timeout must actually cut a PoC short. Without it the scan would
// block for the full server delay.
func TestScanner_TaskHardTimeoutCutsSlowPoc(t *testing.T) {
	const serverDelay = 10 * time.Second

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	// Only the PoC's own path is slow. The reachability probe afrog runs
	// first has its own 5s ceiling, so a uniformly slow server would be cut
	// there and the PoC would never execute.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/probe" {
			select {
			case <-time.After(serverDelay):
			case <-r.Context().Done():
				return
			case <-release:
			}
		}
		_, _ = w.Write([]byte(magicToken))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	writePoc(t, dir, "slow.yaml", "sdk-test-slow")

	scanner, err := New(context.Background(),
		WithTargets(srv.URL),
		WithPocPaths(dir),
		WithPocPathsOnly(),
		WithFingerprintDisabled(),
		// Well above the server delay, so only the task timeout can end this.
		WithTimeout(60),
		WithTaskTimeout(TaskTimeoutOptions{HardSec: 1}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = scanner.Close() })

	start := time.Now()
	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed >= serverDelay-2*time.Second {
		t.Fatalf("scan took %v, so the 1s task timeout did not cut the %v request", elapsed, serverDelay)
	}
}

// The PoC path list must reach the engine before PoC loading, otherwise smart
// estimation silently produces no per-task ceiling.
func TestScanner_SmartTaskTimeoutReachesEngine(t *testing.T) {
	srv := newTestServer(t)
	dir := t.TempDir()
	writePoc(t, dir, "smart.yaml", "sdk-test-smart")

	scanner, err := New(context.Background(),
		WithTargets(srv.URL),
		WithPocPaths(dir),
		WithPocPathsOnly(),
		WithFingerprintDisabled(),
		WithTaskTimeout(TaskTimeoutOptions{Smart: true, VisibleCapSec: 120}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = scanner.Close() })

	if !scanner.internal.TaskSmartTimeout {
		t.Error("TaskSmartTimeout did not reach the engine options")
	}
	if scanner.internal.TaskTimeoutVisibleCapSec != 120 {
		t.Errorf("VisibleCapSec = %d, want 120", scanner.internal.TaskTimeoutVisibleCapSec)
	}

	pocs := scanner.Pocs()
	if len(pocs) == 0 {
		t.Fatal("no pocs loaded")
	}
	if pocs[0].EstimatedTaskTimeoutSec <= 0 {
		t.Errorf("EstimatedTaskTimeoutSec = %d, want > 0 with smart timeout on",
			pocs[0].EstimatedTaskTimeoutSec)
	}
	if pocs[0].EstimatedTaskTimeoutSec > 120 {
		t.Errorf("EstimatedTaskTimeoutSec = %d, want <= the 120s cap", pocs[0].EstimatedTaskTimeoutSec)
	}
	_ = filepath.Base(dir)
}
