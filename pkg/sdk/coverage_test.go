package sdk

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Every option has to actually change the configuration. A typo in one of the
// one-line option functions would otherwise be invisible: the option compiles,
// the scan runs, and the setting is silently ignored.
func TestOptions_EveryOptionApplies(t *testing.T) {
	tests := []struct {
		name   string
		option Option
		check  func(*Options) bool
	}{
		{"WithTargets", WithTargets("a", "b"), func(o *Options) bool { return len(o.Targets) == 2 }},
		{"WithTargetsFile", WithTargetsFile("t.txt"), func(o *Options) bool { return o.TargetsFile == "t.txt" }},
		{"WithPocPaths", WithPocPaths("p1", "p2"), func(o *Options) bool { return len(o.PocPaths) == 2 }},
		{"WithPocPathsOnly", WithPocPathsOnly(), func(o *Options) bool { return o.PocPathsOnly }},
		{"WithSearch", WithSearch("tomcat"), func(o *Options) bool { return o.Search == "tomcat" }},
		{"WithSeverity", WithSeverity("high"), func(o *Options) bool { return o.Severity == "high" }},
		{"WithExcludePocs", WithExcludePocs("x", "y"), func(o *Options) bool { return len(o.ExcludePocs) == 2 }},
		{"WithExcludePocsFile", WithExcludePocsFile("e.txt"), func(o *Options) bool { return o.ExcludePocsFile == "e.txt" }},

		{"WithConcurrency", WithConcurrency(7), func(o *Options) bool { return o.Concurrency == 7 }},
		{"WithRateLimit", WithRateLimit(11), func(o *Options) bool { return o.RateLimit == 11 }},
		{"WithTimeout", WithTimeout(13), func(o *Options) bool { return o.Timeout == 13 }},
		{"WithRetries", WithRetries(4), func(o *Options) bool { return o.Retries == 4 }},
		{"WithMaxHostError", WithMaxHostError(9), func(o *Options) bool { return o.MaxHostError == 9 }},
		{"WithMaxRespBodySize", WithMaxRespBodySize(5), func(o *Options) bool { return o.MaxRespBodySize == 5 }},
		{"WithRequestLimitPerTarget", WithRequestLimitPerTarget(6), func(o *Options) bool { return o.ReqLimitPerTarget == 6 }},
		{"WithPolite", WithPolite(), func(o *Options) bool { return o.Polite }},
		{"WithBalanced", WithBalanced(), func(o *Options) bool { return o.Balanced }},
		{"WithAggressive", WithAggressive(), func(o *Options) bool { return o.Aggressive }},
		{"WithAutoRequestLimit", WithAutoRequestLimit(), func(o *Options) bool { return o.AutoReqLimit }},
		{"WithSmartConcurrency", WithSmartConcurrency(), func(o *Options) bool { return o.Smart }},
		{"WithStopOnFirstMatch", WithStopOnFirstMatch(), func(o *Options) bool { return o.StopOnFirstMatch }},

		{"WithFingerprintDisabled", WithFingerprintDisabled(), func(o *Options) bool { return o.DisableFingerprint }},
		{"WithFingerprintFilterMode", WithFingerprintFilterMode(FingerprintOpportunistic),
			func(o *Options) bool { return o.FingerprintFilterMode == FingerprintOpportunistic }},
		{"WithWebProbe", WithWebProbe(), func(o *Options) bool { return o.EnableWebProbe }},

		{"WithProxy", WithProxy("http://127.0.0.1:8080"), func(o *Options) bool { return o.Proxy != "" }},
		{"WithHeaders", WithHeaders("X-A: 1"), func(o *Options) bool { return len(o.Headers) == 1 }},

		{"WithPortScan", WithPortScan(PortScanOptions{Ports: "80"}),
			func(o *Options) bool { return o.EnablePortSan && o.PortScan.Ports == "80" }},
		{"WithOOB", WithOOB(OOBOptions{Adapter: "ceyeio"}),
			func(o *Options) bool { return o.OOB.Enabled && o.OOB.Adapter == "ceyeio" }},
		{"WithCurated", WithCurated(CuratedOptions{Enabled: "auto"}),
			func(o *Options) bool { return o.Curated.Enabled == "auto" }},

		{"WithDingtalk", WithDingtalk(), func(o *Options) bool { return o.Dingtalk }},
		{"WithWecom", WithWecom(), func(o *Options) bool { return o.Wecom }},

		{"WithRequestResponse", WithRequestResponse(false), func(o *Options) bool { return !o.IncludeRequestResponse }},
		{"WithMaxStoredResults", WithMaxStoredResults(3), func(o *Options) bool { return o.MaxStoredResults == 3 }},
		{"WithStreamBuffer", WithStreamBuffer(8), func(o *Options) bool { return o.StreamBuffer == 8 }},
		{"WithRedactedHeaders", WithRedactedHeaders(), func(o *Options) bool { return len(o.RedactedHeaders) > 0 }},
		{"WithVerbose", WithVerbose(), func(o *Options) bool { return o.Verbose }},

		{"WithTaskTimeout", WithTaskTimeout(TaskTimeoutOptions{HardSec: 12}),
			func(o *Options) bool { return o.TaskTimeout.HardSec == 12 }},
		{"WithExecutionMonitor", WithExecutionMonitor(ExecutionMonitorOptions{LogLimit: 2}),
			func(o *Options) bool { return o.EnableMonitor && o.Monitor.LogLimit == 2 }},
		{"WithCheckpoint", WithCheckpoint(CheckpointOptions{Path: "c.afg"}),
			func(o *Options) bool { return o.Checkpoint.Path == "c.afg" }},
		{"WithCyberspace", WithCyberspace(CyberspaceOptions{Engine: CyberspaceZoomEye, Query: "q"}),
			func(o *Options) bool { return o.Cyberspace.Engine == CyberspaceZoomEye }},
		{"WithTargetPreProbe", WithTargetPreProbe(), func(o *Options) bool { return o.TargetPreProbe }},

		{"WithResultHandler", WithResultHandler(func(Result) {}),
			func(o *Options) bool { return len(o.handlers.result) == 1 }},
		{"WithRawResultHandler", WithRawResultHandler(nil),
			func(o *Options) bool { return len(o.handlers.rawResult) == 0 }},
		{"WithFailureHandler", WithFailureHandler(func(Failure) {}),
			func(o *Options) bool { return len(o.handlers.failure) == 1 }},
		{"WithPortHandler", WithPortHandler(func(PortEvent) {}),
			func(o *Options) bool { return len(o.handlers.port) == 1 }},
		{"WithHostHandler", WithHostHandler(func(HostEvent) {}),
			func(o *Options) bool { return len(o.handlers.host) == 1 }},
		{"WithWebProbeHandler", WithWebProbeHandler(func(WebProbeEvent) {}),
			func(o *Options) bool { return len(o.handlers.webProbe) == 1 }},
		{"WithProgressHandler", WithProgressHandler(func(PhaseProgress) {}),
			func(o *Options) bool { return len(o.handlers.progress) == 1 }},
		{"WithScanInfoHandler", WithScanInfoHandler(func(ScanInfo) {}),
			func(o *Options) bool { return len(o.handlers.scanInfo) == 1 }},
		{"WithMonitorHandler", WithMonitorHandler(func(string) {}),
			func(o *Options) bool { return len(o.handlers.monitor) == 1 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := NewOptions()
			if err := tt.option(o); err != nil {
				t.Fatalf("%s: %v", tt.name, err)
			}
			if !tt.check(o) {
				t.Errorf("%s did not take effect", tt.name)
			}
		})
	}
}

// The options that map straight onto engine fields must survive the
// translation, not just land on the SDK Options struct.
func TestScanner_OptionsReachTheEngine(t *testing.T) {
	srv := newTestServer(t)
	dir := t.TempDir()
	writePoc(t, dir, "reach.yaml", "sdk-test-reach")

	scanner, err := New(context.Background(),
		WithTargets(srv.URL),
		WithPocPaths(dir),
		WithPocPathsOnly(),
		WithFingerprintDisabled(),
		WithConcurrency(7),
		WithRateLimit(11),
		WithTimeout(13),
		WithRetries(4),
		WithMaxHostError(9),
		WithMaxRespBodySize(5),
		WithRequestLimitPerTarget(6),
		WithSmartConcurrency(),
		WithWebProbe(),
		WithSearch("reach"),
		WithHeaders("X-Test: 1"),
		WithStopOnFirstMatch(),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = scanner.Close() })

	in := scanner.internal
	checks := []struct {
		name string
		got  any
		want any
	}{
		{"Concurrency", in.Concurrency, 7},
		{"RateLimit", in.RateLimit, 11},
		{"Timeout", in.Timeout, 13},
		{"Retries", in.Retries, 4},
		{"MaxHostError", in.MaxHostError, 9},
		{"MaxRespBodySize", in.MaxRespBodySize, 5},
		{"ReqLimitPerTarget", in.ReqLimitPerTarget, 6},
		{"Smart", in.Smart, true},
		{"EnableWebProbe", in.EnableWebProbe, true},
		{"Search", in.Search, "reach"},
		{"DisableFingerprint", in.DisableFingerprint, true},
		{"StopOnFirstMatch", in.VulnerabilityScannerBreakpoint, true},
		{"SDKMode", in.SDKMode, true},
		{"Silent", in.Silent, true},
		{"DisableUpdateCheck", in.DisableUpdateCheck, true},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("engine %s = %v, want %v", c.name, c.got, c.want)
		}
	}
	if len(in.Header) != 1 {
		t.Errorf("engine Header has %d entries, want 1", len(in.Header))
	}
	// A library must never be configured to write report files.
	if in.Json != "" || in.JsonAll != "" || in.Output != "" {
		t.Error("engine is configured to write report files")
	}
}

// The accessors and the less-used streams must behave sensibly before, during
// and after a scan.
func TestScanner_AccessorsAndRemainingStreams(t *testing.T) {
	scanner, _ := newTestScanner(t)

	if scanner.IsRunning() {
		t.Error("IsRunning = true before Start")
	}
	if scanner.HasResults() {
		t.Error("HasResults = true before the scan")
	}
	if scanner.CuratedError() != nil {
		t.Errorf("CuratedError = %v with curated disabled", scanner.CuratedError())
	}
	if enabled, status := scanner.OOBStatus(); enabled || status != "disabled" {
		t.Errorf("OOBStatus = (%v, %q), want (false, \"disabled\")", enabled, status)
	}

	scanner.Pause()
	if !scanner.IsPaused() {
		t.Error("IsPaused = false after Pause")
	}
	scanner.Resume()
	if scanner.IsPaused() {
		t.Error("IsPaused = true after Resume")
	}

	// Subscribing before the scan means each stream must close when it ends,
	// otherwise these range loops would never finish.
	ports := scanner.PortStream()
	hosts := scanner.HostStream()
	probes := scanner.WebProbeStream()
	progress := scanner.ProgressStream()
	infos := scanner.ScanInfoStream()

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range ports {
		}
		for range hosts {
		}
		for range probes {
		}
		for range progress {
		}
		for range infos {
		}
	}()

	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	select {
	case <-drained:
	case <-time.After(30 * time.Second):
		t.Fatal("a stream was left open after the scan finished")
	}

	if !scanner.HasResults() {
		t.Error("HasResults = false after a finding")
	}
	if scanner.IsRunning() {
		t.Error("IsRunning = true after the scan finished")
	}
	if scanner.OpenPorts() == nil {
		t.Error("OpenPorts returned nil")
	}
}

// The error types have to unwrap so callers can use errors.Is and errors.As.
func TestErrors_WrapAndUnwrap(t *testing.T) {
	base := errors.New("boom")

	mount := &CuratedMountError{Err: base}
	if !errors.Is(mount, base) {
		t.Error("CuratedMountError does not unwrap to its cause")
	}
	if mount.Error() == "" {
		t.Error("CuratedMountError.Error() is empty")
	}

	f := Failure{Target: "t", PocID: "p", Err: base}
	if !errors.Is(f, base) {
		t.Error("Failure does not unwrap to its cause")
	}
	if f.Error() != "boom" {
		t.Errorf("Failure.Error() = %q, want %q", f.Error(), "boom")
	}

	// A Failure with no cause must not panic and must read as empty.
	var empty Failure
	if empty.Error() != "" {
		t.Errorf("empty Failure.Error() = %q, want empty", empty.Error())
	}
}

// Progress before the scan finishes goes through the weighted path, which is
// skipped entirely by the "finished cleanly is 100%" shortcut.
func TestScanner_ProgressBeforeFinishIsWeighted(t *testing.T) {
	srv := newTestServer(t)
	dir := t.TempDir()
	writePoc(t, dir, "weighted.yaml", "sdk-test-weighted")

	scanner, err := New(context.Background(),
		WithTargets(srv.URL),
		WithPocPaths(dir),
		WithPocPathsOnly(),
		WithFingerprintDisabled(),
		// Both stages carry weight, so the port and web-probe phases are read.
		WithPortScan(PortScanOptions{Ports: "80", SkipDiscovery: true}),
		WithWebProbe(),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = scanner.Close() })

	got := scanner.Progress()
	if got < 0 || got > 100 {
		t.Fatalf("Progress = %.2f before the scan, want within [0, 100]", got)
	}
}

// recordOpenPort builds a nested map, so the same host reported twice must
// collect both ports rather than replacing the first.
func TestScanner_RecordOpenPort(t *testing.T) {
	scanner, _ := newTestScanner(t)

	scanner.recordOpenPort("10.0.0.1", 80)
	scanner.recordOpenPort("10.0.0.1", 443)
	scanner.recordOpenPort("10.0.0.1", 80) // duplicate
	scanner.recordOpenPort("10.0.0.2", 22)

	ports := scanner.OpenPorts()
	if len(ports) != 2 {
		t.Fatalf("OpenPorts has %d hosts, want 2", len(ports))
	}
	if len(ports["10.0.0.1"]) != 2 {
		t.Errorf("10.0.0.1 has %v, want two distinct ports", ports["10.0.0.1"])
	}
	if len(ports["10.0.0.2"]) != 1 {
		t.Errorf("10.0.0.2 has %v, want one port", ports["10.0.0.2"])
	}
}

func TestClampFloat(t *testing.T) {
	tests := []struct {
		in   float64
		want float64
	}{
		{-1, 0}, {0, 0}, {50.5, 50.5}, {100, 100}, {101, 100},
	}
	for _, tt := range tests {
		if got := clampFloat(tt.in); got != tt.want {
			t.Errorf("clampFloat(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// Fingerprint hits are turned into results, which is a separate path from
// ordinary PoC matches.
func TestScanner_FingerprintHitsBecomeResults(t *testing.T) {
	scanner, _ := newTestScanner(t)

	scanner.handleFingerprint("key", nil)
	if got := scanner.ResultCount(); got != 0 {
		t.Fatalf("an empty hit list produced %d results", got)
	}
}
