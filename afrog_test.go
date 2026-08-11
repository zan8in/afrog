package afrog

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/result"
)

func captureStdout(t *testing.T) (*os.File, *os.File, *os.File) {
	t.Helper()
	stdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	return stdout, r, w
}

func restoreStdout(t *testing.T, stdout, r, w *os.File) string {
	t.Helper()
	os.Stdout = stdout
	_ = w.Close()

	var sb strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	<-done
	_ = r.Close()
	return sb.String()
}

const compatToken = "AFROG_COMPAT_TOKEN"

func newCompatServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "afrog-compat/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><title>compat</title>" + compatToken + "</html>"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeCompatPoc(t *testing.T, dir, id string) {
	t.Helper()
	body := "id: " + id + `
info:
  name: compat test poc
  author: compat
  severity: info
rules:
  r0:
    request:
      method: GET
      path: /probe
    expression: response.status == 200 && response.body.bcontains(b"` + compatToken + `")
expression: r0()
`
	if err := os.WriteFile(filepath.Join(dir, id+".yaml"), []byte(body), 0o644); err != nil {
		t.Fatalf("write poc: %v", err)
	}
}

// newCompatOptions builds options the way pre-existing integrations do: take
// the defaults, then assign struct fields directly.
func newCompatOptions(t *testing.T, target string) *SDKOptions {
	t.Helper()
	dir := t.TempDir()
	writeCompatPoc(t, dir, "compat-match")

	opts := NewSDKOptions()
	opts.Targets = []string{target}
	opts.PocFile = dir
	opts.DisableFingerprint = true
	opts.Timeout = 10
	opts.Silent = true // keeps the test output clean; not part of the old API
	return opts
}

// The original usage pattern must keep working unchanged.
func TestCompat_BasicScan(t *testing.T) {
	srv := newCompatServer(t)
	opts := newCompatOptions(t, srv.URL)

	scanner, err := NewSDKScanner(opts)
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	if err := scanner.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	results := scanner.GetResults()
	if len(results) != 1 {
		t.Fatalf("GetResults returned %d results, want 1", len(results))
	}
	if !scanner.HasVulnerabilities() {
		t.Error("HasVulnerabilities = false after a finding")
	}
	if got := scanner.GetVulnerabilityCount(); got != 1 {
		t.Errorf("GetVulnerabilityCount = %d, want 1", got)
	}

	// GetResults still hands back the engine's own type, with the request and
	// response attached.
	r := results[0]
	if r.PocInfo == nil || r.PocInfo.Id != "compat-match" {
		t.Errorf("result carries the wrong PoC: %+v", r.PocInfo)
	}
	if len(r.AllPocResult) == 0 {
		t.Error("result carries no request/response")
	}
}

// Defaults must match the original ones exactly.
func TestCompat_NewSDKOptionsDefaults(t *testing.T) {
	o := NewSDKOptions()
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"RateLimit", o.RateLimit, 150},
		{"Concurrency", o.Concurrency, 25},
		{"Retries", o.Retries, 1},
		{"Timeout", o.Timeout, 50},
		{"MaxHostError", o.MaxHostError, 3},
		{"MaxRespBodySize", o.MaxRespBodySize, 2},
		{"BruteMaxRequests", o.BruteMaxRequests, 5000},
		{"DefaultAccept", o.DefaultAccept, true},
		{"FingerprintFilterMode", o.FingerprintFilterMode, "strict"},
		{"PSPorts", o.PSPorts, "top"},
		{"PSS4Chunk", o.PSS4Chunk, 1000},
		{"OOBRateLimit", o.OOBRateLimit, 25},
		{"OOBConcurrency", o.OOBConcurrency, 25},
		{"OOBFinalizeTimeout", o.OOBFinalizeTimeout, -1},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}

// Callbacks are public fields assigned after construction, so they must be
// read at call time rather than captured when the scanner is built.
func TestCompat_CallbacksAssignedAfterConstruction(t *testing.T) {
	srv := newCompatServer(t)
	opts := newCompatOptions(t, srv.URL)

	scanner, err := NewSDKScanner(opts)
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	var mu sync.Mutex
	var got []*result.Result
	scanner.OnResult = func(r *result.Result) {
		mu.Lock()
		got = append(got, r)
		mu.Unlock()
	}

	if err := scanner.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("OnResult fired %d times, want 1", len(got))
	}
}

// EnableStream allocates the channels; they must deliver and then close so a
// range loop terminates.
func TestCompat_StreamingChannels(t *testing.T) {
	srv := newCompatServer(t)
	opts := newCompatOptions(t, srv.URL)
	opts.EnableStream = true

	scanner, err := NewSDKScanner(opts)
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	if scanner.ResultChan == nil || scanner.PhaseProgressChan == nil {
		t.Fatal("EnableStream did not allocate the channels")
	}

	var count int
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range scanner.ResultChan {
			count++
		}
	}()

	if err := scanner.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	select {
	case <-drained:
	case <-time.After(30 * time.Second):
		t.Fatal("ResultChan was not closed when the scan finished")
	}
	if count != 1 {
		t.Errorf("received %d results from ResultChan, want 1", count)
	}
}

// Without EnableStream the channels stay nil, exactly as before.
func TestCompat_ChannelsNilWithoutEnableStream(t *testing.T) {
	srv := newCompatServer(t)
	scanner, err := NewSDKScanner(newCompatOptions(t, srv.URL))
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	if scanner.ResultChan != nil || scanner.PortChan != nil || scanner.HostChan != nil ||
		scanner.WebProbeChan != nil || scanner.PhaseProgressChan != nil || scanner.ScanInfoChan != nil {
		t.Error("channels were allocated without EnableStream")
	}
}

// A caller that enables streaming but never drains must not stall the scan.
// The original implementation dropped on a full channel, and code in the wild
// relies on that.
func TestCompat_UndrainedChannelDoesNotBlockScan(t *testing.T) {
	srv := newCompatServer(t)
	opts := newCompatOptions(t, srv.URL)
	opts.EnableStream = true

	scanner, err := NewSDKScanner(opts)
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	done := make(chan error, 1)
	go func() { done <- scanner.Run() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("scan stalled on an undrained channel")
	}
}

func TestCompat_RunAsync(t *testing.T) {
	srv := newCompatServer(t)
	scanner, err := NewSDKScanner(newCompatOptions(t, srv.URL))
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	if err := scanner.RunAsync(); err != nil {
		t.Fatalf("RunAsync: %v", err)
	}

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if scanner.GetProgress() >= 100 && scanner.GetVulnerabilityCount() > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := scanner.GetVulnerabilityCount(); got != 1 {
		t.Fatalf("found %d results after RunAsync, want 1", got)
	}
}

// The setters are called between construction and Run, so their values have to
// reach the scan.
func TestCompat_SettersApplyBeforeRun(t *testing.T) {
	srv := newCompatServer(t)
	scanner, err := NewSDKScanner(newCompatOptions(t, srv.URL))
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	scanner.SetRateLimit(42)
	scanner.SetConcurrency(3)

	if err := scanner.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := scanner.GetVulnerabilityCount(); got != 1 {
		t.Fatalf("found %d results, want 1", got)
	}
	if scanner.opts.RateLimit != 42 || scanner.opts.Concurrency != 3 {
		t.Errorf("setters did not update the options: rate=%d concurrency=%d",
			scanner.opts.RateLimit, scanner.opts.Concurrency)
	}
}

func TestCompat_StatsAndProgress(t *testing.T) {
	srv := newCompatServer(t)
	scanner, err := NewSDKScanner(newCompatOptions(t, srv.URL))
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	before := scanner.GetStats()
	if before.TotalPocs != 1 {
		t.Errorf("TotalPocs = %d before the scan, want 1", before.TotalPocs)
	}

	if err := scanner.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	after := scanner.GetStats()
	if after.FoundVulns != 1 {
		t.Errorf("FoundVulns = %d, want 1", after.FoundVulns)
	}
	if after.CompletedScans < 1 {
		t.Errorf("CompletedScans = %d, want at least 1", after.CompletedScans)
	}
	if after.StartTime.IsZero() || after.EndTime.IsZero() {
		t.Error("StartTime or EndTime not set")
	}
	if got := scanner.GetProgress(); got != 100 {
		t.Errorf("GetProgress = %.2f after a clean finish, want 100", got)
	}
}

// Close must be safe before a scan, after one, and when called twice.
func TestCompat_CloseAtEveryPoint(t *testing.T) {
	srv := newCompatServer(t)

	tests := []struct {
		name   string
		before func(s *SDKScanner)
	}{
		{"never started", func(*SDKScanner) {}},
		{"after run", func(s *SDKScanner) { _ = s.Run() }},
		{"after stop", func(s *SDKScanner) { s.Stop() }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := NewSDKScanner(newCompatOptions(t, srv.URL))
			if err != nil {
				t.Fatalf("NewSDKScanner: %v", err)
			}
			tt.before(scanner)

			done := make(chan struct{})
			go func() { defer close(done); scanner.Close(); scanner.Close() }()

			select {
			case <-done:
			case <-time.After(60 * time.Second):
				t.Fatal("Close blocked")
			}
		})
	}
}

// A missing target used to be a configuration error at construction time.
func TestCompat_ConstructionErrorsSurfaceEarly(t *testing.T) {
	opts := NewSDKOptions()
	opts.Silent = true
	if _, err := NewSDKScanner(opts); err == nil {
		t.Fatal("NewSDKScanner with no targets should have failed")
	}
}

// A nil options value falls back to the defaults rather than panicking.
func TestCompat_NilOptions(t *testing.T) {
	if _, err := NewSDKScanner(nil); err == nil {
		t.Fatal("NewSDKScanner(nil) should fail on the missing target, not panic")
	}
}

// Specifying PocFile and AppendPoc together used to drop AppendPoc silently.
func TestCompat_PocFileAndAppendPocAreBothHonoured(t *testing.T) {
	srv := newCompatServer(t)

	dirA := t.TempDir()
	writeCompatPoc(t, dirA, "compat-a")
	dirB := t.TempDir()
	writeCompatPoc(t, dirB, "compat-b")

	opts := NewSDKOptions()
	opts.Targets = []string{srv.URL}
	opts.PocFile = dirA
	opts.AppendPoc = []string{dirB}
	opts.DisableFingerprint = true
	opts.Timeout = 10
	opts.Silent = true

	scanner, err := NewSDKScanner(opts)
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	if got := scanner.GetStats().TotalPocs; got != 2 {
		t.Fatalf("loaded %d pocs, want 2 (PocFile + AppendPoc)", got)
	}
}

// The new options must be reachable from the old struct without changing how
// the rest of it is used.
func TestCompat_NewCapabilitiesAreReachable(t *testing.T) {
	srv := newCompatServer(t)
	opts := newCompatOptions(t, srv.URL)
	opts.TaskHardTimeoutSec = 30
	opts.MaxStoredResults = 10
	opts.ResumeFile = filepath.Join(t.TempDir(), "compat.afg")

	var failures int
	opts.OnFailure = func(string, string, error) { failures++ }

	scanner, err := NewSDKScanner(opts)
	if err != nil {
		t.Fatalf("NewSDKScanner with the new options: %v", err)
	}
	defer scanner.Close()

	if err := scanner.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := scanner.GetVulnerabilityCount(); got != 1 {
		t.Fatalf("found %d results, want 1", got)
	}
	if _, err := os.Stat(opts.ResumeFile); err != nil {
		t.Errorf("resume file was not written: %v", err)
	}
}

// Pause, Resume and IsPaused must still gate the scan.
func TestCompat_PauseResume(t *testing.T) {
	srv := newCompatServer(t)
	scanner, err := NewSDKScanner(newCompatOptions(t, srv.URL))
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	if scanner.IsPaused() {
		t.Error("IsPaused = true before anything happened")
	}

	scanner.Pause()
	if !scanner.IsPaused() {
		t.Error("IsPaused = false after Pause")
	}

	scanner.Resume()
	if scanner.IsPaused() {
		t.Error("IsPaused = true after Resume")
	}

	// The scan must still complete normally after a pause/resume cycle.
	if err := scanner.Run(); err != nil {
		t.Fatalf("Run after pause/resume: %v", err)
	}
	if got := scanner.GetVulnerabilityCount(); got != 1 {
		t.Errorf("found %d results, want 1", got)
	}
}

// IsStopping reflects Stop, and a stopped scan must not hang.
func TestCompat_StopAndIsStopping(t *testing.T) {
	srv := newCompatServer(t)
	scanner, err := NewSDKScanner(newCompatOptions(t, srv.URL))
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	if scanner.IsStopping() {
		t.Error("IsStopping = true before Stop")
	}

	if err := scanner.RunAsync(); err != nil {
		t.Fatalf("RunAsync: %v", err)
	}
	scanner.Stop()

	if !scanner.IsStopping() {
		t.Error("IsStopping = false after Stop")
	}

	done := make(chan struct{})
	go func() { defer close(done); scanner.Close() }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("Close blocked after Stop")
	}
}

// GetOpenPorts returns an empty map rather than nil when no pre-scan ran, so
// callers can range over it unconditionally.
func TestCompat_GetOpenPorts(t *testing.T) {
	srv := newCompatServer(t)
	scanner, err := NewSDKScanner(newCompatOptions(t, srv.URL))
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	ports := scanner.GetOpenPorts()
	if ports == nil {
		t.Fatal("GetOpenPorts returned nil")
	}
	if len(ports) != 0 {
		t.Errorf("GetOpenPorts returned %d hosts without a port pre-scan", len(ports))
	}

	if err := scanner.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := scanner.GetOpenPorts(); got == nil {
		t.Error("GetOpenPorts returned nil after the scan")
	}
}

// SetProxy re-initialises the shared HTTP client, so it must not break a scan
// when pointed back at no proxy.
func TestCompat_SetProxy(t *testing.T) {
	srv := newCompatServer(t)
	scanner, err := NewSDKScanner(newCompatOptions(t, srv.URL))
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	scanner.SetProxy("")
	if scanner.opts.Proxy != "" {
		t.Errorf("Proxy = %q, want empty", scanner.opts.Proxy)
	}

	if err := scanner.Run(); err != nil {
		t.Fatalf("Run after SetProxy: %v", err)
	}
	if got := scanner.GetVulnerabilityCount(); got != 1 {
		t.Errorf("found %d results, want 1", got)
	}
}

// The OOB helpers must report "not configured" without probing anything when
// OOB was never enabled.
func TestCompat_OOBReportsDisabledWhenUnconfigured(t *testing.T) {
	srv := newCompatServer(t)
	scanner, err := NewSDKScanner(newCompatOptions(t, srv.URL))
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	if scanner.IsOOBEnabled() {
		t.Error("IsOOBEnabled = true without any OOB configuration")
	}
	enabled, status := scanner.GetOOBStatus()
	if enabled {
		t.Error("GetOOBStatus reported enabled without configuration")
	}
	if strings.TrimSpace(status) == "" {
		t.Error("GetOOBStatus returned an empty description")
	}
}

// IsOOBEnabled keeps its original shape: the explicit flag wins, and failing
// that a configured adapter plus a key or domain counts as enabled.
func TestCompat_IsOOBEnabledMatchesOriginalRules(t *testing.T) {
	tests := []struct {
		name string
		opts *SDKOptions
		want bool
	}{
		{"nothing set", &SDKOptions{}, false},
		{"explicit flag", &SDKOptions{EnableOOB: true}, true},
		{"adapter only", &SDKOptions{OOB: "ceyeio"}, false},
		{"adapter and key", &SDKOptions{OOB: "ceyeio", OOBKey: "k"}, true},
		{"adapter and domain", &SDKOptions{OOB: "ceyeio", OOBDomain: "d"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SDKScanner{opts: tt.opts}
			if got := s.IsOOBEnabled(); got != tt.want {
				t.Errorf("IsOOBEnabled = %v, want %v", got, tt.want)
			}
		})
	}
}

// Run prints the scan summary the way the original SDK did, and Silent turns
// that off for callers that want the quiet behaviour of the new API.
func TestCompat_PrintsSummaryUnlessSilent(t *testing.T) {
	srv := newCompatServer(t)

	tests := []struct {
		name       string
		silent     bool
		wantOutput bool
	}{
		{"default prints", false, true},
		{"silent is quiet", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := newCompatOptions(t, srv.URL)
			opts.Silent = tt.silent

			scanner, err := NewSDKScanner(opts)
			if err != nil {
				t.Fatalf("NewSDKScanner: %v", err)
			}
			defer scanner.Close()

			stdout, r, w := captureStdout(t)
			runErr := scanner.Run()
			output := restoreStdout(t, stdout, r, w)

			if runErr != nil {
				t.Fatalf("Run: %v", runErr)
			}
			if tt.wantOutput && !strings.Contains(output, "扫描信息") {
				t.Errorf("expected the scan summary on stdout, got:\n%s", output)
			}
			if !tt.wantOutput && output != "" {
				t.Errorf("Silent still wrote to stdout:\n%s", output)
			}
		})
	}
}

// A second Run on the same scanner must report the single-use error rather
// than silently doing nothing.
func TestCompat_SecondRunIsRejected(t *testing.T) {
	srv := newCompatServer(t)
	scanner, err := NewSDKScanner(newCompatOptions(t, srv.URL))
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	if err := scanner.Run(); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if err := scanner.Run(); err == nil {
		t.Error("second Run should have failed on a single-use scanner")
	}
}

// A field can sit on SDKOptions, compile fine, and still never reach the
// engine. That failure is invisible: the caller sets it, the scan runs, and
// the setting is ignored. This pins every field that maps onto an engine
// setting to the value the engine actually ends up with.
func TestCompat_EveryOptionReachesTheEngine(t *testing.T) {
	srv := newCompatServer(t)
	dir := t.TempDir()
	writeCompatPoc(t, dir, "reach")

	opts := NewSDKOptions()
	opts.Silent = true
	opts.Targets = []string{srv.URL}
	opts.PocFile = dir
	opts.DisableFingerprint = true

	opts.Concurrency = 7
	opts.RateLimit = 11
	opts.Timeout = 13
	opts.Retries = 4
	opts.MaxHostError = 9
	opts.MaxRespBodySize = 5
	opts.BruteMaxRequests = 123
	opts.DefaultAccept = false
	opts.ReqLimitPerTarget = 6
	opts.Smart = true
	opts.EnableWebProbe = true
	opts.Search = "reach"
	opts.Severity = "info"
	opts.ExcludePocs = []string{"nope"}
	opts.Headers = []string{"X-Test: 1"}
	opts.VulnerabilityScannerBreakpoint = true
	opts.FingerprintFilterMode = "opportunistic"
	opts.Proxy = ""

	scanner, err := NewSDKScanner(opts)
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	in := scanner.Scanner().EngineOptions()
	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"Concurrency", in.Concurrency, 7},
		{"RateLimit", in.RateLimit, 11},
		{"Timeout", in.Timeout, 13},
		{"Retries", in.Retries, 4},
		{"MaxHostError", in.MaxHostError, 9},
		{"MaxRespBodySize", in.MaxRespBodySize, 5},
		{"BruteMaxRequests", in.BruteMaxRequests, 123},
		{"DefaultAccept", in.DefaultAccept, false},
		{"ReqLimitPerTarget", in.ReqLimitPerTarget, 6},
		{"Smart", in.Smart, true},
		{"EnableWebProbe", in.EnableWebProbe, true},
		{"Search", in.Search, "reach"},
		{"Severity", in.Severity, "info"},
		{"DisableFingerprint", in.DisableFingerprint, true},
		{"FingerprintFilterMode", in.FingerprintFilterMode, "opportunistic"},
		{"VulnerabilityScannerBreakpoint", in.VulnerabilityScannerBreakpoint, true},
		{"PocPathsOnly", in.PocPathsOnly, true}, // PocFile keeps its exclusive meaning
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("SDKOptions.%s did not reach the engine: got %v, want %v", c.field, c.got, c.want)
		}
	}
	if len(in.Header) != 1 {
		t.Errorf("Headers did not reach the engine: %v", in.Header)
	}
	if len(in.ExcludePocs) != 1 {
		t.Errorf("ExcludePocs did not reach the engine: %v", in.ExcludePocs)
	}
}

// The port pre-scan block is a nested struct in the old options, so each of
// its fields needs its own mapping.
func TestCompat_PortScanOptionsReachTheEngine(t *testing.T) {
	srv := newCompatServer(t)
	opts := newCompatOptions(t, srv.URL)
	opts.PortScan = true
	opts.PSPorts = "80,443"
	opts.PSRateLimit = 33
	opts.PSTimeout = 700
	opts.PSRetries = 2
	opts.PSSkipDiscovery = true
	opts.PSS4Chunk = 250

	scanner, err := NewSDKScanner(opts)
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	in := scanner.Scanner().EngineOptions()
	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"PortScan", in.PortScan, true},
		{"PSPorts", in.PSPorts, "80,443"},
		{"PSRateLimit", in.PSRateLimit, 33},
		{"PSTimeout", in.PSTimeout, 700},
		{"PSRetries", in.PSRetries, 2},
		{"PSSkipDiscovery", in.PSSkipDiscovery, true},
		{"PSS4Chunk", in.PSS4Chunk, 250},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("SDKOptions.%s did not reach the engine: got %v, want %v", c.field, c.got, c.want)
		}
	}
}

// The OOB block likewise has to arrive field by field.
func TestCompat_OOBOptionsReachTheEngine(t *testing.T) {
	srv := newCompatServer(t)
	opts := newCompatOptions(t, srv.URL)
	opts.EnableOOB = true
	opts.OOB = "ceyeio"
	opts.OOBKey = "test-key"
	opts.OOBDomain = "test.example.com"
	opts.OOBRateLimit = 8
	opts.OOBConcurrency = 9
	opts.OOBFinalizeTimeout = 15
	opts.OOBPollInterval = 4
	opts.OOBHitRetention = 6

	scanner, err := NewSDKScanner(opts)
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	in := scanner.Scanner().EngineOptions()
	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"EnableOOB", in.EnableOOB, true},
		{"OOB", in.OOB, "ceyeio"},
		{"OOBKey", in.OOBKey, "test-key"},
		{"OOBDomain", in.OOBDomain, "test.example.com"},
		{"OOBRateLimit", in.OOBRateLimit, 8},
		{"OOBConcurrency", in.OOBConcurrency, 9},
		{"OOBFinalizeTimeout", in.OOBFinalizeTimeout, 15},
		{"OOBPollInterval", in.OOBPollInterval, 4},
		{"OOBHitRetention", in.OOBHitRetention, 6},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("SDKOptions.%s did not reach the engine: got %v, want %v", c.field, c.got, c.want)
		}
	}
	if !scanner.IsOOBEnabled() {
		t.Error("IsOOBEnabled = false with OOB configured")
	}
}

// The capabilities added after the facade must reach the engine too.
func TestCompat_NewOptionsReachTheEngine(t *testing.T) {
	srv := newCompatServer(t)
	opts := newCompatOptions(t, srv.URL)
	opts.TaskHardTimeoutSec = 45
	opts.TaskSmartTimeout = true
	opts.MonitorTargets = true
	opts.ResumeFile = filepath.Join(t.TempDir(), "reach.afg")

	scanner, err := NewSDKScanner(opts)
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	in := scanner.Scanner().EngineOptions()
	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"TaskHardTimeoutSec", in.TaskHardTimeoutSec, 45},
		{"TaskSmartTimeout", in.TaskSmartTimeout, true},
		{"MonitorTargets", in.MonitorTargets, true},
		{"Resume", in.Resume, opts.ResumeFile},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("SDKOptions.%s did not reach the engine: got %v, want %v", c.field, c.got, c.want)
		}
	}
}

// The facade must expose the current SDK for callers that want to migrate
// gradually.
func TestCompat_ScannerAccessorExposesTheModernAPI(t *testing.T) {
	srv := newCompatServer(t)
	scanner, err := NewSDKScanner(newCompatOptions(t, srv.URL))
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	defer scanner.Close()

	modern := scanner.Scanner()
	if modern == nil {
		t.Fatal("Scanner() returned nil")
	}
	if got := modern.PocCount(); got != 1 {
		t.Errorf("PocCount = %d, want 1", got)
	}
}
