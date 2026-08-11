package afrog

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/result"
)

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
