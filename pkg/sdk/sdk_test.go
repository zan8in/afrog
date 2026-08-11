package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/result"
)

const magicToken = "AFROG_SDK_TEST_TOKEN"

// newTestServer returns a server whose response matches the test PoC.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "afrog-test/1.0")
		w.Header().Set("X-Custom", "custom-value")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><title>afrog test</title>" + magicToken + "</html>"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// writePoc writes a PoC that matches newTestServer's response.
func writePoc(t *testing.T, dir, name, id string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	body := "id: " + id + `
info:
  name: ` + id + `
  author: afrog-test
  severity: info
  description: sdk test poc
rules:
  r0:
    request:
      method: GET
      path: /probe?q=1
    expression: response.status == 200 && response.body.bcontains(b"` + magicToken + `")
expression: r0()
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write poc %s: %v", path, err)
	}
	return path
}

// newTestScanner wires a scanner to a local server and a temporary PoC dir.
func newTestScanner(t *testing.T, extra ...Option) (*Scanner, *httptest.Server) {
	t.Helper()
	srv := newTestServer(t)
	dir := t.TempDir()
	writePoc(t, dir, "match.yaml", "sdk-test-match")

	options := append([]Option{
		WithTargets(srv.URL),
		WithPocPaths(dir),
		WithPocPathsOnly(),
		WithFingerprintDisabled(),
		WithTimeout(10),
	}, extra...)

	scanner, err := New(context.Background(), options...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = scanner.Close() })
	return scanner, srv
}

// --- PoC input ---------------------------------------------------------------

func TestScanner_PocInputForms(t *testing.T) {
	srv := newTestServer(t)
	dir := t.TempDir()
	single := writePoc(t, dir, "one.yaml", "one")
	writePoc(t, dir, "two.yaml", "two")

	tests := []struct {
		name  string
		paths []string
		want  int
	}{
		{name: "single file", paths: []string{single}, want: 1},
		{name: "directory", paths: []string{dir}, want: 2},
		{name: "glob", paths: []string{filepath.Join(dir, "*.yaml")}, want: 2},
		{name: "mixed inputs are merged and de-duplicated", paths: []string{single, dir}, want: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := New(context.Background(),
				WithTargets(srv.URL),
				WithPocPaths(tt.paths...),
				WithPocPathsOnly(),
			)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer scanner.Close()

			if got := scanner.PocCount(); got != tt.want {
				t.Errorf("PocCount() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestScanner_RejectsUnresolvablePocPath(t *testing.T) {
	srv := newTestServer(t)

	_, err := New(context.Background(),
		WithTargets(srv.URL),
		WithPocPaths(filepath.Join(t.TempDir(), "missing")),
	)
	if !errors.Is(err, ErrPocPathNotFound) {
		t.Fatalf("error = %v, want ErrPocPathNotFound", err)
	}
}

func TestScanner_RequiresTargets(t *testing.T) {
	dir := t.TempDir()
	writePoc(t, dir, "a.yaml", "a")

	_, err := New(context.Background(), WithPocPaths(dir))
	if !errors.Is(err, ErrNoTargets) {
		t.Fatalf("error = %v, want ErrNoTargets", err)
	}
}

func TestScanner_PocDiagnosticsExposeSkippedPocs(t *testing.T) {
	srv := newTestServer(t)
	dir := t.TempDir()
	writePoc(t, dir, "good.yaml", "good")

	broken := filepath.Join(dir, "broken.yaml")
	if err := os.WriteFile(broken, []byte("id: broken\ninfo: [not a mapping\n"), 0o644); err != nil {
		t.Fatalf("write broken poc: %v", err)
	}

	scanner, err := New(context.Background(),
		WithTargets(srv.URL),
		WithPocPaths(dir),
		WithPocPathsOnly(),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer scanner.Close()

	if len(scanner.PocDiagnostics()) == 0 {
		t.Fatal("expected a diagnostic for the malformed PoC")
	}
	if scanner.PocCount() != 1 {
		t.Errorf("PocCount() = %d, want 1", scanner.PocCount())
	}
}

// --- full data output --------------------------------------------------------

func TestScanner_ResultsCarryFullRequestAndResponse(t *testing.T) {
	scanner, srv := newTestScanner(t)

	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	results := scanner.Results()
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}

	r := results[0]
	if r.PocID != "sdk-test-match" {
		t.Errorf("PocID = %q, want sdk-test-match", r.PocID)
	}
	if !strings.HasPrefix(r.FullTarget, srv.URL) {
		t.Errorf("FullTarget = %q, want prefix %q", r.FullTarget, srv.URL)
	}
	if len(r.Exchanges) == 0 {
		t.Fatal("expected at least one exchange")
	}

	ex := r.Exchanges[0]
	if !strings.Contains(ex.Request, "GET /probe?q=1") {
		t.Errorf("raw request missing request line:\n%s", ex.Request)
	}
	if !strings.Contains(ex.Response, magicToken) {
		t.Errorf("raw response missing body token:\n%s", ex.Response)
	}
	if ex.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", ex.StatusCode)
	}
	if ex.Method != http.MethodGet {
		t.Errorf("Method = %q, want GET", ex.Method)
	}
	if ex.ResponseHeaders["server"] != "afrog-test/1.0" {
		t.Errorf("response header server = %q, want afrog-test/1.0", ex.ResponseHeaders["server"])
	}
	if ex.BodyTruncated {
		t.Error("BodyTruncated should be false for a small response")
	}
}

// Redaction has to survive the whole path from the engine to Results(), not
// just the Exchange helper: the point of the option is that a caller can log
// or persist the results without leaking credentials.
func TestScanner_RedactsCredentialsInScanResults(t *testing.T) {
	const secret = "super-secret-credential"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session="+secret)
		w.Header().Set("X-Custom", "keep-me")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>" + magicToken + "</html>"))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	writePoc(t, dir, "redact.yaml", "sdk-test-redact")

	scanner, err := New(context.Background(),
		WithTargets(srv.URL),
		WithPocPaths(dir),
		WithPocPathsOnly(),
		WithFingerprintDisabled(),
		WithTimeout(10),
		WithHeaders("Authorization: Bearer "+secret),
		WithRedactedHeaders(),
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

	// Serialising is how these leak in practice, so assert on the encoded form.
	blob, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal results: %v", err)
	}
	encoded := string(blob)

	if strings.Contains(encoded, secret) {
		t.Errorf("serialised results still carry the credential:\n%s", encoded)
	}
	if !strings.Contains(encoded, redactedValue) {
		t.Errorf("nothing was redacted:\n%s", encoded)
	}
	if !strings.Contains(encoded, "keep-me") {
		t.Errorf("redaction removed a harmless header:\n%s", encoded)
	}
}

func TestScanner_ResultsAreJSONSerialisable(t *testing.T) {
	scanner, _ := newTestScanner(t)

	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	data, err := json.Marshal(scanner.Results())
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	// Raw exchanges must survive as readable text, not base64 blobs.
	if !strings.Contains(string(data), magicToken) {
		t.Errorf("serialised results should contain the raw response body:\n%s", data)
	}

	var round []Result
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(round) != 1 {
		t.Fatalf("round-tripped %d results, want 1", len(round))
	}
}

func TestScanner_RequestResponseCanBeDisabled(t *testing.T) {
	scanner, _ := newTestScanner(t, WithRequestResponse(false))

	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	results := scanner.Results()
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if len(results[0].Exchanges) != 0 {
		t.Errorf("Exchanges = %d, want 0 when capture is disabled", len(results[0].Exchanges))
	}
}

func TestScanner_MaxStoredResultsDoesNotSuppressHandlers(t *testing.T) {
	srv := newTestServer(t)
	dir := t.TempDir()
	writePoc(t, dir, "a.yaml", "poc-a")
	writePoc(t, dir, "b.yaml", "poc-b")

	var handled atomic.Int64
	scanner, err := New(context.Background(),
		WithTargets(srv.URL),
		WithPocPaths(dir),
		WithPocPathsOnly(),
		WithFingerprintDisabled(),
		WithMaxStoredResults(1),
		WithResultHandler(func(Result) { handled.Add(1) }),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer scanner.Close()

	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if got := len(scanner.Results()); got != 1 {
		t.Errorf("stored %d results, want 1", got)
	}
	if got := handled.Load(); got != 2 {
		t.Errorf("handler fired %d times, want 2", got)
	}
	if got := scanner.ResultCount(); got != 2 {
		t.Errorf("ResultCount() = %d, want 2", got)
	}
}

func TestScanner_RawResultHandlerReceivesEngineType(t *testing.T) {
	var got atomic.Int64
	scanner, _ := newTestScanner(t, WithRawResultHandler(func(r *result.Result) {
		if r != nil && len(r.AllPocResult) > 0 {
			got.Add(1)
		}
	}))

	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.Load() != 1 {
		t.Fatalf("raw handler fired %d times with exchanges, want 1", got.Load())
	}
}

// --- lifecycle ---------------------------------------------------------------

func TestScanner_ExecuteIsSingleUse(t *testing.T) {
	scanner, _ := newTestScanner(t)

	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if err := scanner.Execute(context.Background()); !errors.Is(err, ErrAlreadyFinished) {
		t.Fatalf("second Execute = %v, want ErrAlreadyFinished", err)
	}
}

func TestScanner_WaitBeforeStart(t *testing.T) {
	scanner, _ := newTestScanner(t)

	if err := scanner.Wait(context.Background()); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("Wait = %v, want ErrNotStarted", err)
	}
}

func TestScanner_DoneClosesAfterScan(t *testing.T) {
	scanner, _ := newTestScanner(t)

	if err := scanner.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	select {
	case <-scanner.Done():
	case <-time.After(60 * time.Second):
		t.Fatal("scan did not finish within the timeout")
	}
	if err := scanner.Err(); err != nil {
		t.Errorf("Err() = %v, want nil", err)
	}
}

func TestScanner_ContextCancellationStopsScan(t *testing.T) {
	scanner, _ := newTestScanner(t)

	ctx, cancel := context.WithCancel(context.Background())
	if err := scanner.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	cancel()

	select {
	case <-scanner.Done():
	case <-time.After(60 * time.Second):
		t.Fatal("cancelling the context did not stop the scan")
	}
	if !scanner.IsStopping() {
		t.Error("IsStopping() should be true after the context was cancelled")
	}
}

func TestScanner_StopIsIndependentOfStopOnFirstMatch(t *testing.T) {
	// StopOnFirstMatch used to share a field with the stop flag, so enabling it
	// made IsStopping report true before the scan even began.
	scanner, _ := newTestScanner(t, WithStopOnFirstMatch())

	if scanner.IsStopping() {
		t.Fatal("IsStopping() must be false before Stop is called")
	}
	scanner.Stop()
	if !scanner.IsStopping() {
		t.Fatal("IsStopping() must be true after Stop")
	}
}

func TestScanner_CloseIsIdempotent(t *testing.T) {
	scanner, _ := newTestScanner(t)

	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if err := scanner.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := scanner.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := scanner.Start(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Start after Close = %v, want ErrClosed", err)
	}
}

func TestScanner_CloseWithoutStartDoesNotBlock(t *testing.T) {
	scanner, _ := newTestScanner(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = scanner.Close()
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close blocked when no scan had been started")
	}
}

func TestScanner_MultipleResultHandlers(t *testing.T) {
	var first, second atomic.Int64

	scanner, _ := newTestScanner(t,
		WithResultHandler(func(Result) { first.Add(1) }),
		WithResultHandler(func(Result) { second.Add(1) }),
	)

	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if first.Load() != 1 || second.Load() != 1 {
		t.Fatalf("handlers fired %d and %d times, want 1 each", first.Load(), second.Load())
	}
}

// --- streams -----------------------------------------------------------------

func TestScanner_ResultStreamDeliversEveryFinding(t *testing.T) {
	scanner, _ := newTestScanner(t)

	results := scanner.ResultStream()
	if err := scanner.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	var (
		wg    sync.WaitGroup
		count int
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range results {
			count++
		}
	}()

	if err := scanner.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	wg.Wait()

	if count != 1 {
		t.Fatalf("streamed %d results, want 1", count)
	}
}

// An unsubscribed stream must never stall the scan, which is the failure mode
// a naive blocking implementation would introduce.
func TestScanner_UnsubscribedStreamDoesNotBlockScan(t *testing.T) {
	scanner, _ := newTestScanner(t)

	done := make(chan error, 1)
	go func() { done <- scanner.Execute(context.Background()) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("scan stalled even though no stream was subscribed")
	}
}

func TestScanner_StreamClosesSoRangeTerminates(t *testing.T) {
	scanner, _ := newTestScanner(t)

	results := scanner.ResultStream()
	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range results {
		}
	}()

	select {
	case <-drained:
	case <-time.After(10 * time.Second):
		t.Fatal("result stream was not closed when the scan finished")
	}
}

func TestScanner_SubscribingAfterScanYieldsClosedStream(t *testing.T) {
	scanner, _ := newTestScanner(t)

	if err := scanner.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range scanner.ResultStream() {
		}
	}()

	select {
	case <-drained:
	case <-time.After(10 * time.Second):
		t.Fatal("subscribing after the scan should yield an already-closed stream")
	}
}

// --- resource management -----------------------------------------------------

// The out-of-band poll loop used to outlive every completed scan, so a
// long-running host process accumulated one goroutine per scan.
func TestScanner_DoesNotLeakGoroutines(t *testing.T) {
	// Warm up shared lazily-initialised state so it is not counted as a leak.
	warm, _ := newTestScanner(t)
	if err := warm.Execute(context.Background()); err != nil {
		t.Fatalf("warm-up Execute: %v", err)
	}
	_ = warm.Close()

	before := waitGoroutines(t, 0)

	for i := 0; i < 3; i++ {
		srv := newTestServer(t)
		dir := t.TempDir()
		writePoc(t, dir, "leak.yaml", "leak-check")

		scanner, err := New(context.Background(),
			WithTargets(srv.URL),
			WithPocPaths(dir),
			WithPocPathsOnly(),
			WithFingerprintDisabled(),
		)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := scanner.Execute(context.Background()); err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if err := scanner.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}

	after := waitGoroutines(t, before)
	// A small tolerance covers runtime and net/http background workers.
	if after > before+5 {
		t.Fatalf("goroutine count grew from %d to %d across 3 scans", before, after)
	}
}

// waitGoroutines settles the scheduler and returns the goroutine count,
// returning early once it drops to target or below.
func waitGoroutines(t *testing.T, target int) int {
	t.Helper()
	var n int
	for i := 0; i < 40; i++ {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
		n = runtime.NumGoroutine()
		if target > 0 && n <= target {
			return n
		}
	}
	return n
}

// --- output hygiene ----------------------------------------------------------

func TestScanner_IsSilentByDefault(t *testing.T) {
	scanner, _ := newTestScanner(t)

	stdout, r, w := captureStdout(t)
	execErr := scanner.Execute(context.Background())
	output := restoreStdout(t, stdout, r, w)

	if execErr != nil {
		t.Fatalf("Execute: %v", execErr)
	}
	if output != "" {
		t.Errorf("SDK wrote to stdout by default:\n%s", output)
	}
}

func TestScanner_VerbosePrintsSummary(t *testing.T) {
	scanner, _ := newTestScanner(t, WithVerbose())

	stdout, r, w := captureStdout(t)
	execErr := scanner.Execute(context.Background())
	output := restoreStdout(t, stdout, r, w)

	if execErr != nil {
		t.Fatalf("Execute: %v", execErr)
	}
	if !strings.Contains(output, "afrog scan") {
		t.Errorf("WithVerbose should print a summary, got:\n%s", output)
	}
}

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

func TestScanner_InfoReportsCountsWithoutPrinting(t *testing.T) {
	scanner, _ := newTestScanner(t)

	info := scanner.Info()
	if info.TotalTargets != 1 {
		t.Errorf("TotalTargets = %d, want 1", info.TotalTargets)
	}
	if info.TotalPocs != 1 {
		t.Errorf("TotalPocs = %d, want 1", info.TotalPocs)
	}
	if info.OOBEnabled {
		t.Error("OOBEnabled should be false when OOB is not configured")
	}
}
