# Afrog SDK Usage Guide

## Overview

The Afrog SDK is the Go API for embedding vulnerability scanning into your own programs. The import path is `github.com/zan8in/afrog/v3/pkg/sdk`.

### Key features

- **Structured results** — plain Go structs that can be passed straight to `json.Marshal`
- **Complete data output** — the raw request and response of every scan step is available
- **Flexible PoC input** — single files, directories (searched recursively) and glob patterns
- **Synchronous and asynchronous** — `Execute` blocks; `Start` plus `Wait`/`Done` runs in the background
- **Handlers and streams** — register multiple callbacks, or subscribe to event channels on demand
- **Silent by default** — nothing is written to stdout or stderr
- **Typed errors** — failures are matched with `errors.Is`
- **Deterministic cleanup** — `Close` releases every background goroutine

### Two APIs, one implementation

| Package | Entry point | Use for |
|---|---|---|
| `github.com/zan8in/afrog/v3/pkg/sdk` | `sdk.New(ctx, opts...)` | New code. This guide covers it. |
| `github.com/zan8in/afrog/v3` | `afrog.NewSDKScanner(opts)` | Existing integrations, unchanged |

The root package is a compatibility facade that delegates to `pkg/sdk`, so **the fixes and features described here reach both APIs**. Existing code needs no changes:

```go
options := afrog.NewSDKOptions()
options.Targets = []string{"https://example.com"}
options.PocFile = pocPath
options.Concurrency = 10

scanner, err := afrog.NewSDKScanner(options)
if err != nil {
	log.Fatal(err)
}
defer scanner.Close()

scanner.OnResult = func(r *result.Result) {
	log.Printf("found: %s", r.PocInfo.Id)
}
if err := scanner.Run(); err != nil {
	log.Fatal(err)
}
results := scanner.GetResults()
```

`SDKOptions` gained optional fields that expose the newer capabilities to the old style: `PocPaths`/`PocPathsOnly` (globs and append semantics), `ResumeFile`, `TaskHardTimeoutSec`/`TaskSmartTimeout`, `Cyberspace`/`Query`/`QueryCount`, `MonitorTargets`, `OOBPollInterval`/`OOBHitRetention`, `MaxStoredResults`, `RedactedHeaders`, `OnFailure` and `Silent`. Leaving them zero reproduces the previous behaviour exactly.

To migrate gradually, `scanner.Scanner()` returns the underlying `*sdk.Scanner`, giving access to the streams and diagnostics of the current API.

One old behaviour was corrected: setting `PocFile` and `AppendPoc` together used to drop `AppendPoc` silently; both are now loaded.

## Installation

```bash
go get -u github.com/zan8in/afrog/v3
```

## Quick start

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/zan8in/afrog/v3/pkg/sdk"
)

func main() {
	ctx := context.Background()

	scanner, err := sdk.New(ctx,
		sdk.WithTargets("https://example.com"),
		sdk.WithPocPaths("./pocs/afrog-pocs"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer scanner.Close()

	if err := scanner.Execute(ctx); err != nil {
		log.Fatal(err)
	}

	for _, r := range scanner.Results() {
		fmt.Printf("[%s] %s - %s\n", r.Severity, r.FullTarget, r.PocName)
	}
}
```

## PoC input

`WithPocPaths` accepts three forms, which can be mixed and repeated:

```go
sdk.WithPocPaths(
	"/path/to/single.yaml",   // a single file
	"/path/to/pocs",          // a directory, searched recursively
	"/path/to/pocs/*.yaml",   // a glob pattern
)
```

### Append or exclusive

| Configuration | Behaviour |
|---------------|-----------|
| `WithPocPaths(...)` | **Append**: merged with the built-in, curated, my and local PoCs; explicit paths win on name conflicts |
| `WithPocPaths(...)` + `WithPocPathsOnly()` | **Exclusive**: only the listed PoCs are used |

### Inspecting what was loaded

You can verify the PoC selection before any network traffic:

```go
fmt.Printf("loaded %d pocs\n", scanner.PocCount())

for _, p := range scanner.Pocs() {
	fmt.Println(p.Id, p.Info.Name)
}

// Which PoCs were skipped, and why
for _, d := range scanner.PocDiagnostics() {
	fmt.Printf("skipped %s: %s\n", d.Path, d.Reason)
}
```

| `PocLoadError.Reason` | Meaning |
|-----------------------|---------|
| `config.PocLoadNotFound` | Path does not exist, or the glob matched nothing |
| `config.PocLoadReadFailed` | The file could not be read |
| `config.PocLoadParseFailed` | YAML parsing failed |
| `config.PocLoadLegacyOOB` | The PoC uses the deprecated v2 OOB syntax |

## Complete data output

`Results()` returns `sdk.Result` values whose `Exchanges` carry the full request and response of every step:

```go
for _, r := range scanner.Results() {
	fmt.Printf("%s [%s] %s\n", r.PocID, r.Severity, r.FullTarget)

	for _, ex := range r.Exchanges {
		fmt.Printf("%s %s -> %d (%d ms)\n", ex.Method, ex.URL, ex.StatusCode, ex.LatencyMs)

		fmt.Println("--- raw request ---")
		fmt.Println(ex.Request)

		fmt.Println("--- raw response ---")
		fmt.Println(ex.Response)

		if ex.BodyTruncated {
			fmt.Println("warning: response body was truncated at MaxRespBodySize")
		}
	}
}
```

### Result

```go
type Result struct {
	PocID       string   `json:"poc_id"`
	PocName     string   `json:"poc_name,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Author      string   `json:"author,omitempty"`
	Description string   `json:"description,omitempty"`
	Reference   []string `json:"reference,omitempty"`
	Tags        []string `json:"tags,omitempty"`

	CveID       string  `json:"cve_id,omitempty"`
	CweID       string  `json:"cwe_id,omitempty"`
	CvssScore   float64 `json:"cvss_score,omitempty"`
	CvssMetrics string  `json:"cvss_metrics,omitempty"`

	Target     string `json:"target"`
	FullTarget string `json:"full_target,omitempty"`

	Extractors   map[string]string `json:"extractors,omitempty"`
	Fingerprints []Fingerprint     `json:"fingerprints,omitempty"`
	Exchanges    []Exchange        `json:"exchanges,omitempty"`

	FoundAt time.Time `json:"found_at"`
}
```

### Exchange

```go
type Exchange struct {
	Request  string `json:"request,omitempty"`  // raw request
	Response string `json:"response,omitempty"` // raw response

	Method          string            `json:"method,omitempty"`
	URL             string            `json:"url,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	RequestBody     string            `json:"request_body,omitempty"`
	StatusCode      int               `json:"status_code,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
	ContentType     string            `json:"content_type,omitempty"`
	LatencyMs       int64             `json:"latency_ms,omitempty"`

	Matched        bool `json:"matched"`
	BodyTruncated  bool `json:"body_truncated,omitempty"`
	BruteTruncated bool `json:"brute_truncated,omitempty"`
	BruteRequests  int  `json:"brute_requests,omitempty"`
}
```

Raw messages are strings rather than `[]byte`, so they serialise as readable text instead of base64:

```go
data, err := json.MarshalIndent(scanner.Results(), "", "  ")
```

### Controlling memory usage

```go
sdk.WithRequestResponse(false),   // do not retain Exchanges
sdk.WithMaxStoredResults(1000),   // accumulate at most 1000 results
```

`MaxStoredResults` only bounds internal accumulation. Handlers and streams still receive **every** result.

### Response body truncation

The response body limit is `MaxRespBodySize` (2 MB by default). Anything beyond it is discarded and `Exchange.BodyTruncated` is set, so a truncated response is distinguishable from a complete one.

```go
sdk.WithMaxRespBodySize(10) // raise to 10 MB
```

## Synchronous and asynchronous execution

### Synchronous

```go
if err := scanner.Execute(ctx); err != nil {
	log.Fatal(err)
}
results := scanner.Results()
```

### Asynchronous

```go
if err := scanner.Start(ctx); err != nil {
	log.Fatal(err)
}

go func() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			fmt.Printf("progress: %.1f%%\n", scanner.Progress())
		case <-scanner.Done():
			return
		}
	}
}()

if err := scanner.Wait(ctx); err != nil {
	log.Printf("scan error: %v", err)
}
```

### Lifecycle methods

| Method | Description |
|--------|-------------|
| `Execute(ctx)` | Runs synchronously until the scan finishes |
| `Start(ctx)` | Starts asynchronously and returns immediately |
| `Wait(ctx)` | Blocks until the scan finishes and returns its error |
| `Done()` | Channel closed when the scan finishes |
| `Err()` | The scan error, or nil while still running |
| `Stop()` | Requests a stop and returns immediately |
| `Close()` | Stops the scan, waits for goroutines to exit, releases resources |
| `Pause()` / `Resume()` / `IsPaused()` | Pause control |
| `IsStopping()` / `IsRunning()` | State queries |

A scanner is single-use:

```go
scanner.Execute(ctx) // first call: fine
scanner.Execute(ctx) // second call: ErrAlreadyFinished
```

Create a new scanner to scan again. `Close` is idempotent and safe to defer immediately after `New`.

## Handlers and streams

### Handlers

```go
scanner, _ := sdk.New(ctx,
	sdk.WithResultHandler(saveToDatabase),
	sdk.WithResultHandler(sendAlert),        // may be registered several times
	sdk.WithFailureHandler(func(f sdk.Failure) {
		log.Printf("poc %s failed on %s: %v", f.PocID, f.Target, f.Err)
	}),
	sdk.WithPortHandler(func(p sdk.PortEvent) { /* ... */ }),
	sdk.WithHostHandler(func(h sdk.HostEvent) { /* ... */ }),
	sdk.WithWebProbeHandler(func(w sdk.WebProbeEvent) { /* ... */ }),
	sdk.WithProgressHandler(func(p sdk.PhaseProgress) { /* ... */ }),
	sdk.WithScanInfoHandler(func(i sdk.ScanInfo) { /* ... */ }),
)
```

Handlers are invoked **concurrently** from scan workers, so implementations must synchronise their own state.

### Streams

Streams are subscription-based: **nothing is published until the subscribe method is first called**, so an unused stream costs nothing and can never stall the scan.

```go
results := scanner.ResultStream() // subscribe before Start

scanner.Start(ctx)

go func() {
	for r := range results {   // the channel closes when the scan finishes
		fmt.Println(r.PocID, r.FullTarget)
	}
}()

scanner.Wait(ctx)
```

| Method | Event type |
|--------|-----------|
| `ResultStream()` | `Result` |
| `PortStream()` | `PortEvent` |
| `HostStream()` | `HostEvent` |
| `WebProbeStream()` | `WebProbeEvent` |
| `ProgressStream()` | `PhaseProgress` |
| `ScanInfoStream()` | `ScanInfo` |

> **Important**: once subscribed, a stream must be consumed. So that findings are never silently dropped, sends **block** when the buffer fills rather than discarding data. Cancelling the context or calling `Stop` releases any blocked send.
>
> Subscribing after the scan has finished yields an already-closed channel, so a range loop terminates immediately instead of deadlocking.

### Advanced: the engine's own result type

When you need fields the stable `Result` does not expose, such as persisting the internal structure:

```go
sdk.WithRawResultHandler(func(r *result.Result) {
	_ = persist(r)
})
```

`result.Result` is an internal type whose shape is not covered by the SDK's stability guarantee. Prefer `WithResultHandler`.

## Error handling

```go
scanner, err := sdk.New(ctx, opts...)
switch {
case errors.Is(err, sdk.ErrNoTargets):
	log.Fatal("no targets specified")
case errors.Is(err, sdk.ErrPocPathNotFound):
	log.Fatal("poc path could not be resolved")
case errors.Is(err, sdk.ErrInvalidOptions):
	log.Fatal("invalid options")
case err != nil:
	log.Fatal(err)
}
```

| Error | Meaning |
|-------|---------|
| `ErrNoTargets` | No scan targets specified |
| `ErrNoPocs` | No executable PoCs |
| `ErrPocPathNotFound` | PoC path resolved to no files |
| `ErrAlreadyRunning` | A scan is already in progress |
| `ErrAlreadyFinished` | The scan finished; the scanner cannot be reused |
| `ErrClosed` | The scanner has been closed |
| `ErrNotStarted` | The scan has not been started |
| `ErrInvalidOptions` | Invalid option combination |
| `ErrWebhookTokenRequired` | A webhook was enabled without a token |

`CuratedMountError` reports that the optional curated PoC source failed to mount. It is **not fatal**: the scan continues, and the error is available from `scanner.CuratedError()`.

## Port pre-scanning

Open ports discovered before the PoC scan are appended to the target set as `host:port`:

```go
scanner, _ := sdk.New(ctx,
	sdk.WithTargets("192.168.1.0/24"),
	sdk.WithPocPaths(pocPath),
	sdk.WithPortScan(sdk.PortScanOptions{
		Ports:         "top",  // top|full|all|80,443|1-1024
		TimeoutMs:     500,
		SkipDiscovery: true,
	}),
	sdk.WithPortHandler(func(p sdk.PortEvent) {
		fmt.Printf("open: %s:%d\n", p.Host, p.Port)
	}),
)

scanner.Execute(ctx)

open := scanner.OpenPorts() // map[string][]int
```

## OOB (out-of-band) detection

```go
scanner, _ := sdk.New(ctx,
	sdk.WithTargets(target),
	sdk.WithPocPaths(pocPath),
	sdk.WithOOB(sdk.OOBOptions{
		Adapter: "ceyeio",
		Key:     "your-ceye-api-token",
		Domain:  "your-subdomain.ceye.io",
	}),
)

// Note: this performs a live probe against the OOB service
if enabled, status := scanner.OOBStatus(); !enabled {
	log.Printf("OOB unavailable: %s", status)
}
```

| Adapter | Required fields |
|---------|-----------------|
| `ceyeio` | `Key`, `Domain` |
| `dnslogcn` | `Domain` |
| `alphalog` | `Domain`, `ApiURL` |
| `xray` | `Key`, `Domain`, `ApiURL` |
| `revsuit` | `Key`, `Domain`, `ApiURL`, `HttpURL` |

When not configured explicitly, the SDK reads `~/.config/afrog/afrog-config.yaml`. The file is only ever read — the SDK never creates or rewrites it.

`OOBOptions` also tunes the polling cadence. The defaults match the CLI:

| Field | Default | Description |
|-------|---------|-------------|
| `PollInterval` | `2` | Seconds between polls of the OOB service |
| `HitRetention` | `10` | Minutes a recorded hit stays available |
| `RateLimit` | `25` | Rate limit for the OOB stage |
| `Concurrency` | `25` | Concurrency for the OOB stage |
| `FinalizeTimeout` | `-1` | Seconds to wait for late callbacks; `-1` lets each PoC decide |

### v3 OOB PoC syntax

```yaml
rules:
  r0:
    request:
      method: GET
      path: /?dns=ping%20{{oob.DNS}}
    expression: oobCheck(oob.ProtocolDNS, 5)
expression: r0()
```

The v2 forms `set: oob: oob()`, `{{oobDNS}}`, `oobWait(...)` and `oobCheck(oob, ...)` are deprecated. PoCs using them are skipped and reported through `PocDiagnostics()`.

## Console output

The SDK is **completely silent** by default. For a summary, use the structured API:

```go
info := scanner.Info()
log.Printf("%d targets, %d pocs, %d tasks",
	info.TotalTargets, info.TotalPocs, info.TotalScans)
```

Or opt into printing with `sdk.WithVerbose()`.

## Per-task timeout

`WithTimeout` bounds a single request, but a PoC with many rules can occupy a worker for far longer than any one request. `WithTaskTimeout` bounds the whole target+PoC task:

```go
sdk.WithTaskTimeout(sdk.TaskTimeoutOptions{
	HardSec: 120,  // fixed ceiling in seconds, 0 disables
	Smart:   true, // derive the ceiling from the PoC's content
})
```

`Smart` estimates the ceiling from rule count, sleeps, brute force and payloads. When both are set the **larger** value wins, so `HardSec` acts as a floor rather than an override.

The estimate is capped per protocol family, with the same defaults as the CLI: `VisibleCapSec` 300 (plain HTTP), `NetCapSec` 360 (tcp/udp/ssl), `GoCapSec` 420 (go PoCs).

## Execution monitor

The SDK equivalent of the CLI's `-pedm`, for finding slow or stuck PoCs:

```go
sdk.WithExecutionMonitor(sdk.ExecutionMonitorOptions{
	SlowThresholdSec: 20, // seconds after which a task counts as slow
	SummaryTop:       10, // report the N slowest PoCs at the end
	SummaryBy:        sdk.MonitorSummaryByMax, // or MonitorSummaryByAvg
}),
sdk.WithMonitorHandler(func(line string) {
	log.Println(line)
}),
```

Reports go only to the handlers registered with `WithMonitorHandler`; the SDK never writes them to the console. **Without a handler the monitor still runs but its output goes nowhere**, so use the two options together.

## Resuming a scan

The SDK equivalent of the CLI's `-resume`. The checkpoint is read at startup to skip finished work, and rewritten periodically while the scan runs:

```go
sdk.WithCheckpoint(sdk.CheckpointOptions{
	Path:         "scan.afg",
	SaveInterval: 10 * time.Second, // 0 uses the 10s default
})
```

Progress is keyed by PoC id and target, so **the target and PoC sets must be unchanged** between runs or the skip mapping will not line up. A missing file is treated as a fresh scan rather than an error.

Do not confuse this with `Scanner.Resume()`, which lifts a `Pause()`.

## Sourcing targets from a search engine

The SDK equivalent of the CLI's `-cs` / `-q` / `-qc`. Targets can come entirely from the search, with no `WithTargets` at all:

```go
scanner, _ := sdk.New(ctx,
	sdk.WithCyberspace(sdk.CyberspaceOptions{
		Engine: sdk.CyberspaceZoomEye,
		Query:  `app:"tomcat"`,
		Count:  100,
	}),
	sdk.WithPocPaths(pocPath),
)
```

Only **ZoomEye** is implemented; any other engine name returns `ErrInvalidOptions`. The API key is read from `cyberspace.zoom_eyes` in the configuration file, and `sdk.New` fails when it is missing. A search that matches nothing returns `ErrNoTargets`.

## Target pre-probe

The SDK equivalent of the CLI's `-mt`. It probes each target's protocol and liveness in parallel with the scan, blacklisting hosts that exceed `MaxHostError`:

```go
sdk.WithTargetPreProbe()
```

Despite the CLI flag being named monitor-targets, it does **not** watch the targets file for changes.

## Configuration reference

### Targets

| Option | Description |
|--------|-------------|
| `WithTargets(...)` | Targets to scan |
| `WithTargetsFile(path)` | File with one target per line |
| `WithCyberspace(cfg)` | Source targets from a search engine (ZoomEye only) |
| `WithTargetPreProbe()` | Probe target protocol and liveness in parallel (CLI `-mt`) |

### PoC

| Option | Description |
|--------|-------------|
| `WithPocPaths(...)` | File/directory/glob, append semantics |
| `WithPocPathsOnly()` | Use only the explicit PoCs |
| `WithSearch(kw)` | Keyword filter |
| `WithSeverity(sev)` | Severity filter |
| `WithExcludePocs(...)` | Exclude specific PoCs |
| `WithExcludePocsFile(path)` | Exclusion list file |

### Performance

| Option | Default |
|--------|---------|
| `WithConcurrency(n)` | `25` |
| `WithRateLimit(n)` | `150` |
| `WithTimeout(sec)` | `50` |
| `WithRetries(n)` | `1` |
| `WithMaxHostError(n)` | `3` |
| `WithMaxRespBodySize(mb)` | `2` |
| `WithRequestLimitPerTarget(n)` | `0` |
| `WithPolite()` / `WithBalanced()` / `WithAggressive()` | — |
| `WithAutoRequestLimit()` | — |
| `WithSmartConcurrency()` | — |
| `WithStopOnFirstMatch()` | — |

`WithRequestLimitPerTarget`, `WithAutoRequestLimit`, `WithPolite`, `WithBalanced` and `WithAggressive` are mutually exclusive; setting more than one returns `ErrInvalidOptions`.

### Fingerprinting and probing

| Option | Default |
|--------|---------|
| `WithFingerprintDisabled()` | Fingerprinting is on by default |
| `WithFingerprintFilterMode(mode)` | `"strict"` (or `"opportunistic"`) |
| `WithWebProbe()` | Off by default |

### Network

| Option | Description |
|--------|-------------|
| `WithProxy(p)` | HTTP/SOCKS5 proxy |
| `WithHeaders(...)` | Custom headers in `"Name: value"` form |

### Output

| Option | Default |
|--------|---------|
| `WithRequestResponse(b)` | `true` |
| `WithMaxStoredResults(n)` | `0` (unlimited) |
| `WithStreamBuffer(n)` | `256` |
| `WithRedactedHeaders(...)` | No redaction |
| `WithVerbose()` | Silent by default |

### Redacting sensitive data

`Exchange` carries the full raw request and response by default, which may
include credentials such as `Authorization`, `Cookie` and `Set-Cookie`. Enable
redaction whenever results are logged, persisted or returned over an API:

```go
sdk.WithRedactedHeaders()                            // mask the default credential headers
sdk.WithRedactedHeaders("authorization", "x-token")  // mask a custom set
```

Redaction masks the value to `[REDACTED]` in both the raw `Exchange.Request` /
`Response` and the `RequestHeaders` / `ResponseHeaders` maps, touching only
headers and never the body. It is opt-in because the raw messages are the point
of `Exchange`, and masking everything by default would weaken debugging.

### Other

| Option | Description |
|--------|-------------|
| `WithOOB(cfg)` | Out-of-band detection |
| `WithPortScan(cfg)` | Port pre-scan |
| `WithCurated(cfg)` | Curated PoC source |
| `WithTaskTimeout(cfg)` | Ceiling for a single target+PoC task |
| `WithExecutionMonitor(cfg)` | PoC execution duration monitor (CLI `-pedm`) |
| `WithMonitorHandler(fn)` | Receive execution monitor reports |
| `WithCheckpoint(cfg)` | Resume an interrupted scan (CLI `-resume`) |
| `WithDingtalk()` / `WithWecom()` | Webhook notifications |
| `WithOptions(o)` | Use a fully populated `Options` |

## API reference

### Construction

| Method | Returns |
|--------|---------|
| `New(ctx, options...)` | `*Scanner, error` |
| `NewOptions()` | `*Options` |

### Results

| Method | Returns |
|--------|---------|
| `Results()` | `[]Result` |
| `ResultCount()` | `int` |
| `HasResults()` | `bool` |
| `OpenPorts()` | `map[string][]int` |
| `Stats()` | `Stats` |
| `Progress()` | `float64` |

### PoCs and information

| Method | Returns |
|--------|---------|
| `Pocs()` | `[]poc.Poc` |
| `PocCount()` | `int` |
| `PocDiagnostics()` | `[]config.PocLoadError` |
| `Info()` | `ScanInfo` |
| `OOBStatus()` | `bool, string` |
| `CuratedError()` | `error` |

## Concurrency

**A single scanner instance is safe for concurrent use** — its methods may be called from multiple goroutines.

**Running several scanners concurrently in one process is not supported.** The HTTP client, rate limiter and protocol probe cache are process-global, so concurrent scanners overwrite each other's proxy, timeout and rate-limit settings.

```go
// Correct: sequential reuse
for _, group := range targetGroups {
	scanner, _ := sdk.New(ctx, sdk.WithTargets(group...), sdk.WithPocPaths(pocPath))
	if err := scanner.Execute(ctx); err != nil {
		log.Print(err)
	}
	results = append(results, scanner.Results()...)
	scanner.Close()
}
```

## Integration examples

### CI security gate

```go
scanner, err := sdk.New(ctx,
	sdk.WithTargetsFile("staging-urls.txt"),
	sdk.WithPocPaths("/security/pocs"),
	sdk.WithSeverity("high,critical"),
)
if err != nil {
	log.Fatal(err)
}
defer scanner.Close()

if err := scanner.Execute(ctx); err != nil {
	log.Fatal(err)
}

if results := scanner.Results(); len(results) > 0 {
	for _, v := range results {
		fmt.Printf("- [%s] %s: %s\n", v.Severity, v.FullTarget, v.PocName)
	}
	os.Exit(1)
}
```

### Timeout control

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
defer cancel()

if err := scanner.Execute(ctx); err != nil {
	if errors.Is(err, context.DeadlineExceeded) {
		log.Println("scan timed out")
	}
}

results := scanner.Results() // partial results remain available
```

### Signal handling

```go
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
defer stop()

scanner.Execute(ctx) // Ctrl+C stops the scan and returns context.Canceled
```

### Web service integration

```go
func scanHandler(w http.ResponseWriter, r *http.Request) {
	scanner, err := sdk.New(r.Context(),
		sdk.WithTargets(r.URL.Query().Get("target")),
		sdk.WithPocPaths(os.Getenv("POC_PATH")),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer scanner.Close()

	if err := scanner.Execute(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(scanner.Results())
}
```

## Examples

Every program under `examples/` runs as-is. PoC paths resolve to the repository's `pocs/afrog-pocs` automatically and can be overridden with `-pocs`:

```bash
go run ./examples/basic_scan
go run ./examples/full_output -json
go run ./examples/async_scan
go run ./examples/progress_scan
go run ./examples/oob_scan -oob dnslogcn -oob-domain your.dnslog.cn
go run ./examples/sdk_portscan -target 127.0.0.1
go run ./examples/vuln_scan -target https://example.com
go run ./examples/port_scan -targets 127.0.0.1
```

## FAQ

### I set a PoC directory — why didn't the built-in PoCs run?

You probably added `WithPocPathsOnly()`. Remove it to merge with the built-in PoCs.

### The scan appears to hang

Check whether a stream was subscribed to but is not being consumed. A subscribed stream blocks the scan once its buffer fills, so that findings are not dropped.

### Why does `Wait` return `context.Canceled`?

The scan was cancelled by `Stop` or by the parent context. Results discovered so far are still available from `Results()`.

### Memory grows quickly on large scans

```go
sdk.WithRequestResponse(false),
sdk.WithMaxStoredResults(1000),
```

Process results in a handler instead of relying on `Results()` to accumulate them.

## License

MIT License
