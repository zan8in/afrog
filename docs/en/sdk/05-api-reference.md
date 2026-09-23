---
title: API Reference
slug: /docs/sdk/api-reference
lang: en
summary: Common constructors, result accessors, and scan information APIs in the afrog SDK.
status: published
source: docs/zh/sdk/05-api-reference.md
last_reviewed: 2026-09-16
---

This page summarizes the most commonly used SDK methods so you can quickly answer: what are the main entry points, and what scan information can be read back.

## Construction

| Method | Return value |
| --- | --- |
| `New(ctx, options...)` | `*Scanner, error` |
| `NewOptions()` | `*Options` |

### `New`

This is the main constructor for a scanner.

```go
scanner, err := sdk.New(ctx,
  sdk.WithTargets("https://example.com"),
  sdk.WithPocPaths("./pocs"),
)
```

### `NewOptions`

Useful when you want to build a reusable option set first and then pass it around.

## Result access

| Method | Return value |
| --- | --- |
| `Results()` | `[]Result` |
| `ResultCount()` | `int` |
| `HasResults()` | `bool` |
| `OpenPorts()` | `map[string][]int` |
| `Stats()` | `Stats` |
| `Progress()` | `float64` |

### `Results()`

Returns structured results and is the most common integration entry point.

### `ResultCount()` / `HasResults()`

Useful when you only need a quick answer about whether the scan found anything.

### `OpenPorts()`

When port pre-scan is enabled, this returns the discovered open ports.

### `Stats()` / `Progress()`

Useful for summaries, dashboards, and progress display.

## PoCs and scan information

| Method | Return value |
| --- | --- |
| `Pocs()` | `[]poc.Poc` |
| `PocCount()` | `int` |
| `PocDiagnostics()` | `[]config.PocLoadError` |
| `Info()` | `ScanInfo` |
| `OOBStatus()` | `bool, string` |
| `CuratedError()` | `error` |

### `Pocs()` / `PocCount()`

Use these to inspect which PoCs are actually loaded and how many there are.

### `PocDiagnostics()`

When PoCs are skipped, a path is invalid, or YAML loading fails, this is where you inspect the reason.

### `Info()`

Returns overall scan information and is useful for summary views.

### `OOBStatus()`

Checks whether the out-of-band provider is available.

### `CuratedError()`

Returns optional curated-source errors. These usually do not block the main scan.

## Concurrency note

A single scanner instance is concurrency-safe and its methods can be called from multiple goroutines.

However, running multiple scanners in parallel inside the same process is not recommended, because HTTP clients, rate limiters, and probing caches use shared process-level state. Concurrent scanners may overwrite one another's proxy, timeout, or rate settings.

Recommended pattern: reuse scanners sequentially.

```go
for _, group := range targetGroups {
  scanner, _ := sdk.New(ctx, sdk.WithTargets(group...), sdk.WithPocPaths(pocPath))
  if err := scanner.Execute(ctx); err != nil {
    log.Print(err)
  }
  results = append(results, scanner.Results()...)
  scanner.Close()
}
```

## Typical integration snippets

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
```

### Signal handling

```go
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
defer stop()

scanner.Execute(ctx)
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

## Common questions

### Why did built-in PoCs not run when I specified a PoC directory

Usually `WithPocPathsOnly()` was enabled. Remove it if you want built-in PoCs plus your custom directory.

### Why does `Wait` return `context.Canceled`

Usually the scan was stopped by `Stop()` or an external `context` cancellation. You can still inspect partial results through `Results()`.

### Why does memory grow too quickly on large scans

Start with:

```go
sdk.WithRequestResponse(false)
sdk.WithMaxStoredResults(1000)
```

Then combine with handlers or streams so you do not rely entirely on `Results()` accumulating everything in memory.

> **← Previous:** [Config Reference](./04-config-reference.md) ｜ **Handbook home:** [SDK Quickstart](./01-quickstart.md) ｜ **Next →:** [Examples](./06-examples.md)
