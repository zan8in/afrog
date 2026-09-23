---
title: Handlers and Streams
slug: /docs/sdk/handlers-and-streams
lang: en
summary: Event handlers, stream subscriptions, and consumption guidance for the afrog SDK.
status: published
source: docs/zh/sdk/03-handlers-and-streams.md
last_reviewed: 2026-09-16
---

If you want results during the scan rather than only after completion, the `afrog` SDK gives you two main mechanisms:

- handlers
- streams

## Handlers

Handlers are useful when scan events should flow directly into business logic such as persistence, alerts, or statistics.

Example:

```go
scanner, _ := sdk.New(ctx,
  sdk.WithResultHandler(saveToDatabase),
  sdk.WithResultHandler(sendAlert),
  sdk.WithFailureHandler(func(f sdk.Failure) {
    log.Printf("PoC %s failed on %s: %v", f.PocID, f.Target, f.Err)
  }),
  sdk.WithPortHandler(func(p sdk.PortEvent) { /* ... */ }),
  sdk.WithHostHandler(func(h sdk.HostEvent) { /* ... */ }),
  sdk.WithWebProbeHandler(func(w sdk.WebProbeEvent) { /* ... */ }),
  sdk.WithProgressHandler(func(p sdk.PhaseProgress) { /* ... */ }),
  sdk.WithScanInfoHandler(func(i sdk.ScanInfo) { /* ... */ }),
)
```

Key points:

- you can register multiple handlers of the same type
- handlers are triggered concurrently by scan goroutines
- your own handler implementation must be concurrency-safe

## Streams

Streams are useful when you want to consume channels yourself, for example:

- WebSocket delivery
- real-time frontend dashboards
- custom queues or workers

Example:

```go
results := scanner.ResultStream()

scanner.Start(ctx)

go func() {
  for r := range results {
    fmt.Println(r.PocID, r.FullTarget)
  }
}()

scanner.Wait(ctx)
```

## Available stream subscriptions

| Method | Event type |
| --- | --- |
| `ResultStream()` | `Result` |
| `PortStream()` | `PortEvent` |
| `HostStream()` | `HostEvent` |
| `WebProbeStream()` | `WebProbeEvent` |
| `ProgressStream()` | `PhaseProgress` |
| `ScanInfoStream()` | `ScanInfo` |

## The most important rule with streams

Once you subscribe, you must consume.

The SDK blocks instead of silently dropping events when a channel buffer fills up. So if:

- you subscribe to a stream
- but nobody is reading it

the scan can block itself.

Canceling the `context` or calling `Stop()` can release that kind of blockage.

## Best time to subscribe

Subscribe before `Start(ctx)` whenever possible:

```go
results := scanner.ResultStream()
progress := scanner.ProgressStream()
```

That avoids missing early events.

## What if you subscribe after the scan has already finished

If you subscribe after completion, you get a closed channel. A `range` loop exits immediately, without deadlock.

## Advanced: raw engine results

If structured `Result` objects are not enough, you can subscribe to the underlying engine result type:

```go
sdk.WithRawResultHandler(func(r *result.Result) {
  _ = persist(r)
})
```

Important notes:

- `result.Result` is an internal type
- it is outside the stable SDK compatibility contract
- prefer `WithResultHandler` whenever the structured result is sufficient

## How to choose

General rule:

- want direct side effects: use handlers
- want explicit control over consumption pace: use streams
- want stable output contracts: prefer structured `Result`
- want lower-level internals: consider raw results only then

> **← Previous:** [Sync and Async](./02-sync-and-async.md) ｜ **Handbook home:** [SDK Quickstart](./01-quickstart.md) ｜ **Next →:** [Config Reference](./04-config-reference.md)
