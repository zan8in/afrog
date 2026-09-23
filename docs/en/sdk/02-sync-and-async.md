---
title: Sync and Async
slug: /docs/sdk/sync-and-async
lang: en
summary: Synchronous and asynchronous execution patterns for the afrog SDK.
status: published
source: docs/zh/sdk/02-sync-and-async.md
last_reviewed: 2026-09-16
---

`afrog` SDK supports both synchronous and asynchronous execution. Which one to choose depends on whether you want the shortest path to a finished scan or you want to manage progress and scheduling yourself.

## Synchronous execution

The synchronous path is the most direct. `Execute(ctx)` blocks until the scan finishes.

```go
if err := scanner.Execute(ctx); err != nil {
  log.Fatal(err)
}
results := scanner.Results()
```

Useful for:

- command-style batch jobs
- simple backend tasks
- first integrations where the goal is to get a working scan quickly

## Asynchronous execution

If you want to show progress, combine scanning with other work, or manage your own event loop, use:

- `Start(ctx)`
- `Wait(ctx)`
- `Done()`

Example:

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

Useful for:

- live progress display
- running other tasks in parallel
- platform integrations with custom scheduling

## Lifecycle methods

| Method | Description |
| --- | --- |
| `Execute(ctx)` | Run synchronously and return only after completion |
| `Start(ctx)` | Start asynchronously and return immediately |
| `Wait(ctx)` | Block until completion and return the scan error |
| `Done()` | Return a channel that closes when the scan finishes |
| `Err()` | Return the scan error, or `nil` before completion |
| `Stop()` | Request a stop and return immediately |
| `Close()` | Stop scanning, wait for goroutines to exit, and release resources |
| `Pause()` / `Resume()` / `IsPaused()` | Pause control |
| `IsStopping()` / `IsRunning()` | State inspection |

## One-shot behavior

A scanner instance is one-shot:

```go
scanner.Execute(ctx) // first run: ok
scanner.Execute(ctx) // second run: ErrAlreadyFinished
```

If you need another run, create a new `Scanner` instance.

## Recommended `Close()` usage

`Close()` is idempotent, so after `New` succeeds it is usually best to write:

```go
defer scanner.Close()
```

This keeps cleanup reliable for both synchronous and asynchronous paths.

## How to choose

Recommended rule of thumb:

- want the fastest integration path: start with sync
- want progress display, streaming, or platform workflows: move to async

> **← Previous:** [SDK Quickstart](./01-quickstart.md) ｜ **Next →:** [Handlers and Streams](./03-handlers-and-streams.md)
