<!--
title: FAQ
slug: /docs/sdk/faq
lang: en
summary: Common afrog SDK integration questions and practical guidance.
status: published
source: docs/zh/sdk/07-faq.md
last_reviewed: 2026-09-16
-->

This page collects the questions that appear most often during `afrog` SDK integration.

## Why did built-in PoCs not run when I specified a PoC directory

The most common reason is:

```go
WithPocPathsOnly()
```

Its meaning is "use only the explicitly provided PoCs", so built-in PoCs are not merged in. Remove this option if you want your local PoCs plus the built-in set.

## Why does the scan appear stuck

First check whether you subscribed to a stream but never consumed it.

The SDK blocks instead of silently dropping results when a stream buffer is full. If you subscribe to a stream and nobody reads from it, the scan can block on your side.

## Why does `Wait` return `context.Canceled`

Usually one of these happened:

- `Stop()` was called
- the outer `context` was canceled
- an interrupt signal was received

This does not mean all results are lost. You can still inspect completed partial results through `Results()`.

## Why does memory grow too fast on large scans

Start with:

```go
sdk.WithRequestResponse(false)
sdk.WithMaxStoredResults(1000)
```

Also consider:

- writing to storage through handlers
- consuming results through streams
- not relying only on `Results()` to keep everything in memory

## When should I use sync vs async

Practical rule of thumb:

- simple jobs and batch runs: start with sync
- progress display, streaming consumption, or platform integration: use async

## Can multiple scanners run in parallel

Running multiple scanner instances in the same process is not recommended because some network-related state is shared process-wide and can overwrite proxy, timeout, or rate settings.

A safer pattern is sequential execution inside one process, or external process-level orchestration.

> **← Previous:** [Examples](./06-examples.md) ｜ **Handbook home:** [SDK Quickstart](./01-quickstart.md) ｜ **Docs home →:** [afrog Docs](../index.md)
