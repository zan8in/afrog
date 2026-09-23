---
title: SDK Quickstart
slug: /docs/sdk/quickstart
lang: en
summary: The shortest path to embed afrog scanning into a Go program.
status: published
source: docs/zh/sdk/01-quickstart.md
last_reviewed: 2026-09-16
---

`afrog` SDK is designed for embedding scanning capabilities into your own Go applications. For new integrations, the recommended entry point is `pkg/sdk`.

## Package path

Recommended import:

```go
github.com/zan8in/afrog/v3/pkg/sdk
```

If you still use the older root-package API, it can continue to work, but `pkg/sdk` is the better choice for new projects.

## Install

```bash
go get -u github.com/zan8in/afrog/v3
```

## Minimal example

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

This shows the most common integration path:

1. create a `context`
2. construct a scanner
3. provide targets and PoC sources
4. execute the scan
5. read the results

## PoC inputs

`WithPocPaths` supports three common forms and they can be mixed:

```go
sdk.WithPocPaths(
  "/path/to/single.yaml",
  "/path/to/pocs",
  "/path/to/pocs/*.yaml",
)
```

These mean:

- a single file
- a recursively loaded directory
- a glob pattern

## Execution styles

### Synchronous execution

The simplest way:

```go
if err := scanner.Execute(ctx); err != nil {
  log.Fatal(err)
}
results := scanner.Results()
```

### Asynchronous execution

If you want to manage progress, subscribe to state, or integrate your own scheduling loop:

```go
if err := scanner.Start(ctx); err != nil {
  log.Fatal(err)
}

if err := scanner.Wait(ctx); err != nil {
  log.Printf("scan error: %v", err)
}
```

## Reading results

`Results()` returns structured results that are suitable for post-processing or JSON serialization.

```go
for _, r := range scanner.Results() {
  fmt.Printf("%s [%s] %s\n", r.PocID, r.Severity, r.FullTarget)
}
```

If you need fuller request and response details, you can also read `Exchanges` from the result objects.

## Memory control

For larger integrations, these two options are especially useful:

```go
sdk.WithRequestResponse(false)
sdk.WithMaxStoredResults(1000)
```

They mean:

- do not retain full request and response data
- cap the number of stored results in memory

## Common initialization errors

The most common setup errors include:

- `ErrNoTargets`
- `ErrNoPocs`
- `ErrPocPathNotFound`
- `ErrInvalidOptions`

Example:

```go
scanner, err := sdk.New(ctx, opts...)
switch {
case errors.Is(err, sdk.ErrNoTargets):
  log.Fatal("no scan targets provided")
case errors.Is(err, sdk.ErrPocPathNotFound):
  log.Fatal("PoC path cannot be resolved")
case err != nil:
  log.Fatal(err)
}
```

## In this handbook

- [Sync and Async](./02-sync-and-async.md)
- [Handlers and Streams](./03-handlers-and-streams.md)
- [Configuration Reference](./04-config-reference.md)
- [API Reference](./05-api-reference.md)
- [Examples](./06-examples.md)
- [FAQ](./07-faq.md)

> **← Docs home:** [afrog Docs](../index.md) ｜ **Next →:** [Sync and Async](./02-sync-and-async.md)
