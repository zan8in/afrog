<!--
title: Config Reference
slug: /docs/sdk/config-reference
lang: en
summary: Common afrog SDK options, defaults, and configuration boundaries.
status: published
source: docs/zh/sdk/04-config-reference.md
last_reviewed: 2026-09-16
-->

This page summarizes the most commonly used SDK options so you can quickly answer two questions during integration: what to configure, and what the default behavior is.

## Targets

| Option | Description |
| --- | --- |
| `WithTargets(...)` | List of scan targets |
| `WithTargetsFile(path)` | Read targets from a file, one per line |
| `WithCyberspace(cfg)` | Load targets from cyberspace search, currently ZoomEye only |
| `WithTargetPreProbe()` | Concurrent pre-probing of target protocol and liveness, equivalent to CLI `-mt` |

## PoCs

| Option | Description |
| --- | --- |
| `WithPocPaths(...)` | Files, directories, or glob patterns, with append semantics |
| `WithPocPathsOnly()` | Use only explicitly provided PoCs |
| `WithSearch(kw)` | Filter by keyword |
| `WithSeverity(sev)` | Filter by severity |
| `WithExcludePocs(...)` | Exclude specific PoCs |
| `WithExcludePocsFile(path)` | Read exclusions from a file |

## Performance

| Option | Default |
| --- | --- |
| `WithConcurrency(n)` | `25` |
| `WithRateLimit(n)` | `150` |
| `WithTimeout(sec)` | `50` |
| `WithRetries(n)` | `1` |
| `WithMaxHostError(n)` | `3` |
| `WithMaxRespBodySize(mb)` | `2` |
| `WithRequestLimitPerTarget(n)` | `0` |
| `WithPolite()` / `WithBalanced()` / `WithAggressive()` | none |
| `WithAutoRequestLimit()` | none |
| `WithSmartConcurrency()` | none |
| `WithStopOnFirstMatch()` | none |

Important note:

- `WithRequestLimitPerTarget`
- `WithAutoRequestLimit`
- `WithPolite`
- `WithBalanced`
- `WithAggressive`

These single-target throttling strategies are mutually exclusive. Setting more than one will return `ErrInvalidOptions`.

## Fingerprint and probing

| Option | Default |
| --- | --- |
| `WithFingerprintDisabled()` | fingerprinting is enabled by default |
| `WithFingerprintFilterMode(mode)` | `"strict"`, optional `"opportunistic"` |
| `WithWebProbe()` | enabled by default (matching the CLI `-w`); pass `false` to disable |
| `WithWebProbeTimeout(seconds)` | `0`, meaning the engine default (30s); equivalent to `-w-timeout` |
| `WithWebFavicon()` | off by default; equivalent to `-w-favicon`, costing one extra request per target |

## Network

| Option | Description |
| --- | --- |
| `WithProxy(p)` | HTTP or SOCKS5 proxy |
| `WithHeaders(...)` | Custom request headers in `"Name: value"` form |

## Output

| Option | Default |
| --- | --- |
| `WithRequestResponse(b)` | `true` |
| `WithMaxStoredResults(n)` | `0`, meaning unlimited |
| `WithStreamBuffer(n)` | `256` |
| `WithRedactedHeaders(...)` | no redaction by default |
| `WithVerbose()` | quiet by default |

### Redaction guidance

If results may flow into logs, databases, or API responses, enable header redaction:

```go
sdk.WithRedactedHeaders()
sdk.WithRedactedHeaders("authorization", "x-token")
```

Redaction applies to:

- raw request payloads
- raw response payloads
- request header structures
- response header structures

Matched header values are replaced with `[REDACTED]`.

## OOB

Configure out-of-band checks through `WithOOB(cfg)`:

```go
sdk.WithOOB(sdk.OOBOptions{
  Adapter: "ceyeio",
  Key:     "your-ceye-api-token",
  Domain:  "your-subdomain.ceye.io",
})
```

Common adapters and required fields:

| Adapter | Required fields |
| --- | --- |
| `ceyeio` | `Key`, `Domain` |
| `dnslogcn` | `Domain` |
| `alphalog` | `Domain`, `ApiURL` |
| `xray` | `Key`, `Domain`, `ApiURL` |
| `revsuit` | `Key`, `Domain`, `ApiURL`, `HttpURL` |

If you do not pass OOB config explicitly, the SDK tries to read:

```text
~/.config/afrog/afrog-config.yaml
```

The SDK does not create or rewrite this file automatically.

## Port pre-scan

Configure it through `WithPortScan(cfg)`:

```go
sdk.WithPortScan(sdk.PortScanOptions{
  Ports:         "top",
  TimeoutMs:     500,
  SkipDiscovery: true,
})
```

Useful for:

- network-range scanning
- service discovery
- dynamically feeding `host:port` targets into later vulnerability scans

`RateLimit` caps concurrency (how many connections are in flight); `ConnectRateLimit` / `ConnectRateLimitPerHost` cap the connection rate (how many new connections are opened per second, globally and per host). The two are orthogonal: a concurrency cap alone cannot stop hundreds of thousands of connection attempts per second on a low-latency LAN, which fills up the NAT/conntrack session table of the network afrog runs on. Leaving these two fields at `0` keeps the built-in protective default (1000/s global, 100/s per host); a negative value disables the cap.

```go
sdk.WithPortScan(sdk.PortScanOptions{
  Ports:            "top",
  ConnectRateLimit: 200,   // tighten the global rate explicitly
  DisableLinkProbe: true,  // turn the gateway RTT probe off
})
```

`DisableLinkProbe` turns off the periodic gateway RTT measurement taken during the scan, which is used to ease the rate off when the local uplink saturates. It is on by default.

## Task timeout

Request timeout and task timeout are different. Task timeout limits the total runtime of one target plus one PoC:

```go
sdk.WithTaskTimeout(sdk.TaskTimeoutOptions{
  HardSec: 120,
  Smart:   true,
})
```

Meaning:

- `HardSec`: fixed lower-bound style cap
- `Smart`: estimate timeout based on rules, brute usage, sleep, payloads, and similar signals

When both are enabled, the larger value wins. In practice, `HardSec` acts more like a floor guard than a hard override.

## Execution duration monitoring

Equivalent to CLI `-pedm`:

```go
sdk.WithExecutionMonitor(sdk.ExecutionMonitorOptions{
  SlowThresholdSec: 20,
  SummaryTop:       10,
  SummaryBy:        sdk.MonitorSummaryByMax,
}),
sdk.WithMonitorHandler(func(line string) {
  log.Println(line)
})
```

Note:

- monitor output is sent only to `WithMonitorHandler`
- without a handler, monitoring runs but you will not see the output

## Checkpoint and resume

Equivalent to CLI `-resume`:

```go
sdk.WithCheckpoint(sdk.CheckpointOptions{
  Path:         "scan.afg",
  SaveInterval: 10 * time.Second,
})
```

Checkpoints are recorded by target plus PoC id, so the target set and PoC set should stay consistent when resuming.

## Common errors

The most common initialization and runtime errors include:

- `ErrNoTargets`
- `ErrNoPocs`
- `ErrPocPathNotFound`
- `ErrAlreadyRunning`
- `ErrAlreadyFinished`
- `ErrClosed`
- `ErrNotStarted`
- `ErrInvalidOptions`
- `ErrWebhookTokenRequired`

If curated PoC mounting fails, it is treated as an optional error and does not stop the scan. You can inspect it through `scanner.CuratedError()`.

> **← Previous:** [Handlers and Streams](./03-handlers-and-streams.md) ｜ **Handbook home:** [SDK Quickstart](./01-quickstart.md) ｜ **Next →:** [API Reference](./05-api-reference.md)
