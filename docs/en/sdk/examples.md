---
title: Examples
slug: /docs/sdk/examples
lang: en
summary: Runnable afrog SDK examples and the scenarios they are meant to demonstrate.
status: published
source: docs/zh/sdk/examples.md
last_reviewed: 2026-09-16
---

If you have already read [SDK Quickstart](./quickstart.md), the best next step is usually to run an example rather than keep reading concepts.

## Example directory

The repository `examples/` directory already contains multiple runnable programs. By default, they locate the in-repo `pocs/afrog-pocs` tree automatically, and you can override that with the `-pocs` flag when needed.

## Common examples

### Basic scanner

```bash
go run ./examples/basic_scan
```

Useful for:

- the smallest working SDK integration
- understanding `sdk.New + Execute + Results`

### Full output

```bash
go run ./examples/full_output -json
```

Useful for:

- inspecting full request and response data
- seeing how structured results map into JSON

### Async scanner

```bash
go run ./examples/async_scan
```

Useful for:

- learning asynchronous execution
- seeing `Start / Wait / Done` in practice

### Progress scanner

```bash
go run ./examples/progress_scan
```

Useful for:

- displaying scan progress
- understanding progress-related SDK hooks

### OOB scanner

```bash
go run ./examples/oob_scan -oob dnslogcn -oob-domain your.dnslog.cn
```

Useful for:

- out-of-band scanning
- validating OOB configuration

### SDK port scan

```bash
go run ./examples/sdk_portscan -target 127.0.0.1
```

Useful for:

- pre-scanning open ports
- observing `OpenPorts()` behavior

### Vulnerability scan

```bash
go run ./examples/vuln_scan -target https://example.com
```

Useful for:

- a more realistic business-style integration
- consuming vulnerability results in a flow closer to real usage

### Port scan

```bash
go run ./examples/port_scan -targets 127.0.0.1
```

Useful for:

- using the standalone port-scanning capability
- understanding the portscan-focused flow itself

## How to choose an example

General rule:

- want to get something running quickly: `basic_scan`
- want full data visibility: `full_output`
- want asynchronous control: `async_scan`
- want progress display: `progress_scan`
- want OOB coverage: `oob_scan`

## Related pages

- [SDK Quickstart](./quickstart.md)
- [Sync and Async](./sync-and-async.md)
- [API Reference](./api-reference.md)
