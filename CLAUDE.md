# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

afrog is a high-performance vulnerability scanner written in Go (1.24). It uses YAML-based PoC definitions to scan targets for CVEs, default passwords, information disclosure, fingerprint identification, and other vulnerability types.

**Module**: `github.com/zan8in/afrog/v3`

## Environment

Go 1.24.1 is installed at `C:\Go`. GOPROXY is set to `https://goproxy.cn,direct` for faster downloads in China. Environment variables are in `~/.bashrc`.

```bash
go build -o afrog.exe cmd/afrog/main.go   # build binary
go build ./...                             # check all packages compile
go vet ./...                               # static analysis
go test ./...                              # run all tests
go test -v -run TestX ./pkg/runner/        # run specific test
go test -count=1 ./pkg/fingerprint/        # run tests without cache
```

## Architecture

### Scan flow

```
CLI (cmd/afrog/main.go)
  -> config.NewOptions()                    -- parse flags, load afrog-config.yaml
  -> curated service mount                  -- fetch encrypted curated PoC set
  -> runner.NewRunner(options)              -- build scan engine
    -> options.CreatePocList()              -- load PoCs (curated > my > append > local > builtin)
    -> FingerprintPoCs() / ReversePoCs()    -- classify PoC types
    -> runner.initOOB(reversePocs)          -- OOB adapter + manager setup (oob_coordinator.go)
    -> PortScan (optional)                  -- discover open ports -> append to targets
    -> webProbe (optional)                  -- discover live web services (webprobe.go)
    -> runFingerprintStage                  -- fingerprint PoCs (stage_fingerprint.go)
    -> runVulnStage (x2: non-OOB + OOB)     -- main vulnerability scan
      -> for each target+Poc pair:
          checker.Check()                  -- validate via CEL expression evaluation
            -> executor.Execute()           -- send HTTP/RawHTTP/TCP/UDP request
            -> CEL program against response
      -> result collection                  -- HTML report, JSON output, webhooks
```

### Key packages

| Package | Role |
|---------|------|
| `pkg/config` | CLI flags (`options.go`), config file (`config.go`), `ContainsOOBToken`/`PocUsesOOB` (exported for runner reuse), `ApplyDefaults()`/`ValidateRateLimitModes()`/`TargetStrings()` helpers, version/banner, update mechanism |
| `pkg/runner` | Core engine split across files: `engine.go` (Execute orchestrator, Engine struct, CheckerPool), `context.go` (runtime callbacks via `ScanContext`), `errors.go` (error severity: Suppressed/Retryable/Fatal), `webprobe.go`, `stage_fingerprint.go`, `pedm.go` (PoC execution duration monitor), `filter.go` (fingerprint filtering), `oob_coordinator.go` (OOB init + status), `checker.go` (per-target PoC validation), `executor.go` (protocol dispatch), `celcompile.go`/`celprogram.go`/`cel.go` (CEL compilation + runtime) |
| `pkg/poc` | PoC YAML struct definitions (Xray-style). `Poc.IsNetOnly()` identifies TCP/UDP-only PoCs. Constants: `HTTP_Type`, `TCP_Type`, `GO_Type`, etc. |
| `pkg/pocsrepo` | Multi-source PoC repository with priority ordering |
| `pkg/protocols` | `http/retryhttpclient` (HTTP with retry), `raw` (raw HTTP), `netxclient` (TCP/UDP multi-step sessions), `gox` (specialized exploits: SMB, MySQL, Redis, FTP, etc.) |
| `pkg/proto` | Protobuf `Request`/`Response` types used across all protocol handlers |
| `pkg/targets` | `TargetIndex` -- normalizes input targets into URL/hostPort/host categories |
| `pkg/result` | `Result` and `PocResult` data models for scan findings |
| `pkg/report` | HTML vulnerability report generation |
| `pkg/fingerprint` | Fingerprint matching engine + `Executor` interface |
| `pkg/portscan` | Pre-scan port discovery |
| `pkg/curated` | Encrypted curated PoC mount/update service |
| `pkg/web` | Web UI + SQLite-backed persistent vulnerability storage |
| `pkg/webhook` | Dingtalk and WeChat Work notification integrations |
| `afrog.go` | Public SDK (`SDKScanner`). Uses `runner.NewRunner(options, runner.WithSDKMode())`. `sendOrDrop[T]()` for non-blocking channel sends (6 call sites). |

### PoC execution model

PoCs are YAML files following a format similar to Xray PoC v2:

- **`rules`**: ordered list; each rule has `request` (method/path/headers/body or raw), `expression`/`expressions` (CEL for response validation), and `output` (variable bindings to subsequent rules)
- **Rule chaining**: `STOP_IF_FIRST_MATCH` / `STOP_IF_FIRST_MISMATCH` control flow, `before_sleep` for timing
- **Payloads**: optional brute-force payload sets (username/password dictionaries)
- **Extractors**: regex-based extraction from response body/headers into variables
- **Gopoc**: Go-based PoC hooks (`gox/` package) for complex protocol interactions
- **OOB**: PoCs request reverse platform tokens for blind vulnerability verification. OOB detection is unified in `config.ContainsOOBToken()` / `config.PocUsesOOB()`.

### PoC loading priority

1. **curated** -- encrypted PoC set from remote service (`~/.config/afrog/pocs-curated/`)
2. **my** -- user directory `./my-pocs/` or `AFROG_POCS_CURATED_DIR` env override
3. **append** -- `--append-pocs` CLI flag
4. **local** -- `-P` / `--poc-file` CLI flag
5. **builtin** -- embedded via `pocs/pocs.go` (Go `embed`)

### Config file

On first run, `~/.config/afrog/afrog-config.yaml` is auto-created. Key sections:
- `curated`: encrypted PoC subscription settings
- `reverse`: OOB platform credentials (ceye/dnslogcn/alphalog/xray/revsuit)
- `webhook`: Dingtalk and WeChat Work notification tokens
- `cyberspace`: Zoomeye API integration

### SDK (library usage)

`afrog.go` exports `SDKScanner` -- the public API for library consumers. Uses `runner.NewRunner(options, runner.WithSDKMode())`. See `examples/` for patterns: basic scan, async scan with callbacks, OOB scan, progress scan, port scan.

## Refactoring notes

engine.go was split (2025-06) into focused files under `pkg/runner/`:

| File | Lines | Responsibility |
|------|-------|----------------|
| `engine.go` | ~878 | Execute orchestrator, Engine struct, CheckerPool, pause/resume/stop |
| `webprobe.go` | ~290 | Web service discovery + helpers |
| `pedm.go` | ~400 | PoC execution duration monitoring |
| `stage_fingerprint.go` | ~165 | Fingerprint scan stage |
| `filter.go` | ~82 | PoC fingerprint/tag filtering |
| `oob_coordinator.go` | ~98 | OOB adapter init + status display |
| `context.go` | ~14 | `ScanContext` runtime callbacks, lazy-init via `getScanCtx()` |
| `errors.go` | ~39 | `ScanError` type, `SevSuppressed`/`SevRetryable`/`SevFatal` severity levels |
| `progress_render.go` | ~171 | CLI progress bar (available, not yet integrated into main.go) |
| `shutdown.go` | ~89 | Graceful signal handling + auto-save (available, not yet integrated) |

Key deduplications and cleanups:
- `containsOOBToken` / `pocUsesOOB` -> exported as `config.ContainsOOBToken` / `config.PocUsesOOB`
- `isNetOnlyPoc` closures -> `poc.Poc.IsNetOnly()` method
- SDK runner creation -> `runner.NewRunner(options, runner.WithSDKMode())`
- Channel send pattern -> `sendOrDrop[T]()` (6 call sites migrated)
- Target list extraction -> `config.Options.TargetStrings()` (4 duplicate loops eliminated)
- Rate limit defaults -> `config.Options.ApplyDefaults()` / `ValidateRateLimitModes()`
- `MMutex` global, `collectOrderedPocPaths`, ~300 lines commented-out code deleted
- `ReadComplieOptions` typo -> `ReadCompileOptions`
- CEL eval errors now logged at debug level instead of silently swallowed
- Test coverage: 12 packages, 43 new test cases (filter, context, poc, oob_coordinator, fingerprint)

## Code style

- **Formatting**: `gofmt -w .` before every commit. Tabs for indentation, LF line endings (see `.editorconfig`)
- **Immutability**: Prefer creating new objects over mutating existing ones
- **Error handling**: Explicit at every level, never silently swallow
- **Naming**: `camelCase` for variables/functions, `PascalCase` for types/interfaces, `UPPER_SNAKE_CASE` for constants
- **File size**: Keep under 800 lines; extract utilities from large modules
- **Function size**: Keep under 50 lines; split large functions into focused pieces

## Common pitfalls

1. **Don't auto-split Go files**: Automated line-based extraction fails on Go nested declarations. Split manually.
2. **gofmt before string edits**: Tab/space mismatches cause Edit tool failures. Run `gofmt -w .` first.
3. **String literals with ESC bytes**: ANSI escape sequences in Go strings get corrupted by Python string replacement. Use raw string literals or careful byte handling.
4. **CRLF on Windows**: gofmt may convert LF to CRLF on Windows. Cosmetic only, no functional impact. Configure `git config --global core.autocrlf false` to avoid.
