<!--
title: CLI Options
slug: /docs/user-guide/cli-options
lang: en
summary: Authoritative reference for the most commonly used afrog CLI options.
status: published
source: docs/zh/user-guide/04-cli-options.md
last_reviewed: 2026-09-16
-->

This page summarizes the main `afrog` CLI groups, common usage patterns, and key defaults so it can work both as an onboarding page and as an in-site parameter dictionary.

## Common starting commands

| Scenario | Recommended command |
| --- | --- |
| Scan a single URL | `afrog -t http://example.com` |
| Scan multiple URLs from a file | `afrog -T targets.txt` |
| Only scan high and critical issues | `afrog -T targets.txt -S high,critical` |
| Use only custom PoCs | `afrog -t http://example.com -P ./pocs/` |
| Export JSON | `afrog -t http://example.com -j result.json` |
| Export full JSON | `afrog -t http://example.com -ja result.json` |

## Target input

### `-t`

Specify a single target. Useful for:

- one URL
- one host
- one CIDR or IP range

Examples:

```bash
afrog -t https://example.com
afrog -t 192.168.1.100
afrog -t 192.168.1.0/24 -ps
```

### `-T`

Read multiple targets from a file, one target per line.

```bash
afrog -T targets.txt
```

### `-cs`

Enable a cyberspace input source, for example:

```bash
afrog -cs zoomeye
```

Useful when you want to pull assets from a cyberspace search provider before continuing with afrog scanning.

### `-q`

Provide the query string for the cyberspace search:

```bash
afrog -cs zoomeye -q "app:'tomcat'"
```

### `-qc`

Control the number of cyberspace results. The default is `100`.

```bash
afrog -cs zoomeye -q "app:'tomcat'" -qc 1000
```

### `-ps`

Enable port pre-scan. Useful for IPs, CIDRs, and range-style inputs.

```bash
afrog -t 192.168.1.0/24 -ps
```

### `-w`

Collect web asset info before vulnerability scanning: identify HTTP(S) assets and print URL, status, title, Server and tech-stack fingerprints (e.g. `php`, `apache`, `thinkphp`).

**Enabled by default**; disable with `-w=false`:

```bash
afrog -t 192.168.1.0/24 -ps           # web probing is already on
afrog -t 192.168.1.0/24 -ps -w=false  # disable explicitly
```

The web probing result also decides which targets the HTTP PoCs hit: when `-ps` is on, a `host:port` the port fingerprint has already ruled out as HTTP(S) (such as `22`/`3306`/`6379`, or TLS-but-not-web services like `465`/`993`/`995`) is kept out of the HTTP PoC target pool, while TCP/SSL PoCs still cover every port. Non-web ports found by `-p all` therefore no longer make every HTTP task sit there until it times out.

With `-w=false` this gating is off and HTTP PoCs are fired at every target as before. Use `-debug` to see how many targets were gated (`vuln-scan gated non-http-targets=N`).

### `-w-timeout`

Per-request timeout (seconds) for the web probing stage, covering both the HTTP request and the TLS certificate fetch. Defaults to `30`.

It is independent of the global `-timeout`: the global timeout governs PoC requests, while `-w-timeout` only governs the probing stage. Raise it on its own when a target is slow instead of relaxing the whole scan. Shared hosting and middleboxes often take more than 10s to emit response headers, so keep this default generous.

```bash
afrog -t http://example.com -w -w-timeout 30
```

### `-w-favicon`

Also fetch the favicon during web probing and compute its hash, which helps identify a shared asset set or applications that titles do not reveal. **Off by default**; each target costs one extra request.

```bash
afrog -t http://example.com -w -w-favicon
```

### `-p`

Control the port range for pre-scan. Supports:

- keywords: `top`, `full`, `all`
- comma-separated port lists
- port ranges

```bash
afrog -t 192.168.1.100 -ps -p 80,443,8080
afrog -t 192.168.1.100 -ps -p 1-65535
```

### `-Pn`

Skip host discovery and go directly to port scanning.

```bash
afrog -t 192.168.1.0/24 -ps -Pn
```

## PoC selection and filtering

### `-P`

Specify a single PoC file or a PoC directory.

```bash
afrog -t http://example.com -P ./pocs/test.yaml
afrog -t http://example.com -P ./pocs/
```

### `-ap`

Append custom PoCs in addition to built-in PoCs.

```bash
afrog -t http://example.com -ap ./my-pocs/
```

### `-pocmigrate`

Migrate legacy PoCs to the current syntax. Supports a file or a directory.

```bash
afrog -pocmigrate ./legacy-pocs/
```

### `-s`

Filter PoCs by keywords, usually matching `id`, `name`, or `tags`.

```bash
afrog -t http://example.com -s spring,weblogic
```

### `-S`

Filter by severity. Common severities:

- `info`
- `low`
- `medium`
- `high`
- `critical`
- `unknown`

```bash
afrog -t http://example.com -S high,critical
```

### `-sort`

Control scan ordering. Currently supports:

- `severity`
- `a-z`

```bash
afrog -T targets.txt -sort severity
```

### `-ep`

Exclude a category or keyword set of PoCs.

```bash
afrog -t http://example.com -ep log4j
```

### `-epf`

Read the PoC exclusion list from a file.

```bash
afrog -t http://example.com -epf ./exclude.txt
```

### `-pl`

List matched PoCs.

```bash
afrog -pl -s weaver,ecology
```

### `-pd`

Show details of a specific PoC.

```bash
afrog -pd ssh-weak-login
```

### `-validate`

Validate PoC syntax. Useful while authoring or onboarding many PoCs at once.

```bash
afrog -validate ./pocs/
```

## Output options

### `-o`

Set the HTML report output path.

```bash
afrog -t http://example.com -o ./result/my_scan.html
```

### `-json` / `-j`

Write compact JSON results.

```bash
afrog -t http://example.com -j result.json
```

### `-json-all` / `-ja`

Write fuller JSON output that includes request and response details.

```bash
afrog -t http://example.com -ja result_full.json
```

For output details, see:

- [Output and Reports](./06-output-and-report.md)

## Debugging and troubleshooting

### `-debug`

Print additional debugging information.

```bash
afrog -t http://example.com -debug
```

### `-nf`

Skip fingerprinting. Useful for quick temporary verification, but it changes how `requires`-based gating behaves.

```bash
afrog -t http://example.com -nf
```

### `-resume`

Resume from a checkpoint file.

```bash
afrog -resume resume.afg
```

## Network and performance

### `-timeout` / `-retries`

Control timeout and retry count.

```bash
afrog -t http://example.com -timeout 60 -retries 2
```

### `-proxy`

Send requests through a proxy.

```bash
afrog -t http://example.com -proxy http://127.0.0.1:8080
```

`-proxy` supports:

- comma-separated multiple proxies
- file input
- HTTP and SOCKS5 proxies

### `-H`

Add global request headers.

```bash
afrog -t http://example.com -H 'X-Forwarded-For: 1.1.1.1' -H 'Cookie: a=b'
```

### `-http-default-accept`

Add `Accept: */*` automatically when a PoC does not set `Accept` explicitly. The current default is `true`.

### `-c`

Control concurrency.

```bash
afrog -T targets.txt -c 50
```

In practice, pushing `-c` very high is not always the best speed strategy. It is usually better to tune concurrency together with global and per-target rate controls.

### `-rl`

Control the global requests-per-second limit. The default is `150`.

```bash
afrog -T targets.txt -rl 80
```

### `-rlt`

Control the per-target (`host:port`) requests-per-second limit. `0` disables it.

```bash
afrog -T targets.txt -rlt 5
```

### `-smart`

Automatically tune concurrency based on target count and runtime conditions.

```bash
afrog -T targets.txt -smart
```

### `-mt`

Monitor target liveness during the scan. Useful on the public internet or in unstable networks.

```bash
afrog -T targets.txt -mt
```

### `-auto-req-limit`

**On by default.** Applies adaptive per-target (`host:port`) throttling: the start rate is derived from `-rl` and clamped by concurrency, then a bidirectional AIMD loop raises or lowers it at runtime based on failure rate and latency. Healthy targets climb additively up to roughly `-rl` (so they are effectively unthrottled), while degrading targets get backed off multiplicatively. That gives you "scan fast without overwhelming a single target" with no extra configuration.

```bash
# Enabled by default, nothing to add
afrog -T targets.txt -c 50

# Explicitly disable it to go back to relying on -rl alone
afrog -T targets.txt -auto-req-limit=false
```

### `-polite` / `-balanced` / `-aggressive`

These presets are mutually exclusive with `-rlt` and `-auto-req-limit` (at most one takes effect). When neither a preset nor `-rlt` is given, the default is `-auto-req-limit`'s adaptive strategy. They are preset per-target throttling strategies:

- `-polite`: more conservative
- `-balanced`: a middle ground
- `-aggressive`: more permissive

They are most useful in batch scans where you want to protect individual targets from being overwhelmed.

The preset also sets the connection rate cap of the port pre-scan (see `-pcps`): `200/20` for `-polite`, `1000/100` for `-balanced` (the default), and no cap for `-aggressive`.

### `-mhe`

Maximum accumulated errors per host before afrog skips it. The default is `3`.

```bash
afrog -T targets.txt -mhe 5
```

### `-mrbs`

Maximum HTTP response body size. The default is `2`.

```bash
afrog -t https://example.com -mrbs 4
```

### `-brute-max-requests`

Maximum number of requests allowed for one brute rule. The default is `5000`, and `0` disables the cap.

```bash
afrog -t https://example.com -brute-max-requests 1000
```

## OOB

### `-oob`

Set the out-of-band adapter, for example:

```bash
afrog -t https://example.com -oob ceyeio
afrog -t https://example.com -oob dnslogcn
```

### `-orl`

Requests-per-second limit for OOB PoCs. The default is `25`.

### `-oc`

Concurrency limit for OOB PoCs. The default is `25`.

### `-oob-poll-interval`

Polling interval for OOB results, in seconds. The default is `2`.

### `-oob-hit-retention`

Retention window for OOB hits, in minutes. The default is `10`.

### `-oob-finalize-timeout`

Final OOB wait timeout in seconds. `-1` uses the pending timeout, and `0` disables final waiting.

## Stage control

### `-prate`

Global concurrency cap (worker pool size) for port pre-scan — not a per-second request rate. The default is `500`.

The effective value is additionally bounded by the local open-file limit: afrog first tries to raise the soft `ulimit -n` up to the hard limit, then narrows the pool to `min(-prate, budget)`. When it narrows, it prints a `[WRN] port-scan fd-limit ...` line explaining why. See [Practical Tips](./07-tips.md).

### `-pcps`

Global connection rate cap for the port pre-scan, in new connections per second. It follows the throttling preset by default: `1000` for `-balanced` (the default), `200` for `-polite`, and no cap for `-aggressive`. `-pcps 0` disables the cap explicitly; a positive value sets it explicitly.

Concurrency (`-prate`) and rate (`-pcps`) are two orthogonal dimensions: concurrency bounds how many connections are in flight, while the rate bounds how many new connections are opened per second. Concurrency alone is not enough — a few hundred concurrent probes at low RTT mean hundreds of thousands of connection attempts per second on a LAN, which exhausts the NAT/conntrack session table of the local exit device (a home or office router). Filtered ports never reply, so their entries linger for the 30–120s timeout; once the table is full, every new connection from anyone on that network fails. The default cap exists to prevent exactly that.

### `-pcps-host`

Connection rate cap for the port pre-scan against a single host, in new connections per second. It follows the preset by default: `100` for `-balanced`, `20` for `-polite`, and no cap for `-aggressive`. Its semantics match `-pcps`.

### `-ps-link-probe`

Whether to periodically measure the RTT to the default gateway during the port pre-scan. The default is `true`. A rising gateway RTT means the local uplink is saturated, so the scan eases its rate off and prints a `[WRN] port-scan throttled ...` line; it speeds back up once the link is healthy again. Disable it with `-ps-link-probe=false`.

### `-ptimeout`

Timeout for port pre-scan, in milliseconds. The default is `1000`.

### `-ptries`

Retry count per port in port pre-scan. The default is `0` (no retry). Each extra retry makes a dropping port pay another full timeout plus backoff, so a full-port scan slows down in multiples — raise it only for lossy targets.

### `-ps-s4-chunk`

Chunk size used by port pre-scan when `ports=full`. The default is `1000`.

### `-fingerprint-filter-mode`

Control the fingerprint filter mode for app-specific PoCs. Supported values:

- `strict`
- `opportunistic`

The default is `strict`.

### `-vsb`

Stop scanning and report immediately once a vulnerability is found. Useful when you only care about whether anything hits, not about completing the full scan batch.

## Additional output controls

### `-doh`

Disable automatic HTML report generation. It has higher priority than `-o`.

### `-nc`

Disable ANSI color output.

### `-silent`

Reduce output to results only as much as possible.

### `-live-stats`

Render live statistics in a single-line status display.

## PEDM and task timeout

PEDM (PoC Execution Duration Monitor) is used to observe execution duration, slow tasks, and task-level timeouts.

### `-pedm`

Enable PEDM.

### `-pedm-log-limit`

Print the first N started-task logs. `0` disables it.

### `-pedm-slow-sec`

Print slow-task logs when execution exceeds this threshold in seconds. The default is `30`.

### `-pedm-slow-log-limit`

Maximum number of completed slow-task logs. The default is `20`.

### `-pedm-summary-top`

Print the top N slowest summary entries when the scan ends. The default is `10`.

### `-pedm-summary-by`

PEDM summary sort key. Currently supports:

- `max`
- `avg`

### `-task-hard-timeout-sec`

Hard timeout for one target-plus-PoC task, in seconds. `0` disables it.

### `-task-smart-timeout`

Estimate task timeout from PoC content and use it as the primary hard-timeout strategy.

### `-task-timeout-visible-cap-sec`

Smart-timeout cap for regular HTTP PoCs. The default is `300`.

### `-task-timeout-net-cap-sec`

Smart-timeout cap for `tcp/udp/ssl` PoCs. The default is `360`.

### `-task-timeout-go-cap-sec`

Smart-timeout cap for Go PoCs. The default is `420`.

## Extra debug tools

### `-test`

Test mode. It disables requires gating. Useful for troubleshooting PoC behavior, but not recommended as a default scanning mode.

### `-v` / `-version`

Show the afrog version.

## Services and integrations

### `-web`

Start the web service.

### `-dingtalk`

Start the DingTalk webhook service.

### `-wecom`

Start the WeCom webhook service.

## Config

### `-config`

Specify the afrog configuration file path.

```bash
afrog -config ./afrog-config.yaml -t https://example.com
```

## Curated

### `-curated`

Control curated pocs mode. Supported values:

- `auto`
- `on`
- `off`

### `-curated-endpoint`

Specify the curated service endpoint.

### `-curated-timeout`

Control curated mount timeout in seconds.

### `-curated-force-update`

Force a curated pocs update check immediately.

## Update

### `-un` / `-update`

Update the afrog engine to the latest released version.

### `-duc` / `-disable-update-check`

Disable automatic update checks.

## Recommended combinations

### Fast single-target scan

```bash
afrog -t https://example.com
```

### Batch high-severity scan

```bash
afrog -T targets.txt -S high,critical
```

### Network discovery plus web probing plus vulnerability scanning

```bash
afrog -t 192.168.1.0/24 -ps        # web probing is on by default; disable with -w=false
```

### Stable batch scanning

```bash
afrog -T targets.txt -mt -auto-req-limit
```

## Note

This page now covers the major flag groups from the current `afrog -h`. For runtime truth and the latest defaults, it is still worth checking:

```bash
afrog -h
```

> **← Previous:** [First Scan](./03-first-scan.md) ｜ **Handbook home:** [What afrog does](./01-overview.md) ｜ **Next →:** [Configuration](./05-configuration.md)
