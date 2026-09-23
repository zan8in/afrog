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

Probe web services on targets before vulnerability scanning.

```bash
afrog -t 192.168.1.0/24 -ps -w
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

Automatically apply per-target throttling so you can scan fast without overwhelming a single target.

```bash
afrog -T targets.txt -c 50 -auto-req-limit
```

### `-polite` / `-balanced` / `-aggressive`

These are preset per-target throttling strategies:

- `-polite`: more conservative
- `-balanced`: a middle ground
- `-aggressive`: more permissive

They are most useful in batch scans where you want to protect individual targets from being overwhelmed.

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

Rate limit for port pre-scan.

### `-ptimeout`

Timeout for port pre-scan, in milliseconds.

### `-ptries`

Retry count for port pre-scan.

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
afrog -t 192.168.1.0/24 -ps -w
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
