---
title: CLI Options
slug: /docs/reference/cli-options
lang: en
summary: Authoritative reference for the most commonly used afrog CLI options.
status: published
source: docs/zh/reference/cli-options.md
last_reviewed: 2026-09-16
---

This page collects the most commonly used `afrog` command-line options and serves as the starting point for the broader CLI reference.

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

```bash
afrog -t http://example.com -S high,critical
```

### `-ep`

Exclude a category or keyword set of PoCs.

```bash
afrog -t http://example.com -ep log4j
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

- [Output and Reports](../user-guide/output-and-report.md)

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

### `-H`

Add global request headers.

```bash
afrog -t http://example.com -H 'X-Forwarded-For: 1.1.1.1' -H 'Cookie: a=b'
```

### `-c`

Control concurrency.

```bash
afrog -T targets.txt -c 50
```

In practice, pushing `-c` very high is not always the best speed strategy. It is usually better to tune concurrency together with global and per-target rate controls.

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

## Webhooks

### `-wecom`

Send vulnerability hits to a WeCom robot.

```bash
afrog -T targets.txt -wecom
```

### `-dingtalk`

Send vulnerability hits to a DingTalk robot.

```bash
afrog -T targets.txt -dingtalk
```

Webhook tokens must be configured first. See:

- [Configuration](../user-guide/configuration.md)

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

This page focuses on the high-frequency options first. For the widest possible list of flags and defaults, you can always run:

```bash
afrog -h
```
