---
title: Practical Tips
slug: /docs/user-guide/tips
lang: en
summary: High-frequency afrog recipes: target input, asset discovery, performance and stability, OOB, output, and resume.
status: published
source: new
last_reviewed: 2026-09-23
---

This page is not a parameter dictionary. It combines frequently used flags into recipes you can copy directly. For the full parameter reference, see [CLI Options](./04-cli-options.md).

## Focus on high-severity findings only

```bash
afrog -T targets.txt -S high,critical
```

Pair it with `-sort severity` to order results by risk, which helps when you only want the highlights first.

## Pull assets from cyberspace mapping

```bash
afrog -cs zoomeye -q "app:'tomcat'" -qc 1000
```

`-cs` selects the mapping platform, `-q` passes the query, and `-qc` caps the number of results (default 100). Configure credentials in the `cyberspace` section of your [configuration](./05-configuration.md) first.

## Probe before scanning on network ranges

```bash
afrog -t 192.168.1.0/24 -ps -w
```

- `-ps`: enable port pre-scanning, suited to IPs, ranges and CIDRs
- `-w`: probe targets for web services to identify HTTP(S) assets first
- `-p`: control the port range with `top`, `full`, `80,443,8080`, or `1-65535`
- `-Pn`: skip host discovery and go straight to port scanning

## Run only the PoCs you care about

```bash
afrog -t https://example.com -s spring,weblogic   # keyword filter (id / name / tags)
afrog -t https://example.com -P ./my-pocs/        # specific PoC file or directory
afrog -t https://example.com -ap ./extra-pocs/    # append beyond built-in PoCs
afrog -t https://example.com -ep log4j            # exclude a category
```

Before writing or importing PoCs, validate and confirm:

```bash
afrog -validate ./pocs/        # validate PoC syntax
afrog -pl -s weaver,ecology    # list matched PoCs
afrog -pd ssh-weak-login       # inspect a single PoC
```

## Protect targets during bulk scans

```bash
afrog -T targets.txt -c 50 -auto-req-limit
afrog -T targets.txt -rl 80 -rlt 5
afrog -T targets.txt -mt -balanced
```

- `-c` concurrency, `-rl` global requests per second (default 150), `-rlt` requests per second per target
- `-auto-req-limit`, or `-polite` / `-balanced` / `-aggressive`, applies per-target adaptive limiting
- `-mt` monitors target liveness, useful on the public internet or unstable networks

In practice, do not speed things up by only raising `-c`; tune concurrency and rate limits together.

## Use OOB for blind vulnerabilities

```bash
afrog -t https://example.com -oob ceyeio
```

Available adapters include `ceyeio`, `dnslogcn`, and `alphalog`. Fill in the matching platform credentials in the `reverse` section of your [configuration](./05-configuration.md) first. Use `-orl` and `-oc` to control OOB rate and concurrency.

## Output and automation

```bash
afrog -T targets.txt -o report.html        # HTML report
afrog -T targets.txt -j result.json        # compact JSON
afrog -T targets.txt -ja result_full.json  # full JSON with requests and responses
```

Output controls worth knowing:

- `-silent`: output results only
- `-live-stats`: render live statistics on a single line
- `-nc`: disable ANSI colors
- `-doh`: disable automatic HTML report generation

## Resume long-running scans

```bash
afrog -T big-targets.txt -resume resume.afg
```

After an interruption, pass the same `-resume` file to continue. Best suited to long scans over large target sets.

## Troubleshooting

```bash
afrog -t https://example.com -debug   # more debug output
afrog -t https://example.com -nf      # skip fingerprinting for a quick check
afrog -t https://example.com -test    # test mode, disables requires gating
```

Both `-nf` and `-test` affect `requires`-based gating, so avoid using them as regular scan modes.

## Notifications and web services

```bash
afrog -web         # start the web service
afrog -dingtalk    # start the DingTalk webhook service
afrog -wecom       # start the WeCom webhook service
```

Notification thresholds and tokens are configured in the `webhook` section of your [configuration](./05-configuration.md).

> **← Previous:** [Output and Reports](./06-output-and-report.md) ｜ **Handbook home:** [What afrog does](./01-overview.md) ｜ **Docs home →:** [afrog Docs](../index.md)
