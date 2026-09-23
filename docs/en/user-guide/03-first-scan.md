<!--
title: First Scan
slug: /docs/user-guide/first-scan
lang: en
summary: The shortest path from installation to a successful first afrog scan.
status: published
source: docs/zh/user-guide/03-first-scan.md
last_reviewed: 2026-09-16
-->

This page focuses on one goal: run `afrog` successfully as quickly as possible and understand what the result means.

## Minimal command

By default, `afrog` scans with built-in PoCs and generates an HTML report when it finds vulnerabilities.

```bash
afrog -t https://example.com
```

Here `-t` means a single target.

## Scan multiple targets

If you already have a list of URLs, use `-T` with a file:

```bash
afrog -T urls.txt
```

Put one target on each line.

## Common first-run patterns

### Run only custom PoCs

```bash
afrog -t https://example.com -P mypocs/
```

### Filter by keyword

For example, run only `weblogic` and `jboss` related PoCs:

```bash
afrog -t https://example.com -s weblogic,jboss
```

### Filter by severity

For example, focus only on high and critical issues:

```bash
afrog -t https://example.com -S high,critical
```

Supported severities include `info`, `low`, `medium`, `high`, and `critical`.

## What you will see after a scan

- scan progress and findings in the terminal
- an HTML report in the current directory
- structured output files if JSON output is enabled

For output details, see:

- [Output and Report](./06-output-and-report.md)

## A common first-run warning

If you see an error like:

```text
[ERR] ceye reverse service not set: /home/afrog/.config/afrog/afrog-config.yaml
```

it means the OOB / reverse configuration is not ready yet. PoCs that depend on an out-of-band platform will not work until that is configured.

For setup details, see:

- [Configuration](./05-configuration.md)

## Fingerprint gating reminder

High-cost PoCs such as weak-password, brute-force, or default-credential checks usually run only after the target matches the required fingerprint. `afrog` supports this through:

- `requires`
- `requires-mode`

When `requires-mode: strict` is used, the PoC will be skipped if fingerprinting is disabled or the target does not match the required fingerprint tags.

For the full explanation, see:

- [PoC Quickstart](../poc/01-quickstart.md)

> **← Previous:** [Install](./02-install.md) ｜ **Handbook home:** [What afrog does](./01-overview.md) ｜ **Next →:** [CLI Options](./04-cli-options.md)
