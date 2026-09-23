---
title: What afrog does
slug: /docs/user-guide/overview
lang: en
summary: Opening page of the User Guide: what afrog is, what it does, and how to read this handbook.
status: published
source: new
last_reviewed: 2026-09-23
---

## What afrog is

`afrog` is a high-performance security scanning toolkit built for bug bounty, pentest, and red team workflows. It combines fast target probing, built-in vulnerability checks, custom PoC authoring, and SDK-driven automation in a single Go-based workflow.

### What afrog does

- Fast and focused scanning for web targets and network services
- Built-in and custom PoC support for practical security validation
- Lower false-positive noise through precise rule design and checks
- Flexible integration with Go applications, automation flows, and private PoC pipelines

## What this handbook covers

The User Guide covers everything you need to put `afrog` to work: install, first scan, CLI, configuration, output, and practical tips.

- Writing your own PoCs? Continue with the [PoC Authoring Guide](../poc/01-quickstart.md).
- Embedding `afrog` in a program? Continue with the [SDK Usage Guide](../sdk/01-quickstart.md).

## In this handbook

1. [Install](./02-install.md)
2. [First Scan](./03-first-scan.md)
3. [CLI Options](./04-cli-options.md)
4. [Configuration](./05-configuration.md)
5. [Output and Reports](./06-output-and-report.md)
6. [Practical Tips](./07-tips.md)

## Shortest path

Once installed, a single command gets you your first scan:

```bash
afrog -t https://example.com
```

Start reading from [Install](./02-install.md).

> **← Docs home:** [afrog Docs](../index.md) ｜ **Next →:** [Install](./02-install.md)
