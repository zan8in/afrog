---
title: Output and Reports
slug: /docs/user-guide/output-and-report
lang: en
summary: Console output, HTML reports, JSON exports, and automation-oriented result handling in afrog.
status: published
source: docs/zh/user-guide/output-and-report.md
last_reviewed: 2026-09-16
---

`afrog` supports console output, HTML reports, JSON files, and fuller `JsonAll` output so the same scan can serve both manual review and automated workflows.

## Default output

When you do not add extra output flags:

- the terminal shows scan progress and hits
- an HTML report is generated when vulnerabilities are found

The most common command is:

```bash
afrog -t https://example.com
```

## HTML reports

HTML reports are useful for manual review and archiving. They are one of the most readable output formats in `afrog`.

Useful for:

- single-target verification
- vulnerability review
- sharing readable results with testing or operations teammates

## JSON output

Relevant flags:

- `-json`
- `-j`

These flags save scan results to JSON files. The default output focuses on result summaries such as:

- `target`
- `fulltarget`
- `id`
- `info`

Inside `info`, common fields include:

- `name`
- `author`
- `severity`
- `description`
- `reference`

Examples:

```bash
afrog -t https://example.com -json result.json
afrog -t https://example.com -j result.json
```

## JsonAll output

Relevant flags:

- `-json-all`
- `-ja`

Compared with `-json`, `-json-all` also includes fuller request and response details in the output file.

Examples:

```bash
afrog -t https://example.com -json-all result.json
afrog -t https://example.com -ja result.json
```

Prefer `JsonAll` when you need:

- downstream automation
- custom alerting
- auditing request and response evidence

## One detail about JSON files

During the scan, JSON output is written incrementally. That means if you parse the file before the scan completes, you may need to append the trailing `]` yourself or the parser may fail.

If you wait until the scan is complete, this issue does not apply.

## Screenshots

`afrog` also supports screenshot-oriented result presentation for cases where visual readability matters more.

## Choosing the right output

If your primary goal is:

- manual review: prefer HTML reports
- programmatic integration: prefer `-json` or `-json-all`
- debugging and evidence retention: prefer `-json-all`

## Related pages

- [First Scan](../getting-started/first-scan.md)
- [SDK Quickstart](../sdk/quickstart.md)
