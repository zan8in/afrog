---
title: Output and Reports
slug: /docs/user-guide/output-and-report
lang: en
summary: Console output, HTML reports, JSON exports, and automation-oriented result handling in afrog.
status: published
source: docs/zh/user-guide/06-output-and-report.md
last_reviewed: 2026-09-16
---

`afrog` supports console output, HTML reports, JSON files, and fuller `JsonAll` output so the same scan can serve both manual review and automated workflows.

## Output dictionary

If you plan to integrate `afrog` into a platform, script, or pipeline, the first useful distinction is between these three result styles:

| Output type | Flags | Typical use | Granularity |
| --- | --- | --- | --- |
| Console / HTML | default / `-o` | manual review, archiving | human-readable first |
| `JSON` summary output | `-json` / `-j` | automation, lightweight alerting | result summary |
| `JsonAll` detailed output | `-json-all` / `-ja` | request/response evidence, auditing | result summary + request/response |

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

These flags save scan results to JSON files.

### `-json` field dictionary

`-json` / `-j` maps to the structs in `pkg/report/json.go`. Each result entry has this shape:

| Field | Type | Meaning |
| --- | --- | --- |
| `isvul` | bool | whether the scan hit a vulnerability |
| `target` | string | original target |
| `fulltarget` | string | normalized full target with scheme and port when available |
| `pocinfo` | object | PoC metadata |
| `pocresult` | array | request/response array; usually empty in plain `-json` mode |
| `extractor` | object | named values extracted by extractors |

Inside `pocinfo`, the current fields are:

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | PoC ID |
| `infoname` | string | PoC name |
| `infoauthor` | string | author |
| `infoseg` | string | severity |
| `infodescription` | string | description |
| `inforeference` | string[] | references |

One detail is worth calling out: the actual JSON key in the current code is `infoseg`, not a more obvious variant such as `infoseverity`. If you are building a parser, use the real key name.

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

### Extra fields in `-json-all`

`JsonAll` keeps the same top-level structure, but populates `pocresult`. Each item contains:

| Field | Type | Meaning |
| --- | --- | --- |
| `request` | string | raw request payload |
| `response` | string | raw response payload, converted toward UTF-8 handling |

In practice:

- `-json` is better for summary processing and alerts
- `-json-all` is better for evidence retention, review, debugging, and audits

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

## Minimal `-json` example

```json
[
  {
    "isvul": true,
    "target": "https://example.com",
    "fulltarget": "https://example.com:443",
    "pocinfo": {
      "id": "spring-core-rce",
      "infoname": "Spring Core RCE",
      "infoauthor": "afrog",
      "infoseg": "critical",
      "infodescription": "Example description",
      "inforeference": ["https://example.com/advisory"]
    },
    "extractor": {
      "version": "5.3.17"
    }
  }
]
```

## Minimal `-json-all` example

```json
[
  {
    "isvul": true,
    "target": "https://example.com",
    "fulltarget": "https://example.com:443",
    "pocinfo": {
      "id": "spring-core-rce",
      "infoname": "Spring Core RCE"
    },
    "pocresult": [
      {
        "request": "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n...",
        "response": "HTTP/1.1 200 OK\\r\\nServer: nginx\\r\\n..."
      }
    ]
  }
]
```

## Legacy lightweight JSON output

There is also an older lightweight JSON structure in `pkg/output/json.go` with only three fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string | vulnerability name |
| `severity` | string | severity |
| `url` | string | matched URL |

If a legacy script or integration only sees these three fields, it is probably consuming this lightweight output path rather than the newer `pkg/report/json.go` model.

## Screenshots

`afrog` also supports screenshot-oriented result presentation for cases where visual readability matters more.

## Choosing the right output

If your primary goal is:

- manual review: prefer HTML reports
- programmatic integration: prefer `-json` or `-json-all`
- debugging and evidence retention: prefer `-json-all`

## Suggestions for automation

If you are turning `afrog` into a platform input, a practical parser strategy is:

1. parse the file as an array of result entries
2. tolerate the in-progress state where the trailing `]` has not been written yet
3. treat `target`, `fulltarget`, `pocinfo.id`, and `pocinfo.infoseg` as the most stable indexing fields
4. only consume `pocresult` when you actually need evidence retention

> **← Previous:** [Configuration](./05-configuration.md) ｜ **Handbook home:** [What afrog does](./01-overview.md) ｜ **Next →:** [Practical Tips](./07-tips.md)
