---
title: PoC Quickstart
slug: /docs/poc/quickstart
lang: en
summary: Write and validate the first working afrog PoC.
status: published
source: docs/zh/poc/quickstart.md
last_reviewed: 2026-09-16
---

This page focuses on the shortest path to a working `afrog` PoC.

## A minimal runnable PoC

```yaml
id: demo-basic

info:
  name: Basic structure example
  author: your-name
  severity: info

rules:
  r0:
    request:
      method: GET
      path: /status
    expression: response.status == 200

expression: r0()
```

This already includes the most important parts:

- `id`: the unique PoC identifier
- `info`: base metadata
- `rules`: request and match logic
- top-level `expression`: the final hit condition

## How to read the minimal structure

### `id`

Used as the unique identifier of a PoC. Keep it stable, readable, and easy to search.

### `info`

The most common required fields are:

- `name`
- `author`
- `severity`

### `rules`

Each rule usually contains:

- `request`: what to send
- `expression`: how to decide whether the rule matches

### Top-level `expression`

Used to organize the relationship between rules. The simplest form is:

```yaml
expression: r0()
```

With multiple rules, you can write:

```yaml
expression: step1() && step2()
```

## A slightly fuller example

```yaml
id: demo-basic-headers-body

info:
  name: Basic structure with headers and body
  author: your-name
  severity: low

set:
  ua: "Afrog/3.0"

rules:
  r0:
    request:
      method: POST
      path: /api/login
      headers:
        User-Agent: "{{ua}}"
        Content-Type: application/json
      body: '{"username":"admin","password":"admin"}'
    expression: response.status == 200 && response.body.bcontains(b"token")

expression: r0()
```

This version adds several common patterns:

- variables in `set`
- variable interpolation in headers and body
- response checks on both status and body

## Local validation

After writing a PoC, start with a single target and a minimal test run:

```bash
afrog -t https://example.com -P ./mypocs -debug
```

If you only want a syntax check first, use `-validate`.

## Common mistakes

### Incorrect YAML indentation

`afrog` PoCs are YAML-based, so indentation errors will fail early. Use consistent spaces for indentation.

### Mixing byte matching and text matching

Common objects:

- `response.body`: bytes, often used with `bcontains`, `bmatches`, and `bsubmatch`
- `response_text`: text, often used with `icontains`, `rmatches`, and `submatch`

For Chinese pages, encoding issues, or regex extraction, `response_text` is often the safer choice.

### Missing the top-level `expression`

Even when `rules` are defined, you still need the top-level `expression` to define the final decision logic.

## Next steps

- [PoC Syntax](./syntax.md)
- [Helper Functions](./helper-functions.md)
- [requires](./requires.md)
- [brute](./brute.md)
- [OOB](./oob.md)
- [TCP / SSL](./tcp.md)
