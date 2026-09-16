---
title: PoC Quickstart
slug: /docs/poc/quickstart
lang: en
summary: Write the first working afrog PoC by the shortest path, then know which reference page to open next.
status: published
source: docs/zh/poc/quickstart.md
last_reviewed: 2026-09-16
---

This page focuses on the shortest path to a working `afrog` PoC.

It is not the full reference manual. It is the onboarding path for a first PoC.

If you already know:

- how the fields should be written
- which helpers you need
- what `requires`, `brute`, `OOB`, or `TCP` are each for

then the topic pages are probably the better destination. If your goal is simply "get one working PoC first", stay with this page.

## Decide what kind of PoC you are writing first

Most new authors only need to choose between three starting points:

| What I want to do | Best starting shape |
| --- | --- |
| verify a normal web path or API | a standard HTTP PoC |
| verify a login, credential, or enumeration case | start with HTTP, then add `requires` or `brute` if needed |
| verify a non-HTTP protocol or multi-step session | start with `TCP / SSL` |

If you are not sure, start with the most ordinary HTTP PoC. It is the easiest to write, debug, and reuse as a template.

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

## The shortest first-PoC workflow

This order is usually the most stable:

1. choose the easiest target path that gives a repeatable signal
2. write a PoC with only one rule first
3. validate just one strong response signal
4. only then add variables, extra rules, or advanced features

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

## When to stop at the minimal version first

A common early instinct is to add too much at once:

- multiple rules
- OOB
- brute
- requires
- dynamic extraction

The safer path is usually:

make the smallest working version pass first, then grow it step by step.

## Local validation

After writing a PoC, start with a single target and a minimal test run:

```bash
afrog -t https://example.com -P ./mypocs -debug
```

If you only want a syntax check first, use `-validate`.

## The three most useful habits for a first debug pass

1. validate against one target, not a whole asset list
2. validate one PoC, not a whole directory
3. start with a simple hit condition, then make it stricter after it works

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

### Choosing a target that is too hard for the first PoC

If the first practice target already involves async behavior, complex login flow, or encoding edge cases, the debugging cost rises fast. A simpler and stable target is much better for the first run.

## Next steps

After the first PoC works, continue by question:

- want exact field syntax: [PoC Syntax](./syntax.md)
- want helper lookup: [Helper Functions](./helper-functions.md)
- want target-gated execution: [requires](./requires.md)
- want to iterate over many values: [brute](./brute.md)
- want blind verification: [OOB](./oob.md)
- want non-HTTP protocol support: [TCP / SSL](./tcp.md)
- want lower-level HTTP packet control: [Raw HTTP](./raw-http.md)
