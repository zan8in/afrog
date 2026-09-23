---
title: PoC Syntax
slug: /docs/poc/syntax
lang: en
summary: afrog PoC syntax and field reference, designed for both writing flow and precise lookup.
status: published
source: docs/zh/poc/02-syntax.md
last_reviewed: 2026-09-16
---

This page is not the zero-to-one tutorial. It is the page PoC authors come back to while they are actually writing rules.

You can use it in two layers:

- the outer layer helps you decide what parts a PoC needs
- the inner layer helps you look up a specific field, request style, or syntax edge case

If you have not written your first PoC yet, start with [PoC Quickstart](./01-quickstart.md). If you are already editing rules, this page is the better tab to keep open.

## Build the mental model first

Most `afrog` PoCs can be reduced to five questions:

1. What is this PoC called and what does it describe: `id` + `info`
2. Do I need reusable variables: `set` / `payloads`
3. What requests do I need to send: `rules.*.request`
4. When does each rule count as a hit: `rules.*.expression`
5. How do multiple rules combine into the final result: top-level `expression`

## Top-level structure

The most common top-level keys in a PoC file are:

| Key | Typical usage | Purpose | When you need it |
| --- | --- | --- | --- |
| `id` | required | unique PoC identifier | every PoC |
| `info` | required | metadata, severity, tags, requires | every PoC |
| `set` | common | reusable variables | random strings, shared constants, tokens |
| `payloads` | advanced | multiple input sets | brute force, enumeration, combinations |
| `rules` | required | rule body with requests and matching logic | every PoC |
| `expression` | required | final relationship between rules | every PoC |
| `transport` | optional | default transport mode | non-default HTTP cases |
| `gopoc` | optional | bind to a Go PoC | when YAML logic is not enough |
| `extractors` | uncommon | top-level extractors | when global extraction is needed |

Basic example:

```yaml
id: demo-basic

info:
  name: Basic structure example
  author: your-name
  severity: info

set:
  token: "abc123"

rules:
  r0:
    request:
      method: GET
      path: /status
    expression: response.status == 200

expression: r0()
```

### What a healthy minimal PoC should contain

At minimum, it should have:

- a stable `id`
- a minimal but complete `info`
- at least one rule in `rules`
- an explicit top-level `expression`

If you only wrote `rules` but forgot the top-level `expression`, the PoC is usually not fully finished yet.

## `info`

`info` is both the identity card and the search surface of the PoC. It affects readability, filtering, management, and later cataloging.

### `info` field dictionary

| Field | Typical usage | Purpose | Notes |
| --- | --- | --- | --- |
| `name` | required | display name | should clearly describe the issue |
| `author` | required | author name | useful for ownership and filtering |
| `severity` | required | severity | used by filters such as `-S` |
| `description` | common | short explanation | describes what the PoC checks |
| `reference` | common | reference links | CVEs, advisories, vendor pages |
| `tags` | common | tags | improves search and batch selection |
| `verified` | optional | whether it is verified | signals maturity |
| `affected` | optional | affected scope | version or component range |
| `solutions` | optional | remediation note | makes results friendlier to users |
| `requires` | advanced | fingerprint gating | only run on matching products/services |
| `requires-mode` | advanced | gating mode | controls matching logic |
| `classification` | advanced | CVE / CWE / CVSS metadata | useful for standard cataloging |
| `created` | optional | creation date | helps maintenance and tracking |

In the current code, `requires` is normalized from multiple accepted forms:

- array form
- comma-separated string form
- `requires-mode`, `requiresMode`, or `requires_mode`

Supported severities:

- `critical`
- `high`
- `medium`
- `low`
- `info`

Example:

```yaml
info:
  name: Apache Struts2 RCE check
  author: your-name
  severity: critical
  description: Detect whether the target is vulnerable to Struts2 remote code execution
  reference:
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638
  tags: struts,rce,apache
  created: 2024/01/01
```

## `set`

`set` defines reusable variables. Variables can be referenced in requests and expressions with `{{var}}`.

Typical things to keep in `set`:

- random strings
- usernames and passwords
- reusable tokens
- OOB domains
- fragments shared by multiple rules

Example:

```yaml
set:
  username: admin
  password: admin
  randstr: randomLowercase(8)
```

## `rules`

`rules` is the real body of the PoC. You can think of it as a list of named probing steps.

### Field dictionary for one rule

| Field | Typical usage | Purpose | Notes |
| --- | --- | --- | --- |
| `request` | required | send the request | HTTP / TCP / UDP / SSL / raw / go |
| `expression` | common | single matching expression | the most common style |
| `expressions` | advanced | list of expressions | useful when splitting logic |
| `output` | common | extract values for later rules | common way to pass variables forward |
| `extractors` | common | structured extraction | another extraction style |
| `brute` | advanced | brute force / cartesian combination | for multiple input combinations |
| `stop_if_match` | optional | stop after a match | useful for early exit |
| `stop_if_mismatch` | optional | stop after a mismatch | useful for pruning |
| `before_sleep` | optional | sleep before the rule | useful when state needs time to change |

### `request`

The request shape depends on the protocol you are validating.

### HTTP request field dictionary

| Field | Typical usage | Purpose | Notes |
| --- | --- | --- | --- |
| `method` | required | HTTP method | such as `GET` or `POST` |
| `path` | required | request path | can include variables |
| `headers` | common | request headers | YAML map |
| `body` | common | request body | common for JSON or form posts |
| `follow_redirects` | optional | follow redirects or not | uses engine behavior if omitted |
| `raw` | advanced | raw HTTP request | useful when you need exact packet control |

### Network request field dictionary

When `request.type` is `tcp`, `udp`, `ssl`, `go`, or another non-default mode, these fields become relevant:

| Field | Typical usage | Purpose | Notes |
| --- | --- | --- | --- |
| `type` | required | request type | `http` / `tcp` / `udp` / `ssl` / `go` |
| `host` | common | host name | common in network protocols |
| `port` | common | port | optional, lower priority than explicit `host:port` |
| `data` | common | outgoing data | common for TCP / UDP |
| `data-type` | optional | data format | controls how the payload is sent |
| `read-size` | optional | read size | common in network protocols |
| `read-timeout` | optional | read timeout | common in network protocols |
| `steps` | advanced | multi-step read/write flow | useful for interactive protocols |

### When to use `steps`

If the protocol flow is more than a simple one-send-one-read, such as:

- read a banner first
- then write a payload
- then read the next response

`steps` is usually a better fit than a single `data` field.

Example:

```yaml
rules:
  login:
    request:
      method: POST
      path: /api/login
      headers:
        Content-Type: application/json
      body: '{"user":"{{username}}","pass":"{{password}}"}'
    expression: response.status == 200 && response.body.bcontains(b"token")
```

### `expression`

`afrog` uses CEL expressions for matching.

In practice, most expressions fall into three patterns:

1. check whether the status, headers, or body contain a signal
2. extract something with regex and continue matching
3. combine multiple conditions into a more stable hit

Common objects:

- `response.status`
- `response.body`
- `response_text`
- `response.headers`
- `response.raw_header`
- `response.latency`

Common matching functions:

- text: `contains`, `icontains`, `rmatches`, `submatch`, `submatchall`
- bytes: `bcontains`, `ibcontains`, `bmatches`, `bsubmatch`, `bsubmatchall`

Example:

```yaml
expression: |
  response.status == 200 &&
  "((u|g)id|groups)=[0-9]{1,4}\\([a-z0-9]+\\)".rmatches(response_text) &&
  !response_text.icontains("error")
```

### Text matching vs byte matching

When you work with decoded text, Chinese content, or regex extraction, `response_text` is often the better choice.

Older byte-oriented style:

```yaml
'"(?P<title>.+)"'.bsubmatch(response.body)
```

Recommended text-oriented style:

```yaml
'"(?P<title>.+)"'.submatch(response_text)
```

## Top-level `expression`

The top-level `expression` defines how multiple rules combine.

Example:

```yaml
expression: ping() && version()
```

Even with a single rule, keep the top-level expression explicit.

Common patterns:

- `r0()`: one rule only
- `login() && probe()`: finish a prerequisite, then verify
- `fingerprint() && exploit() && verify()`: staged validation

As a rule of thumb, the top-level `expression` should describe the final conclusion, not bury all logic inside one rule.

## `output` and `extractors`

`afrog` can extract values from responses and reuse them in later rules.

### When `output` is the better choice

If you mainly want to pass a value from one rule to the next, `output` is often the most direct style.

### `output`

One recommended style:

```yaml
rules:
  r0:
    request:
      method: GET
      path: /profile
    expression: response.status == 200
    output:
      web_title: '"<title>(?P<webtitle>.+)</title>".submatch(response_text)'
```

### `extractors`

An equivalent extractor style:

```yaml
rules:
  r0:
    request:
      method: GET
      path: /profile
    expression: response.status == 200
    extractors:
      - type: regex
        extractor:
          web_title: '"<title>(?P<webtitle>.+)</title>".submatch(response_text)'
```

## Dynamic multi-value extraction

For extracting multiple values and validating them one by one, combine:

- `submatchall` / `bsubmatchall`
- `brute`

Example:

```yaml
rules:
  r0:
    request:
      method: GET
      path: /api/templates
    expression: response.status == 200
    output:
      id_matches: '"\"id\":\"(?P<tid>[0-9]+)\"".bsubmatchall(response.body)'

  r1:
    brute:
      mode: clusterbomb
      commit: winner
      continue: false
      template_id: id_matches["tid"]
    request:
      method: GET
      path: /api/check?id={{template_id}}
    expression: response.status == 200 && response_text.icontains("success")

expression: r0() && r1()
```

## `classification`

If you want the PoC to be easier to catalog, manage, or display in a standardized way, add `classification`:

| Field | Purpose |
| --- | --- |
| `cvss-metrics` | CVSS vector |
| `cvss-score` | CVSS score |
| `cve-id` | CVE ID |
| `cwe-id` | CWE ID |

Example:

```yaml
info:
  name: Example CVE
  author: your-name
  severity: high
  classification:
    cve-id: CVE-2024-0001
    cwe-id: CWE-79
    cvss-score: 8.8
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
```

## The three questions authors look up most often

### Which page should I open first

- first working PoC: [PoC Quickstart](./01-quickstart.md)
- exact field syntax: this page
- helper or matching functions: [Helper Functions](./03-helper-functions.md)
- special scenarios: `requires / brute / OOB / Raw HTTP / TCP`

### Which fields matter most for most PoCs

For most HTTP PoCs, these are the core fields to get right first:

- `id`
- `info.name`
- `info.author`
- `info.severity`
- `rules.*.request.method`
- `rules.*.request.path`
- `rules.*.expression`
- top-level `expression`

### Which fields are more advanced

These are usually not required for a first PoC, but become valuable in more complex cases:

- `requires`
- `brute`
- `output`
- `extractors`
- `payloads`
- `raw`
- `steps`
- `classification`

> **← Previous:** [PoC Quickstart](./01-quickstart.md) ｜ **Next →:** [Helper Functions](./03-helper-functions.md)
