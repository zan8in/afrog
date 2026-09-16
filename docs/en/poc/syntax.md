---
title: PoC Syntax
slug: /docs/poc/syntax
lang: en
summary: Authoritative reference for afrog PoC top-level fields and syntax.
status: published
source: docs/zh/poc/syntax.md
last_reviewed: 2026-09-16
---

This page summarizes the core syntax and field structure of `afrog` PoCs. It is intended as a reference page rather than a tutorial.

## Top-level structure

The most common top-level keys in a PoC file are:

- `id`
- `info`
- `set`
- `rules`
- `expression`

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

## `info`

Common fields:

- required: `name`, `author`, `severity`
- optional: `description`, `tags`, `created`, `reference`, `verified`, `requires`, `requires-mode`

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

Example:

```yaml
set:
  username: admin
  password: admin
  randstr: randomLowercase(8)
```

## `rules`

Each rule usually contains:

- `request`
- `expression`

### `request`

Common fields:

- `method`
- `path`
- `headers`
- `body`
- `follow_redirects`

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

## `output` and `extractors`

`afrog` can extract values from responses and reuse them in later rules.

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

## Related pages

- [PoC Quickstart](./quickstart.md)
- [Helper Functions](./helper-functions.md)
- [requires](./requires.md)
- [brute](./brute.md)
- [OOB](./oob.md)
- [Raw HTTP](./raw-http.md)
- [TCP / SSL](./tcp.md)
