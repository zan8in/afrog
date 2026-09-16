---
title: Raw HTTP
slug: /docs/poc/raw-http
lang: en
summary: When and how to use raw HTTP requests in afrog PoCs.
status: published
source: docs/zh/poc/raw-http.md
last_reviewed: 2026-09-16
---

`Raw HTTP` is useful when regular `method/path/headers/body` form is not expressive enough, such as:

- special header ordering
- protocol upgrades
- complex raw payloads
- cases where the request should stay as close as possible to the real wire format

## When to use Raw HTTP

Recommended order of preference:

1. try normal structured request syntax first
2. switch to Raw HTTP only when the normal form cannot express the case clearly

The structured form is easier to maintain, reuse, and read.

## Basic syntax

```yaml
rules:
  raw_req:
    request:
      type: http
      raw: |
        GET /ws HTTP/1.1
        Host: {{Hostname}}
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Version: 13
    expression: response.status == 101 && response.raw_header.ibcontains(b"upgrade")
```

## Typical scenarios

### WebSocket / Upgrade

When upgrade-specific headers must be preserved precisely, Raw HTTP is often the clearest form.

### HTTP probing before special protocol interaction

Some cases are sensitive to header order, blank lines, or exact raw request structure, and are easier to express with raw syntax.

## Usage suggestions

1. Use Raw HTTP only when structured requests are not enough
2. Variables still work, for example `{{Hostname}}`
3. `expression` works exactly the same as with normal HTTP rules
4. Choose `response.raw_header`, `response.body`, or `response_text` depending on the response pattern you need to validate

## Common misunderstandings

### Raw HTTP is not the default "more advanced" style

It exists for a minority of complex cases. It is usually not a good idea to write every PoC in raw form.

### A raw request still needs response validation

The request form does not determine the final hit. `expression` still decides whether the PoC matches.

## Related pages

- [PoC Syntax](./syntax.md)
- [PoC Quickstart](./quickstart.md)
