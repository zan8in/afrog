<!--
title: Raw HTTP
slug: /docs/poc/raw-http
lang: en
summary: afrog Raw HTTP reference for deciding when to leave structured requests and switch to raw packets.
status: published
source: docs/zh/poc/07-raw-http.md
last_reviewed: 2026-09-16
-->

`Raw HTTP` is useful when regular `method/path/headers/body` form is not expressive enough.

This page is best for three practical questions:

- should I really use Raw HTTP here
- what scenarios are a good fit for it
- once I write a raw request, how should I validate the response

If structured syntax already describes the request clearly, there is usually no reason to switch. Raw HTTP is for the cases where you really need the request to look like the wire-level packet you have in mind.

Typical cases include:

- special header ordering
- protocol upgrades
- complex raw payloads
- cases where the request should stay as close as possible to the real wire format

## When to use Raw HTTP

Recommended order of preference:

1. try normal structured request syntax first
2. switch to Raw HTTP only when the normal form cannot express the case clearly

The structured form is easier to maintain, reuse, and read.

## Decide when to use it first

Good reasons to switch to Raw HTTP:

- you need exact control over header ordering
- you need to send upgrade-style requests
- you need to control blank lines or exact raw request layout
- the target is sensitive to the real client-like request shape

Usually unnecessary when:

- the request is a normal GET or POST
- you only need a few extra headers
- the body is long but still ordinary
- structured `request` syntax already expresses the case clearly

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

### The key mental model

With Raw HTTP, only the **request shape** changes. The **match logic** does not.

In practice:

- `request.raw` sends the packet you want
- `expression` still decides whether the PoC hits

## Quick field lookup

| Item | Purpose | Typical usage |
| --- | --- | --- |
| `request.type` | explicitly declare HTTP type | `http` |
| `request.raw` | raw HTTP packet | multi-line YAML block |
| `{{Hostname}}` | current target host | very common in raw packets |
| `response.raw_header` | raw response headers | useful for Upgrade-style checks |
| `response.body` | raw response bytes | binary or exact byte matching |
| `response_text` | decoded response text | page text and regex extraction |

## Typical scenarios

### WebSocket / Upgrade

When upgrade-specific headers must be preserved precisely, Raw HTTP is often the clearest form.

### HTTP probing before special protocol interaction

Some cases are sensitive to header order, blank lines, or exact raw request structure, and are easier to express with raw syntax.

### Special request-line or Host forms

If the target cares about the request line, absolute URL style, or a very specific Host form, Raw HTTP is usually the clearer way to write it.

## Minimal workflow

When writing a Raw HTTP PoC, this order is usually the most stable:

1. confirm that structured syntax really is not enough
2. keep the raw packet minimal at first
3. write the most stable possible `expression`
4. only then add variables or extra headers if needed

## Usage suggestions

1. Use Raw HTTP only when structured requests are not enough
2. Variables still work, for example `{{Hostname}}`
3. `expression` works exactly the same as with normal HTTP rules
4. Choose `response.raw_header`, `response.body`, or `response_text` depending on the response pattern you need to validate
5. For a first version, keep the raw packet as small as possible

## Common misunderstandings

### Raw HTTP is not the default "more advanced" style

It exists for a minority of complex cases. It is usually not a good idea to write every PoC in raw form.

### A raw request still needs response validation

The request form does not determine the final hit. `expression` still decides whether the PoC matches.

### Raw HTTP is not "the more professional default"

It is lower-level, not automatically better. For many everyday HTTP PoCs, structured syntax stays clearer and easier to maintain.

## One-line takeaway

Raw HTTP is valuable not because it is more complex, but because it lets you send the packet you actually mean. Use it when structured syntax starts to distort that intent.

> **← Previous:** [OOB](./06-oob.md) ｜ **Handbook home:** [PoC Quickstart](./01-quickstart.md) ｜ **Next →:** [TCP / SSL](./08-tcp.md)
