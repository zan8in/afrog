---
title: TCP / SSL
slug: /docs/poc/tcp
lang: en
summary: afrog TCP / SSL reference for deciding when to use multi-step sessions and how read, write, and save-as fit together.
status: published
source: docs/zh/poc/08-tcp.md
last_reviewed: 2026-09-16
---

`afrog` supports not only HTTP PoCs, but also `tcp` and `ssl` protocol checks.

This page is best for four practical questions:

- should this protocol case use a TCP / SSL PoC at all
- when is one `data` exchange enough, and when do I need `steps`
- how should `read`, `write`, and `save-as` work together
- should I store the read result as bytes, string, or the default structured form

For services that require "read banner, write command, read response" behavior, `steps` is usually the right path.

## When to use TCP / SSL

Useful for:

- banner-first protocols such as POP3, IMAP, SMTP, and FTP
- service identification for databases or middleware
- protocols that require multiple reads and writes on the same connection

Less relevant when:

- the target is pure HTTP
- a normal structured HTTP request is enough
- the problem does not involve multi-step session behavior

## Basic structure

Minimal TCP example:

```yaml
id: tcp-detect

info:
  name: TCP service identification
  author: your-name
  severity: info

rules:
  mysql:
    request:
      type: tcp
      host: "{{Hostname}}"
      port: 3306
      data: "\n"
    expression: response.raw.ibcontains(b"mysql") || response.raw.ibcontains(b"mariadb")

expression: mysql()
```

For TLS, change `type` to `ssl`.

## Decide when to use `steps`

If the protocol can be handled with one send and one read, you can often start with:

- `type`
- `host`
- `port`
- `data`

But once any of the following is true, `steps` is usually the better fit:

- the server sends a banner first
- you need multiple read and write turns
- you want to save intermediate values by phase
- the response ends with a protocol-specific separator

## Why `steps` matters

Older `tcp/ssl` rules are fine for simple "write once, read once" interactions. But many real protocols need:

1. connect and read the server banner first
2. send a command
3. read one or more follow-up responses

That is exactly what `request.steps` is for.

## Basic `steps` structure

```yaml
request:
  type: tcp
  host: "{{host}}"
  steps:
    - read:
        read-size: 4096
        read-timeout: 3
        read-until: "\r\n"
        read-type: bytes
        save-as: banner
    - write:
        data: "CAPA\r\n"
    - read:
        read-size: 8192
        read-timeout: 3
        read-until: "\r\n.\r\n"
        read-type: bytes
        save-as: capa
expression: banner.bcontains(b"+OK") && capa.bcontains(b"+OK")
```

### What this flow is doing

1. read the welcome banner and save it as `banner`
2. send `CAPA`
3. read the capability block and save it as `capa`
4. decide the final result in `expression`

## Quick field lookup

| Field | Purpose | Typical usage |
| --- | --- | --- |
| `request.type` | protocol type | `tcp` / `ssl` |
| `request.host` | target host | `"{{Hostname}}"` |
| `request.port` | target port | such as `3306` |
| `request.data` | simple one-shot payload | good for one send / one read |
| `request.steps` | multi-step I/O flow | good for session-style protocols |
| `read-size` | maximum bytes to read | such as `4096` |
| `read-timeout` | per-read timeout | such as `3` |
| `read-until` | separator that ends the read | such as `"\r\n"` |
| `read-type` | storage type | `bytes` / `string` |
| `save-as` | variable name for saved data | such as `banner` |

## Common `read` fields

- `read-size`: maximum bytes to read in this step
- `read-timeout`: maximum wait time for this read
- `read-until`: stop when the separator is found
- `read-type`: type used when storing the result
- `save-as`: variable name for the stored result

## Common `write` fields

- `data`: payload to send
- `data-type`: optional, useful for non-default encodings such as hexadecimal

## `read-type`

This is one of the most important fields when writing multi-step protocol checks.

### `bytes`

Store the result as raw bytes, useful with:

- `bcontains`
- `ibcontains`
- other byte-oriented helpers

### `string`

Store the result as text, useful with:

- `icontains`
- `toLower`
- other string helpers

### Omitted `read-type`

When omitted, the value is stored as a structured response object, which is useful when you want richer fields rather than only raw content.

## How to choose `read-type`

The shortest rule of thumb:

- want byte matching: use `bytes`
- want string matching: use `string`
- want richer structure: omit `read-type` first

## `read-until` boundaries

- if the separator is found within `read-size`, the returned value includes content up to that separator
- if not found, the read returns on size limit or timeout with whatever data was collected
- common escaped forms work directly, for example:
  - `"\r\n"`
  - `"\r\n.\r\n"`

## Why POP3 is a good example

POP3 often follows this pattern:

1. server sends a `+OK` banner first
2. client sends `CAPA`
3. server returns a multi-line capability list

If you use a single `data` exchange only, you can easily end up with:

- banner data not fully consumed
- multi-line responses cut off
- unstable state checks

`steps` is built for this kind of interaction.

## Minimal workflow

When writing a TCP / SSL PoC, this order tends to work best:

1. decide whether it is one-shot or multi-step
2. try `data` first for one-shot cases
3. switch to `steps` for real session flows
4. save key intermediate values with `save-as`
5. keep `expression` focused on the most stable signals

## Usage suggestions

1. For banner-first protocols, the first step is usually `read`
2. For multi-line endings, prefer `read-until`
3. Save key intermediate values with `save-as` so later expressions can inspect them
4. For TLS-enabled ports, it is often simplest to add a parallel `type: ssl` rule
5. Keep the number of I/O rounds minimal first, then grow the flow only if needed

## Common misunderstandings

### Writing many `steps` just because it is not HTTP

If the protocol only needs one send and one read, a simple `data` request is often enough.

### Forgetting `save-as` and then needing the value later

In multi-step protocols, intermediate data often becomes the later match input. Save it as soon as it matters.

### Using an inaccurate `read-until`

When the separator is wrong, the most common outcomes are truncated responses and unstable matching.

## One-line takeaway

The hard part of TCP / SSL PoCs is usually not "how do I send a packet", but "how do I split the session into the right steps and keep the important values".

> **← Previous:** [Raw HTTP](./07-raw-http.md) ｜ **Handbook home:** [PoC Quickstart](./01-quickstart.md) ｜ **Next →:** [PoC Contributors](./09-contributors.md)
