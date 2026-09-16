---
title: TCP / SSL
slug: /docs/poc/tcp
lang: en
summary: Multi-step TCP and SSL PoC patterns and saved-variable behavior in afrog.
status: published
source: docs/zh/poc/tcp.md
last_reviewed: 2026-09-16
---

`afrog` supports not only HTTP PoCs, but also `tcp` and `ssl` protocol checks. For services that require "read banner, write command, read response" behavior, `steps` is the recommended approach.

## When to use TCP / SSL

Useful for:

- banner-first protocols such as POP3, IMAP, SMTP, and FTP
- service identification for databases or middleware
- protocols that require multiple reads and writes on the same connection

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

## Usage suggestions

1. For banner-first protocols, the first step is usually `read`
2. For multi-line endings, prefer `read-until`
3. Save key intermediate values with `save-as` so later expressions can inspect them
4. For TLS-enabled ports, it is often simplest to add a parallel `type: ssl` rule

## Related pages

- [PoC Syntax](./syntax.md)
- [Raw HTTP](./raw-http.md)
