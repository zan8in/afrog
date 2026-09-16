---
title: requires Fingerprint Gating
slug: /docs/poc/requires
lang: en
summary: afrog fingerprint gating reference for deciding when to use requires and why a PoC gets skipped.
status: published
source: docs/zh/poc/requires.md
last_reviewed: 2026-09-16
---

`requires` and `requires-mode` are the "identify first, verify second" switches of a PoC.

This page is best for two practical questions:

- should this PoC use `requires` at all
- why does this PoC exist but not execute

If you are writing a simple low-cost HTTP PoC, you often do not need this page first. If you are writing weak-password, default-credential, brute-force, or otherwise expensive verification PoCs, this page becomes important.

## Decide when to use it first

The shortest rule of thumb:

- low-cost, generic checks: usually **do not need** `requires`
- expensive checks that only make sense for a specific product: usually **should use** `requires`

Typical fits:

- weak-password checks
- default credentials
- brute-force PoCs
- login probes for a known product or protocol

Less necessary for:

- simple path discovery
- lightweight HTTP echo checks
- PoCs that do not meaningfully increase target cost

## Why fingerprint gating exists

If high-cost PoCs are executed against every target without discrimination, you usually get:

- longer total scan time
- unnecessary login or authentication attempts against unrelated services
- a workflow that lacks "identify first, verify second" discipline

The goal of `requires` is to turn the flow into:

1. run fingerprinting first
2. execute the related PoC only when the matching fingerprint is present

## What to write in the PoC

Both fields live under `info`:

- `requires`
- `requires-mode`

Example:

```yaml
info:
  name: Nacos default credentials
  author: your-name
  severity: high
  requires: [nacos]
  requires-mode: strict
```

### Quick field lookup

| Field | Commonness | Purpose | Default behavior |
| --- | --- | --- | --- |
| `requires` | common | declare which fingerprint tags must match first | no gating when omitted |
| `requires-mode` | common | define what happens when fingerprint data is missing | default `strict` |

## `requires` syntax

Two forms are supported and they mean the same thing.

### Array form

Recommended:

```yaml
requires: [nacos, redis]
```

### String form

```yaml
requires: "nacos,redis"
```

The values are normalized internally:

- trim spaces
- convert to lowercase
- deduplicate

The code path also accepts these `requires-mode` spellings:

- `requires-mode`
- `requiresMode`
- `requires_mode`

## How execution is allowed

The rule is simple:

- no `requires`: no gating
- with `requires`: execute only when the target's matched fingerprint tags intersect with the `requires` values

Those matched tags come from the fingerprint PoC `info.tags`.

### The simplest mental model

The PoC executes only when this is true:

> the current target's fingerprint tags intersect with at least one value in `requires`

Otherwise it is skipped.

## Multi-value semantics

`requires` uses OR semantics, so any matching value is enough.

Example:

```yaml
requires: [nacos, seata]
```

Meaning: execute when the target matches either `nacos` or `seata`.

## `requires-mode`

`requires-mode` defines what happens when no fingerprint result is available.

### `strict`

This is also the default behavior.

The PoC is skipped when:

1. fingerprinting produced no result
2. the fingerprint result does not match `requires`

Useful for:

- weak-password checks
- default credentials
- brute-force PoCs
- other expensive checks you do not want to spray at unrelated targets

In one sentence: **if the engine is not confident enough, do not run it.**

### `opportunistic`

Behavior:

- no fingerprint result: do not block, still execute
- fingerprint exists but does not match: still skip

Useful for lower-cost PoCs where you want narrowing when possible, but do not want to miss a target purely because fingerprint data is unavailable.

In one sentence: **use fingerprint data when present, but do not block purely because it is missing.**

## Why target format matters

Gating needs to map the current scan target to fingerprint results, so target format should stay consistent.

Recommended:

- web targets as full URLs, for example `http://1.2.3.4:8848`
- network services as `host:port`, for example `1.2.3.4:21`

In `strict` mode, if the target is neither a URL nor `host:port`, the PoC may be skipped because the fingerprint result cannot be mapped reliably.

## Two common patterns

### Product-specific credential check

```yaml
info:
  name: Nacos default credentials
  author: your-name
  severity: high
  requires: [nacos]
  requires-mode: strict
```

### Narrow when possible, still run when unknown

```yaml
info:
  name: Medium-cost application check
  author: your-name
  severity: medium
  requires: [seata]
  requires-mode: opportunistic
```

## Typical scenarios

### HTTP application: fingerprint first, then credential check

For example, Nacos:

- fingerprint PoC tags include `nacos,fingerprint`
- credential PoC uses:

```yaml
requires: [nacos]
requires-mode: strict
```

Result:

- run when the target matches Nacos
- skip otherwise

### Network service: fingerprint first, then login probe

For example, FTP anonymous login:

- fingerprint PoC tags include at least `ftp,fingerprint`
- login check uses:

```yaml
requires: [ftp]
requires-mode: strict
```

That means login probes are sent only to confirmed FTP targets.

## Relationship with `-nf`

`-nf` disables the fingerprint stage.

So:

- without `-nf`: `strict` mode can depend on fingerprint results normally
- with `-nf`: `strict` mode will usually skip because no fingerprint result exists

This is also the most common explanation when a `requires` PoC appears not to run.

## Usage suggestions

1. For high-cost PoCs, prefer `strict` first
2. Keep `requires` focused on the primary product tag, not broad categories
3. Fingerprint PoCs should usually expose one primary tag plus `fingerprint`
4. If you run with `-nf`, remember that `strict` mode will usually skip
5. Keep target formatting consistent instead of mixing URLs and bare hosts

## Troubleshooting

When a PoC does not execute, check:

1. whether the target format is normalized
2. whether fingerprinting was disabled
3. whether the fingerprint PoC actually emitted the primary tag
4. whether the PoC should be `opportunistic` instead of `strict`

## One-line takeaway

`requires` is not about limiting features. It is what makes expensive PoCs behave like a disciplined verification workflow: identify first, then act.

## Related pages

- [PoC Quickstart](./quickstart.md)
- [PoC Syntax](./syntax.md)
