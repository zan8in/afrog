---
title: OOB
slug: /docs/poc/oob
lang: en
summary: afrog OOB reference for deciding when to use out-of-band detection, how to write the modern syntax, and how to troubleshoot it.
status: published
source: docs/zh/poc/oob.md
last_reviewed: 2026-09-16
---

OOB (Out-of-Band) is for vulnerabilities where the target really triggers, but the HTTP response does not give you direct evidence.

This page is best for four practical questions:

- is this vulnerability a good fit for OOB
- should I prefer DNS or HTTP callbacks
- what is the current recommended syntax
- where should I start when OOB does not hit

If your PoC can already prove the issue directly from the response, you often do not need OOB first. If the scenario is SSRF, XXE, JNDI, or blind command execution, OOB is often the main path.

## What OOB means

The core idea is simple:

1. make the target access a domain or URL you control
2. query the OOB platform to see whether that access happened

If the callback is recorded, the target really executed the relevant chain.

## Decide when to use it first

Strong fits for OOB:

- SSRF
- XXE
- JNDI
- blind command execution
- asynchronous trigger paths that can only be confirmed through DNS or HTTP callbacks

Usually unnecessary when:

- the response body already proves the issue clearly
- status, headers, or body content are enough for a stable match

## DNS or HTTP first

The most common rule of thumb:

- want broader compatibility: prefer DNS
- want richer callback evidence: prefer HTTP

You can think of it like this:

| Type | Best for | Default instinct |
| --- | --- | --- |
| DNS OOB | SSRF, JNDI, and general blind verification | more common |
| HTTP OOB | cases where you want a clearer callback trail | more explicit |

## Recommended modern syntax

The recommended flow is:

- `{{oob.DNS}}` / `{{oob.HTTP}}`
- `oobCheck(protocol, timeout)`

Minimal DNS example:

```yaml
rules:
  r0:
    request:
      method: GET
      path: /?dns=ping%20{{oob.DNS}}
    expression: oobCheck("dns", 5)

expression: r0()
```

### The three things worth memorizing first

1. use `{{oob.DNS}}` or `{{oob.HTTP}}` directly
2. match with `oobCheck("dns", 5)` or `oobCheck("http", 3)`
3. use `oobEvidence()` when you want the evidence summary back

## Common templates

### DNS callback

```yaml
id: demo-oob-dns

info:
  name: Demo OOB DNS
  author: your-name
  severity: info

rules:
  r0:
    request:
      method: GET
      path: /?dns=ping%20{{oob.DNS}}
    expression: oobCheck("dns", 5)

expression: r0()
```

### HTTP callback

```yaml
id: demo-oob-http

info:
  name: Demo OOB HTTP
  author: your-name
  severity: info

rules:
  r0:
    request:
      method: GET
      path: /?http=curl%20{{oob.HTTP}}
    expression: oobCheck("http", 3)

expression: r0()
```

### JNDI observation

```yaml
id: demo-oob-jndi

info:
  name: Demo OOB JNDI
  author: your-name
  severity: info

rules:
  r0:
    request:
      method: GET
      path: /
      headers:
        User-Agent: "${jndi:ldap://{{oob.DNS}}/a}"
    expression: oobCheck("dns", 5)

expression: r0()
```

## How to choose the timeout

Rule of thumb:

- HTTP OOB: usually `3` seconds
- DNS OOB: usually `5` seconds

If the trigger path may be asynchronous, increase gradually to `8` to `15` seconds.

Do not start with a very large timeout by default. It is usually better to validate with a smaller value first and increase only when needed.

## Where the evidence appears

After a hit, the result usually includes evidence such as `oob_evidence`. You will typically see it in:

- terminal output
- HTML reports
- downstream systems consuming structured results

If you need the evidence inside expressions or outputs, you can also use:

```yaml
oobEvidence()
```

## Quick field and helper lookup

| Item | Purpose | Typical usage |
| --- | --- | --- |
| `{{oob.DNS}}` | OOB DNS domain | query string, header, or payload |
| `{{oob.HTTP}}` | OOB HTTP URL | curl, wget, SSRF target |
| `{{oob.Filter}}` | current filter identifier | less common in hand-written PoCs |
| `oobCheck("dns", 5)` | check whether a DNS callback hit | most common |
| `oobCheck("http", 3)` | check whether an HTTP callback hit | common |
| `oobCheckToken("dns", 5, token)` | validate with an explicit token | advanced |
| `oobEvidence()` | return the latest evidence summary | useful for debugging and output |

## Old syntax vs new syntax

An older style often looks like:

```yaml
set:
  oob: oob()

rules:
  r0:
    request:
      method: GET
      path: /?dns=ping%20{{oob.DNS}}
    expression: oobCheck(oob, oob.ProtocolDNS, 3)
```

The newer recommended style is shorter and more consistent:

```yaml
rules:
  r0:
    request:
      method: GET
      path: /?dns=ping%20{{oob.DNS}}
    expression: oobCheck("dns", 5)
```

### Important reality check

In the current code path, **legacy OOB syntax should no longer be treated as a form worth continuing to write**. The repository already contains explicit legacy OOB detection logic that marks these PoCs as legacy and skips loading them.

So the safer conclusion is not "the old style still works well enough". It is:

- old syntax should be migrated
- new syntax is the form that should continue to be maintained and added

## Common failure reasons

If OOB does not hit, check:

1. the target may not have outbound connectivity
2. the OOB platform configuration may be wrong
3. the timeout may be too short
4. the payload may not actually trigger
5. the PoC may still use outdated syntax or assumptions

## Usage suggestions

1. If direct response evidence is enough, do not force OOB into the PoC
2. For a first version, DNS OOB is usually the easier default
3. Increase timeout gradually instead of starting high
4. Use `oobEvidence()` when you want visible evidence in output or debugging
5. Do not add new PoCs with legacy forms such as `set: oob: oob()`, `{{oobDNS}}`, or `oobCheck(oob, ...)`

## Configuration reminder

The OOB platform itself must be configured first. Common providers include:

- ceye
- dnslog.cn
- alphalog
- xray
- revsuit

Configuration details:

- [Configuration](../user-guide/configuration.md)

## One-line takeaway

OOB is not just a "more advanced normal PoC". It is a separate evidence-chain pattern for non-echo scenarios, so the payload, configuration, and timeout all need to be thought about together.

## Related pages

- [PoC Quickstart](./quickstart.md)
- [PoC Syntax](./syntax.md)
