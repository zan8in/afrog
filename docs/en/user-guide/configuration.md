---
title: Configuration
slug: /docs/user-guide/configuration
lang: en
summary: Configuration file behavior, reverse platform settings, and common configuration pitfalls in afrog.
status: published
source: docs/zh/user-guide/configuration.md
last_reviewed: 2026-09-16
---

On first startup, `afrog` creates its configuration file in the current user's home directory:

```text
$HOME/.config/afrog/afrog-config.yaml
```

This file is mainly used for OOB / reverse providers, notifications, and other runtime dependencies.

## Example configuration

```yaml
reverse:
  ceye:
    api-key: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    domain: "xxxxxx.cey2e.io"
  dnslogcn:
    domain: dnslog.cn
  alphalog:
    domain: dnslogxx.sh
    api_url: "http://dnslogxx.sh/"
  xray:
    x_token: "xraytest"
    domain: dnslogxx.sh
    api_url: "http://x.x.0.x:8777"
  revsuit:
    token: "xx"
    dns_domain: "log.xx.com"
    http_url: "http://x.x.x.x/log/"
    api_url: "http://x.x.x.x/helplog"
```

## What `reverse` means

`reverse` configures out-of-band platforms used in validation flows where the target does not return direct evidence, for example command execution, XXE, or SSRF that must be confirmed through DNS or HTTP callbacks.

The most common providers used in the docs are listed below.

## Ceye

This is the most common and easiest provider to get working quickly.

### How to get it

1. Open [ceye.io](http://ceye.io/)
2. Register and log in
3. Copy the `domain` and `api-key` from your account settings
4. Put them into `afrog-config.yaml`

## Dnslog.cn

- very low setup overhead
- easy to start with
- stability can vary

Site:

- [dnslog.cn](http://dnslog.cn/)

## Alphalog

Useful when you want a self-hosted setup.

- requires deploying your own service
- project: [alphalog](https://github.com/AlphabugX/Alphalog)

## Xray

If you already have an Xray reverse environment, it can be connected directly:

- docs: [xray](https://docs.xray.cool/tools/xray/advanced/reverse)

## Revsuit

Another self-hosted option:

- project: [Revsuit](https://github.com/Li4n0/revsuit)
- tutorial: [tutorial](https://mp.weixin.qq.com/s/hGwcMz8sh7BImBjI3wHqnQ)

## Common issues

### Why do I see `reverse service not set`

If you see an error like:

```text
[ERR] ceye reverse service not set: /home/afrog/.config/afrog/afrog-config.yaml
```

it usually means:

- the config file does not exist yet
- the `reverse` section is incomplete
- the current PoC depends on OOB, but the matching provider is not configured

### Do all PoCs require reverse configuration

No. Only PoCs that depend on OOB / reverse validation need it. Normal direct-response checks often do not.

## Related pages

- [First Scan](../getting-started/first-scan.md)
- [Output and Reports](./output-and-report.md)
