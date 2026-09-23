<!--
title: Configuration
slug: /docs/user-guide/configuration
lang: en
summary: Configuration file behavior, reverse platform settings, and common configuration pitfalls in afrog.
status: published
source: docs/zh/user-guide/05-configuration.md
last_reviewed: 2026-09-16
-->

On first startup, `afrog` creates its configuration file in the current user's home directory:

```text
$HOME/.config/afrog/afrog-config.yaml
```

This file is mainly used for OOB / reverse providers, notifications, and other runtime dependencies.

## Configuration dictionary

`afrog-config.yaml` maps to the structs in `pkg/config/config.go`. The top-level keys currently break down into five groups:

| Top-level key | Type | Purpose | Default / note |
| --- | --- | --- | --- |
| `server` | string | Web service listen address | default `:16868` |
| `reverse` | object | OOB / reverse provider settings | grouped by provider |
| `webhook` | object | DingTalk and WeCom notification settings | generated as an empty template |
| `cyberspace` | object | cyberspace search provider settings | currently includes `zoom_eyes` |
| `curated` | object | curated pocs settings | default `enabled: auto` |

The sections below are meant to be directly searchable like a field dictionary.

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

## `reverse` field dictionary

`reverse` configures the providers used by PoCs that need OOB evidence.

### `reverse.ceye`

| Field | Type | Purpose |
| --- | --- | --- |
| `api-key` | string | Ceye API key |
| `domain` | string | domain assigned by Ceye |

Both fields are empty by default and must be filled manually.

### `reverse.dnslogcn`

| Field | Type | Purpose | Default |
| --- | --- | --- | --- |
| `domain` | string | dnslog.cn domain | `dnslog.cn` |

### `reverse.alphalog`

| Field | Type | Purpose |
| --- | --- | --- |
| `domain` | string | Alphalog callback domain |
| `api_url` | string | Alphalog API URL |

### `reverse.xray`

| Field | Type | Purpose | Default |
| --- | --- | --- | --- |
| `x_token` | string | Xray reverse token | empty |
| `domain` | string | Xray reverse domain | empty |
| `api_url` | string | Xray API URL | `http://x.x.x.x:8777` |

### `reverse.revsuit`

| Field | Type | Purpose |
| --- | --- | --- |
| `token` | string | Revsuit token |
| `dns_domain` | string | DNS callback domain |
| `http_url` | string | HTTP callback URL |
| `api_url` | string | Revsuit API URL |

### `reverse.interactsh`

| Field | Type | Purpose | Default |
| --- | --- | --- | --- |
| `server` | string | interactsh server domain | `oast.pro` |
| `token` | string | private interactsh token | empty |

### `reverse.eye`

| Field | Type | Purpose |
| --- | --- | --- |
| `host` | string | eye host |
| `token` | string | eye token |
| `domain` | string | eye domain |

### `reverse.jndi`

| Field | Type | Purpose |
| --- | --- | --- |
| `jndi_address` | string | JNDI service address |
| `ldap_port` | string | LDAP port |
| `api_port` | string | API port |

## `webhook` field dictionary

`webhook` currently supports `dingtalk` and `wecom`.

### `webhook.dingtalk`

| Field | Type | Purpose | Default |
| --- | --- | --- | --- |
| `tokens` | string[] | DingTalk robot token list | `[""]` |
| `at_mobiles` | string[] | mobile numbers to mention | `[""]` |
| `at_all` | bool | whether to mention everyone | `false` |
| `range` | string | severity range that triggers notifications | `high,critical` |

### `webhook.wecom`

| Field | Type | Purpose | Default |
| --- | --- | --- | --- |
| `tokens` | string[] | WeCom robot token list | `[""]` |
| `at_mobiles` | string[] | mobile numbers to mention | `[""]` |
| `at_all` | bool | whether to mention everyone | `false` |
| `range` | string | severity range that triggers notifications | `high,critical` |
| `markdown` | bool | send messages in Markdown format | `true` |

## `cyberspace` field dictionary

### `cyberspace.zoom_eyes`

| Field | Type | Purpose | Default |
| --- | --- | --- | --- |
| `zoom_eyes` | string[] | ZoomEye credential list | `[""]` |

If you plan to use CLI flags such as `-cs zoomeye`, `-q`, and `-qc`, this section usually needs to be configured first.

## `curated` field dictionary

| Field | Type | Purpose | Default |
| --- | --- | --- | --- |
| `enabled` | string | curated mode, supports `auto` / `on` / `off` | `auto` |
| `auto_update` | bool | automatically update curated pocs | `true` |
| `endpoint` | string | curated service endpoint | empty |
| `bin` | string | custom curated binary path | empty |
| `timeout_sec` | int | timeout in seconds for curated mount / calls | `10` |
| `channel` | string | curated channel | `stable` |
| `license_key` | string | license key | empty |

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

### Can I place the config file somewhere else

Yes. The CLI supports the `-config` flag so you can point to an explicit config path:

```bash
afrog -config ./afrog-config.yaml -t https://example.com
```

If you do not pass `-config`, the default path is:

```text
$HOME/.config/afrog/afrog-config.yaml
```

### Which defaults are auto-filled

On first startup, `afrog` writes a template config with defaults. The most important defaults are:

- `server: ":16868"`
- `reverse.dnslogcn.domain: "dnslog.cn"`
- `reverse.interactsh.server: "oast.pro"`
- `webhook.dingtalk.range: "high,critical"`
- `webhook.wecom.range: "high,critical"`
- `webhook.wecom.markdown: true`
- `curated.enabled: "auto"`
- `curated.auto_update: true`
- `curated.timeout_sec: 10`
- `curated.channel: "stable"`

### Do all PoCs require reverse configuration

No. Only PoCs that depend on OOB / reverse validation need it. Normal direct-response checks often do not.

> **← Previous:** [CLI Options](./04-cli-options.md) ｜ **Handbook home:** [What afrog does](./01-overview.md) ｜ **Next →:** [Output and Reports](./06-output-and-report.md)
