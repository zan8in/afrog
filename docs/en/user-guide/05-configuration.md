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

`afrog-config.yaml` maps to the structs in `pkg/config/config.go`. The top-level keys group as follows:

| Top-level key | Type | Purpose | Default / note |
| --- | --- | --- | --- |
| `server` | string | Web service listen address | default `:16868` |
| `reverse` | object | OOB / reverse provider settings | grouped by provider |
| `webhook` | object | DingTalk and WeCom notification settings | generated as an empty template |
| `cyberspace` | object | cyberspace search provider settings | currently includes `zoom_eyes` |
| `curated` | object | curated pocs settings | default `enabled: auto` |
| `cluster` | object | multi-instance orchestration (web console) | empty means single instance |
| `ai` | object | model access for AI assist | empty means not configured |
| `passive` | object | embedded passive scan (MITM proxy + detectors) | not started automatically |
| `observe` | object | observation stream (`observe.observations`) retention | keeps 200k rows by default |
| `agent` | object | policy and audit for the web Agent write-action surface (`/api/v1/call`) | empty means read-only, no network sends |
| `security` | object | high-risk action gate (cluster dispatch, etc.) | allow by default |

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

## `cluster` field dictionary

`cluster` configures multi-instance orchestration: it lets one web console show the health of several `afrog` instances on its Overview page. Leave it empty for a single instance — the console works as usual.

| Field | Type | Purpose | Default |
| --- | --- | --- | --- |
| `name` | string | display name of this node | empty (the UI shows "this instance") |
| `token` | string | cluster-wide shared secret used between instances | empty (an instance without it exposes nothing) |
| `peers` | object[] | peer instances | empty |
| `peers[].name` | string | peer display name | empty (falls back to the URL) |
| `peers[].url` | string | peer web console address | — |

```yaml
cluster:
  name: "hq"
  token: "cluster-shared-secret"
  peers:
    - name: "node-a"
      url: "http://10.0.0.11:16868"
    - name: "node-b"
      url: "http://10.0.0.12:16868"
```

Key points:

- Every node in the same cluster must share the **same token**; a URL without a scheme is treated as `http://`
- This instance reads each peer's `/api/cluster/self` every 30 seconds and shows the reason on screen when a peer is unreachable
- An instance without `token` never exposes its own state — that is the secure default
- The same `token` also authorises **cross-node dispatch**: an instance without a `token` neither exposes its state nor accepts dispatches (see [Web console](./08-web-console.md))

## `ai` field dictionary

`ai` powers **AI assist** — it lets a model review a finding together with its raw request and response (see [Web console](./08-web-console.md#ai-verdict)). Leave it empty and the UI guides you through filling it in. Only the OpenAI-compatible `POST {base_url}/chat/completions` protocol is implemented, so switching providers means changing `base_url` and `model` only.

| Field | Type | Purpose | Default |
| --- | --- | --- | --- |
| `base_url` | string | API endpoint, usually ending in `/v1` | empty |
| `model` | string | model name, e.g. `deepseek-chat` | empty |
| `api_key` | string | credential | empty |
| `timeout_sec` | int | timeout in seconds for one verdict | `60` |
| `max_tokens` | int | output token cap per verdict | `1200` |

```yaml
ai:
  base_url: "https://api.deepseek.com/v1"
  model: "deepseek-chat"
  api_key: "sk-..."
  timeout_sec: 60
  max_tokens: 1200
```

Key points:

- `base_url` / `model` / `api_key` must **all** be set before AI assist is considered configured; a full path (`.../v1/chat/completions`) is recognised too
- You can also fill it in under **Settings → AI assist**, which writes this file and takes effect immediately — no restart needed; **saving only writes the config and never calls the model**, so use **Test connection** on the same page (one tiny request) to confirm it actually works
- A verdict is only requested **when you click**, never in the background; re-opening the same finding is served from the local cache
- Before sending, `Cookie`, `Authorization`, `Set-Cookie` and similar headers are masked and long bodies are truncated — but the request/response of that finding still goes to the model service you configure, so judge accordingly

## `observe` field dictionary

`observe` controls retention for the observation stream (`observe.observations`). The stream records what scans and agent actions observed, and it grows much faster than findings, so a hard cap is required.

| Field | Type | Purpose | Default |
| --- | --- | --- | --- |
| `max_rows` | int | Maximum observation rows kept per database; `0` means unlimited | `200000` |

```yaml
observe:
  max_rows: 200000
```

Notes:

- When over the cap, the writer checks every 1000 inserts and deletes the oldest 10% in `seq` order; cursor semantics are unaffected
- CLI, web and `afrog mcp` share the same config; when unset the 200k default applies
- The stream is best effort: when the buffer is full the tail is dropped and counted, so it is not an audit log

## `agent` field dictionary

`agent` controls the policy and audit source for the Agent write-action surface (the web `POST /api/v1/call`, gRPC, and `afrog mcp` when no flags are passed). It is synonymous with `afrog mcp -policy/-audit`: **empty means the read-only default, and no network-sending capability is granted by default**; an explicit `-policy`/`-audit` on the command line wins over these fields.

| Field | Type | Purpose | Default |
| --- | --- | --- | --- |
| `policy` | string | Path to the policy YAML; same format as `afrog mcp -policy` | empty (read-only default) |
| `audit` | string | Path to the decision audit JSONL | empty (no logging) |
| `oob` | string | Tool-surface OOB adapter (`ceyeio`/`dnslogcn`/`alphalog`/`xray`/`revsuit`/`interactsh`, same values as CLI `-oob`); credentials come from the `reverse` section | empty (`act.oob_*` unavailable) |
| `mcp` | object | Access settings for the MCP service, with `listen` (bind address) and `token` (access secret); `afrog mcp` reads these when the matching flag is not passed | empty (`listen` empty means stdio) |

```yaml
agent:
  policy: /path/to/agent-policy.yaml
  audit: /path/to/audit.jsonl
  oob: ceyeio
  mcp:
    listen: 127.0.0.1:16870
    token: your-token
```

Notes:

- **Agent → Policy & Audit** in the web console saves exactly these two fields (the policy lands in `~/.config/afrog/agent-policy.yaml`), so a change made in the UI is also picked up by the plain `afrog mcp` on the command line
- `/api/v1/call` **shares the same policy, budget and audit machinery** as MCP (stdio/SSE/streamable); a script hitting REST directly cannot bypass the limits
- The web server is long-lived, so `budget.requests` is a single session allowance shared by the whole process and debited across requests (same as `afrog mcp -listen`); `budget.duration` is the idle window, after which a fresh session starts with the allowance refilled — no restart required
- Read-only calls (`observe.*`, `plan.next`, `poc.search`, `judge.*`, `learn.*`) consume no allowance and are not subject to any budget limit
- Setting `agent.oob` is what gives the tool surface its OOB capability (`act.oob_payload` mints addresses, `act.oob_wait` waits for a callback), with credentials reused from the `reverse` section; when empty both report "not configured" instead of silently waiting
- `agent.mcp` gives `afrog mcp` and the web console a single source for listen/token: an explicit `-listen`/`-token` on the command line wins, otherwise these values are used, and an empty `listen` still means stdio; startup logs print the values actually in effect (the token is shown masked). Binding to a non-loopback address without a token is refused at startup whether the token would have come from a flag or from the config
- Errors are distinguished by semantics: policy denial `403`, budget exhaustion `429`, unknown tool `404`, bad request `400`

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
