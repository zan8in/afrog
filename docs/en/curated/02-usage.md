<!--
title: Using curated PoCs in afrog
slug: /docs/curated/usage
lang: en
summary: Enable, disable, and update curated PoCs through CLI flags and configuration.
status: published
source: new
last_reviewed: 2026-09-23
-->

On the `afrog` side there is only one thing to know: at startup `afrog` calls `afrog-curated mount`, then passes the returned directory to the engine through the `AFROG_POCS_CURATED_DIR` environment variable. So "using curated PoCs in afrog" really means configuring an endpoint and a license.

## Shortest path

1. Have your curated service endpoint and `license_key` ready
2. Fill in `endpoint` and `license_key` in the `curated` section of `afrog-config.yaml`
3. Scan as usual:

```bash
afrog -t https://example.com
```

## CLI flags

| Flag | Purpose |
| --- | --- |
| `-curated` | Curated mode: `auto` / `on` / `off` |
| `-curated-endpoint` | Curated service endpoint |
| `-curated-timeout` | Curated mount timeout in seconds |
| `-curated-force-update` | Force a curated PoC update check immediately |

Examples:

```bash
afrog -t https://example.com -curated on -curated-endpoint https://pro-api.example.com
afrog -t https://example.com -curated-force-update
afrog -t https://example.com -curated off
```

## Configuration

The `curated` section of `afrog-config.yaml`:

| Field | Type | Purpose | Default |
| --- | --- | --- | --- |
| `enabled` | string | Mode: `auto` / `on` / `off` | `auto` |
| `endpoint` | string | Curated service endpoint | empty |
| `license_key` | string | License key | empty |
| `channel` | string | Update channel | `stable` |
| `auto_update` | bool | Whether to check for updates automatically | `true` |
| `timeout_sec` | int | Mount / call timeout in seconds | `10` |
| `bin` | string | Custom `afrog-curated` binary path | empty |

For the full field list, see [Configuration](../user-guide/05-configuration.md).

## How enabled or disabled is decided

- `enabled` is `off` / `false` / `0`, **or** `endpoint` is empty → curated is disabled and the local `pocs-curated` directory is cleaned up
- Otherwise `afrog` mounts at startup and passes the mounted directory to the engine through `AFROG_POCS_CURATED_DIR`

In other words, `auto` effectively means "enabled as soon as an endpoint is configured".

## Environment variables

| Variable | Purpose |
| --- | --- |
| `AFROG_CURATED_LICENSE_KEY` | Default license key, so you can keep it out of the config file |
| `AFROG_POCS_CURATED_DIR` | Set by `afrog` after mounting; the engine loads curated PoCs from it |

## Updates and throttling

- At most one update check every 6 hours by default
- `auto_update: false` skips automatic checks unless `-curated-force-update` is used explicitly
- To update right away:

```bash
afrog -curated-force-update
```

## Troubleshooting

- `curated mount failed` at startup: check the endpoint, license, and network connectivity first
- To keep `afrog` away from curated entirely: use `-curated off`, or leave `endpoint` empty
- For command details and local files, see the [afrog-curated command reference](./03-tool-reference.md)

> **← Previous:** [What curated PoCs are](./01-overview.md) ｜ **Next →:** [afrog-curated command reference](./03-tool-reference.md)
