<!--
title: Configuration and usage
slug: /docs/curated/usage
lang: en
summary: Two steps to configure curated PoCs, then use afrog exactly as you always have.
status: published
source: afrog.wiki/Afrog 支持星球PoC自动更新功能.md
last_reviewed: 2026-09-23
-->

Configuration takes two steps, after which you can use `afrog` exactly as you always have.

## Step 1: get a license

1. **Obtain the license**: join the [subscription community](https://t.zsxq.com/lV66x) to get your personal **License Key** (the only credential for syncing curated PoCs — keep it safe)
2. **Check the version**: use the latest `afrog` and run `afrog -v` to see the current version; the client has been built in since v3

## Step 2: edit the configuration file

Open the main configuration file:

```text
~/.config/afrog/afrog-config.yaml
```

Find or add the `curated:` section and fill in the required fields following the comments:

```yaml
curated:
  # [required] master switch (auto is recommended)
  # auto: detect automatically, on as soon as the configuration is valid
  # on:   force on
  # off:  disable the feature
  enabled: "auto"

  # [optional] automatic updates (default true)
  # when on, updates are checked silently in the background (roughly every 6 hours)
  # and scan speed is unaffected
  auto_update: true

  # [required] curated PoC service endpoint (provided by the author)
  # keep whatever value the author gives unless told otherwise
  endpoint: "https://your-curated-endpoint"

  # [required] your personal License Key
  # paste it directly and make sure there is no stray whitespace
  license_key: "LIC_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

  # [optional] update channel, for example stable / beta
  channel: "stable"

  # [optional] load timeout (default 10)
  # raise it to 20 or 30 on a poor network
  timeout_sec: 10
```

### Field quick reference

| Field | Required | Purpose |
| --- | --- | --- |
| `enabled` | yes | whether curated PoCs are loaded. `auto` is the least fuss and is recommended |
| `license_key` | yes | **the core of authentication**. Only a correct key pulls curated PoCs |
| `endpoint` | yes | the curated service endpoint, normally supplied by the author and rarely changed |
| `auto_update` | no | set to `true` for effortless updates |
| `channel` | no | the update channel (for example `stable`, `beta`), controlling which PoC releases are pulled |
| `timeout_sec` | no | how long to wait on the service, so network hiccups do not stall a scan |

For the complete field list (including advanced fields such as `bin`), see [Configuration](../user-guide/05-configuration.md).

## How to use it

### 1. Everyday use, nothing to remember

Once configured there is no new command to learn; just use `afrog` as usual:

```bash
afrog -t http://example.com
```

What you get:

- `afrog` mounts the curated PoC directory at startup (`~/.config/afrog/pocs-curated`)
- scan tasks automatically include the latest curated PoCs
- all of it happens in the background, with no manual step

### 2. Force an immediate update

Updates are checked roughly every 6 hours by default. If a critical 0day PoC was just published and you do not want to wait, force it:

```bash
# force an update check and start scanning
afrog -t http://example.com -curated-force-update

# update check only (no scan)
afrog -curated-force-update
```

### 3. Turn it off temporarily

When a single task should only use open-source PoCs, there is no need to edit the configuration — one flag is enough:

```bash
afrog -t http://example.com -curated off
```

## Troubleshooting

- `curated mount failed` at startup: first check that `endpoint` and `license_key` are correct and the network is reachable
- no new PoCs for a long time: check that the license has not expired and that `channel` is the one you expect; raising `timeout_sec` in the configuration can also help
- to keep `afrog` away from curated entirely: use `-curated off`, or leave `endpoint` empty

> **← Previous:** [What curated PoCs are](./01-overview.md) ｜ **Docs home →:** [afrog Docs](../index.md)
