---
title: afrog-curated command reference
slug: /docs/curated/tool-reference
lang: en
summary: afrog-curated commands such as login, mount, update, and status, plus environment variables and local files.
status: published
source: new
last_reviewed: 2026-09-23
---

`afrog-curated` is the client-side manager for curated PoCs: it talks to the service, downloads encrypted PoC packs (AFCP), installs them locally, and prints the mounted directory path for `afrog`.

## Commands

### login

Registers the device with the service and obtains a token. Without `--endpoint`, it only writes local state and performs no network login.

```bash
afrog-curated login --endpoint https://pro-api.example.com --license LIC_xxx
```

### mount

Ensures the local curated PoC directory exists, triggers an update check when needed, and prints the directory path.

```bash
afrog-curated mount --endpoint https://pro-api.example.com --channel stable
```

This is the command `afrog` runs at startup.

### update

Two modes: pull updates from the service, or install a local AFCP pack offline.

```bash
afrog-curated update --endpoint https://pro-api.example.com --channel stable

afrog-curated update --afcp /path/to/full.afcp \
  --content-key-b64 "<base64_32bytes_key>" \
  --manifest-id "m-xxxx"
```

### status

Prints local state: license, current directory, manifest id, last check / update time, and last error.

```bash
afrog-curated status
```

### logout

Clears local login and runtime state (it does not delete the installed PoC directory).

### self-update

Self-updates the binary from a download URL, with optional sha256 verification.

```bash
afrog-curated self-update --url "<download_url>" --sha256 "<sha256_hex>"
```

## Common flags

- `--endpoint`: curated service endpoint
- `--license`: license key (defaults to `AFROG_CURATED_LICENSE_KEY`)
- `--channel`: channel, defaults to `stable`
- `--curated-dir`: custom local install directory, defaults to `~/.config/afrog/pocs-curated`
- `--no-update`: disable the remote update check and only print the directory
- `--force-update`: ignore throttling and check for updates immediately
- `--timeout`: timeout in seconds, defaults to `10`
- `--afcp` / `--content-key-b64` / `--manifest-id`: used for offline AFCP pack installation

## Environment variables

- `AFROG_CURATED_LICENSE_KEY`: default license key
- `AFROG_CURATED_DEVICE_FINGERPRINT`: manually specify the device fingerprint (rarely needed; generated and cached locally by default)
- `AFROG_CURATED_MANIFEST_PUBKEY_B64`: manifest signature verification public key (base64, ed25519); when set, the client verifies the signature of the manifest sent by the service

## Local files

The default root directory is `~/.config/afrog/`:

- `pocs-curated/`: the decrypted curated PoC install directory
- `curated-auth.json`: login state (token / device info)
- `curated-device.json`: cached device fingerprint
- `curated-state.json`: runtime state (manifest id, last check / update time, last error)
- `curated-cache/`: download cache (temporary AFCP files)

> **← Previous:** [Using curated PoCs in afrog](./02-usage.md) ｜ **Handbook home:** [What curated PoCs are](./01-overview.md) ｜ **Docs home →:** [afrog Docs](../index.md)
