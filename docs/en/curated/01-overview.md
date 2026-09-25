<!--
title: What curated PoCs are
slug: /docs/curated/overview
lang: en
summary: What curated PoCs (the subscribed PoC feed) are, why they beat built-in PoCs, and what you need before you start.
status: published
source: afrog.wiki/Afrog 支持星球PoC自动更新功能.md
last_reviewed: 2026-09-23
-->

## What curated PoCs are

Curated PoCs are `afrog`'s licensed PoC distribution capability — what is commonly called the **"curated PoC feed"**.

Once you join the subscription community you receive a personal license, and `afrog` mounts and updates the latest high-severity PoCs at startup. **Always current at launch, always battle-ready when scanning** — no manual downloading or unzipping, and your vulnerability knowledge base stays up to date.

It turns PoC updates from "shipped with the engine release" into "updated dynamically under a license".

## How they differ from built-in PoCs

| Aspect | Built-in PoCs | Curated PoCs |
| --- | --- | --- |
| Source | Released with the `afrog` version / repository | Delivered by the curated service |
| Updates | Tied to `afrog` releases | Automatic update checks at startup |
| Distribution control | None | license / channel control both visibility and update track |
| How to get them | Bundled with the engine | Join the [subscription community](https://t.zsxq.com/lV66x) for a license |

## Highlights

- **Current at launch**: configure a license once, and every subsequent start mounts and updates automatically
- **Silent background updates**: checked roughly every 6 hours by default, with no cost to scan time or speed
- **Nothing new to learn**: no new commands are introduced; usage is exactly as before
- **Can be turned off temporarily**: when a task should only use open-source PoCs, one flag disables it without touching the configuration

## What you need

- A personal **License Key**: obtained after joining the [subscription community](https://t.zsxq.com/lV66x), it is the only credential for syncing curated PoCs, so keep it safe
- A reasonably recent `afrog`: use the latest version (`afrog -v` shows the current one); the client has been built in since v3
- The `curated` section filled in inside `afrog-config.yaml`, see [Configuration and usage](./02-usage.md)

> **← Docs home:** [afrog Docs](../index.md) ｜ **Next →:** [Configuration and usage](./02-usage.md)
