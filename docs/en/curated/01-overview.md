<!--
title: What curated PoCs are
slug: /docs/curated/overview
lang: en
summary: What curated PoCs are, how they differ from built-in PoCs, and what you need to get started.
status: published
source: new
last_reviewed: 2026-09-23
-->

## What curated PoCs are

Curated PoCs are `afrog`'s licensed PoC distribution capability: PoCs are delivered by a curated service, mounted locally by clients with a license, and loaded automatically by `afrog` at startup.

It moves PoC distribution from "shipped with the engine release" to "updated dynamically under a license", while license and channel control both visibility and update track.

## How they differ from built-in PoCs

| Aspect | Built-in PoCs | Curated PoCs |
| --- | --- | --- |
| Source | Released with the `afrog` version / repository | Delivered by the curated service (encrypted AFCP pack) |
| Updates | Tied to `afrog` releases | Automatic update checks once licensed |
| Distribution control | None | Controlled by license / channel |
| Offline | Bundled | Supports offline AFCP pack installation |

## When to use them

- You need a license to control PoC distribution and updates
- You want a local PoC directory that updates automatically, can roll back, and can be installed offline
- You do not want to ship static object-storage credentials to clients

## What you need

- A curated service endpoint (for example `https://pro-api.example.com`)
- A `license_key`
- The `afrog-curated` binary, which handles login, mounting, and updates

## In this handbook

1. [Using curated PoCs in afrog](./02-usage.md)
2. [afrog-curated command reference](./03-tool-reference.md)

> **← Docs home:** [afrog Docs](../index.md) ｜ **Next →:** [Using curated PoCs in afrog](./02-usage.md)
