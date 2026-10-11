<!--
title: Web Console Overview
slug: /docs/web/overview
lang: en
summary: The role of afrog's built-in web console, how to start it and sign in, where data lives, the interface navigation and permission model, and a guide to this handbook.
status: published
source: new
last_reviewed: 2026-10-10
-->

## What this is

Besides the command line, `afrog` ships with a web console. It shares **the same engine and PoCs** as the CLI; the only difference is how you interact: it turns a one-off command-line scan into a graphical workflow that can **run persistently, show its progress, keep a trail, and be traced back**.

In one sentence: **the command line suits one-off, scripted work; the web console suits continuous operation, watching the process, and letting a team review results.**

## Starting and signing in

```bash
afrog -web
```

It listens on `:16868` by default. To change the address, set it in `afrog-config.yaml`:

```yaml
server: 127.0.0.1:16868
```

On startup the terminal prints this run's access password:

```text
[INF] Web访问密码: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

- The password is **randomly generated on every start**; open the console in a browser and sign in with that run's password.
- The session is a JWT, and the token distinguishes two roles: `curated` (member) and `free`.
- **Closing the terminal is the same as shutting the service down**, so run it in a persistent environment.

> Note: the service itself has **no built-in HTTPS**. To expose it publicly, put it behind a reverse proxy and add TLS and access control yourself.

## Where data lives

| Content | Location |
| --- | --- |
| Findings, assets, projects, vulnerability ledger, task records | `~/.config/afrog/afrog.db` (SQLite) |
| Configuration for scheduled/planned scans | `~/.config/afrog/schedules.json` |

Findings are long-lived data and are kept indefinitely; task records keep only the **most recent 200** entries to back the history list in the UI. Older tasks can still be found by task ID in the vulnerability ledger.

## Interface navigation

The sidebar groups pages by purpose:

| Group | Page | Description |
| --- | --- | --- |
| Workspace | Overview | Data summary, recent activity, and multi-instance status |
| | Scan | Launch scans, view running and past tasks |
| | Schedules | Re-run the same scan configuration on a timer or periodically (member) |
| | Projects | An organizing unit: a set of assets plus their scan history |
| | Assets | Scanned targets sink in automatically; tag and star them |
| Results | Reports | Filter findings by task, keyword, severity |
| | Ledger | Status transitions and notes for findings (member) |
| Data | Vuln Library | Browse built-in/curated PoCs and vulnerability details, write your own PoC |
| | Curated | Member configuration and activation, curated PoC mount status and updates |
| Other | Settings | Account, notifications, OOB, AI, service info |

## Permissions and membership

- The console is **single-user**: one access password, no multi-account system.
- Pages marked as member features (scheduled scans, ledger, cluster, export, and so on) are **still reachable** by regular users, but show a locked preview and unlock after upgrading; the backend validates again, and front-end visibility is only guidance.

## Guide to this handbook

| Page | Content |
| --- | --- |
| [Launching a Scan](./02-scan.md) | Targets, scan intent, advanced parameters, AI recommended parameters, execution node |
| [Tasks and Live Progress](./03-tasks.md) | Task list, pause/resume/stop, result tabs, export |
| [Assets and Projects](./04-assets-projects.md) | Asset sink, tag & star, project attribution |
| [Ledger](./05-ledger.md) | Finding aggregation, status transitions, notes |
| [Vuln Library and PoC Editor](./06-poc-library.md) | Browse / details / authoring / validation |
| [Scheduled Scans](./07-scheduled-scans.md) | Timer and periodic re-runs |
| [Multiple Instances and Remote Dispatch](./08-cluster.md) | Node aggregation, cross-node execution and finding backfill |
| [AI Assist](./09-ai.md) | Finding verdicts, report summaries, parameter recommendations |
| [Settings](./10-settings.md) | Account, notifications, OOB, AI, service info |

If you would like a one-page quick tour first, read [Web Scan Workspace (quick tour)](../user-guide/08-web-console.md).

> **Handbook home:** Web Console Overview ｜ **Next →:** [Launching a Scan](./02-scan.md)
