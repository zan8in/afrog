<!--
title: Scheduled Scans
slug: /docs/web/scheduled-scans
lang: en
summary: Use scheduled scans to turn "sweep once a day" into an automatic task: configure a recurring/timed re-run of the same scan and review the last result.
status: published
source: new
last_reviewed: 2026-10-10
-->

## When to use it

When you need to **re-run the same scan configuration on a timer or periodically** (for example, "run a batch of high-severity PoCs against some assets every day"), use a scheduled scan instead of kicking it off manually each time.

> Scheduled scans are a member feature. Regular users can open the page and see a locked preview.

## Configuring a schedule

Create a schedule on the **Scheduled Scans** page; its options are essentially the same as a manual scan:

- **Targets**: pick the assets or projects to scan periodically
- **PoCs and parameters**: use the same parameter vocabulary as [scanning](./02-scan.md) (intent, concurrency, rate, timeout, PoC scope, severity and so on)
- **Execution node** (members): optionally hand this scan to an online peer node; see [Multiple instances and remote dispatch](./08-cluster.md)
- **Schedule**: set the trigger time/interval.

The schedule configuration is stored in `~/.config/afrog/schedules.json`.

## What happens when it fires

- When the time comes, the server hands off this scan on schedule and it takes the **same execution path** as a manual scan.
- Schedule-triggered tasks appear in the task list on the **Scan** page with a **"schedule" origin tag**; opening one replays the events emitted since it started, so web probes, ports, and hits are not missing.

## Reviewing the last result

**View last result** on a scheduled scan jumps to the **[findings ledger](./05-ledger.md)** filtered by task, making it easy to compare how the hits changed between each sweep.

## Related

- For scheduled/timed content on the command line see [Timed and scheduled scans](../user-guide/09-scheduled-scans.md);
- For how schedules and tasks differ by origin see [Tasks and the live process](./03-tasks.md).

> **← Previous:** [Vulnerability Library and PoC Editor](./06-poc-library.md) ｜ **Handbook home:** [Web Console Overview](./01-overview.md) ｜ **Next →:** [Multiple instances and remote dispatch](./08-cluster.md)
