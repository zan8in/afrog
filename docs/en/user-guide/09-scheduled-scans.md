<!--
title: Scheduled Scans
slug: /docs/user-guide/scheduled-scans
lang: en
summary: Configure periodic scans with frequency presets: how to create one, when it fires, where results appear, and what happens on downtime or expiry.
status: published
source: new
last_reviewed: 2026-09-30
-->

## Why you want it

The value of scanning is not "we ran it once" but **running it continuously**. A scheduled scan turns one configuration into a periodic task: same targets, same PoC scope, same parameters, re-run on a fixed rhythm — you only step in when the results change.

Typical uses:

- Daily sweep: a full scan of core assets once a day at a fixed time
- Weekly re-test: systems with slow release cycles, confirming on Monday morning that last week's fixes did not regress
- Hourly watch: newly exposed surface or a high-severity PoC scope, to shrink the exposure window

Scheduled scans are a **Curated member feature**. Regular users can open the page, but it shows a locked preview.

## Creating a schedule

On the **Schedules** page, four things define a schedule:

| Field | Notes |
| --- | --- |
| Name | Shows up in the task list; make it descriptive, e.g. "Acme daily sweep" |
| Targets | Pick a **project** (recommended — asset changes follow automatically) or enter a set of ad-hoc targets |
| Scan configuration | Identical to a manual scan: intent, PoC scope, concurrency/rate/timeout, port scan, web probe (`-w`), OOB, etc. |
| Frequency | See below |

### Frequency presets

There is no cron expression to write; three presets cover most recurring scans:

| Frequency | Parameters | Example |
| --- | --- | --- |
| Every N hours | N (1–168) | Every 6 hours |
| Daily | HH:MM | Daily at 09:30 |
| Weekly | Weekday + HH:MM | Mondays at 08:00 |

Targets are validated at save time: a missing project, a project with no valid assets, or an empty ad-hoc target list fails immediately — better to tell you now than to leave behind a schedule that silently fails at every tick.

A single instance holds up to 100 schedules.

## When a scan actually starts

**Saving (creating or editing) does not run anything** — it stores the schedule and computes the next run time. The server-side scheduler fires it when that time arrives:

- The scheduler checks the schedule table every 30 seconds and starts anything that is due
- To verify a configuration right away, use **Run now** in the list: it runs once and does not disturb the existing rhythm
- Every triggered task takes the same path as a manual scan: same asset sink, same project attribution, same notifications, same ledger entries

Each row in the list shows the frequency, where the targets come from, the last run outcome, and the next run time:

```text
Acme daily sweep
Daily 16:01
Project: Acme · 42 targets · Last: fired 2026-09-30 16:01 · Next: 2026-10-01 16:01
```

`Last` has four states:

| State | Meaning |
| --- | --- |
| Not run yet | The schedule exists but no run time has passed |
| Fired | Started as planned; look in Scan / Ledger for results |
| Failed to fire | Due, but could not start (e.g. targets became invalid); the reason is shown |
| Skipped | Not executed (e.g. membership expired) |

### Changing frequency, disabling, deleting

- **Change frequency**: the next run time is recomputed on save
- **Disable**: it stops firing. **Re-enabling** schedules from the current time; runs missed while disabled are not replayed
- **Delete**: the schedule disappears at once; tasks and results it already produced are untouched

## Schedules missed during downtime

On startup the server checks the schedule table immediately: if a "next run" is already in the past, it **runs once**, then continues on the original rhythm.

So a service that was down for three days does not dump three days of work on startup — each schedule catches up once, giving you the latest state of things.

## Where results appear

A scheduled run does not disappear into the background:

- **Scan page**: the task shows up in the list tagged with its `schedule` origin and named after the schedule by default. Its process events (web probe, ports, hits) can be replayed, and the detail page shows stats and diagnostics
- **View last result** in the schedule list: jumps to the ledger filtered to that task, so you can see what it actually found
- **Ledger / Reports**: aggregate by project, time, and severity; track status transitions
- **Notifications**: hit and completion messages go out on the configured channels

After a service restart, recent task records remain visible on the Scan page (the latest 200 are kept), and findings are always reachable in the ledger by task id.

## What happens when membership expires

Schedules do not vanish silently:

- The run time still advances, but nothing starts
- That run is recorded as `skipped` with the reason "scheduled scans are a Curated feature"
- After renewal, no rebuilding is needed — the next due time resumes execution

## Where the configuration lives

Schedule configuration is stored in `~/.config/afrog/schedules.json`, separate from the database (`~/.config/afrog/afrog.db`):

- Schedules are configuration: easy to back up and review by hand
- Tasks are data: findings are kept long term

> **← Previous:** [Web Scan Workspace](./08-web-console.md) ｜ **Handbook home:** [What afrog does](./01-overview.md) ｜ **Docs home →:** [afrog Docs](../index.md)
