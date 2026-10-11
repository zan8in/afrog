<!--
title: Tasks and Live Progress
slug: /docs/web/tasks
lang: en
summary: The running/history split of the task list, pause/resume/stop, the event-stream tabs on task details, and result export.
status: published
source: new
last_reviewed: 2026-10-10
-->

## Task list

The "Scan" page splits tasks into two:

- **Running**: tasks that are executing or queued, run in order behind the concurrency limit
- **History**: completed / failed / cancelled tasks

Running tasks can be **paused, resumed, and stopped**. Pause and resume act on the scan process, and the elapsed timer freezes along with it.

Task origins are tagged: those started manually on the page, those triggered by [Scheduled Scans](./07-scheduled-scans.md) (tagged with a "schedule" origin), and those [dispatched remotely](./08-cluster.md) from other consoles.

## Task details and the live event stream

Open a task and the process is pushed in real time through an **event stream**, split into several tabs:

| Tab | Content |
| --- | --- |
| Vulnerabilities | The list of findings, expandable down to request/response evidence |
| Asset discovery | Port scan and web probe results (only present when the relevant options are enabled) |
| Diff vs last | The difference from the same project's previous scan: new / fixed / still open (member) |
| Stats | Hit count per severity, target count, PoC count, actual executions |
| Diagnostics | The engine's process logs, for diagnosing "why nothing ran" |

### Two guarantees of the event stream

- **Resume after disconnect**: events carry sequence numbers, and when the browser reconnects it sends `Last-Event-ID` to continue from the breakpoint, so no events are missed.
- **Replay**: for tasks not started from this page (such as scheduled scans), opening them replays the process events since the scan started, so web probes, ports, and hits are all present.

## Export and print

After a scan finishes you can export the whole task result as HTML / Excel / Markdown, or print it to PDF (export is a member feature). The exported content matches the [vulnerability report](../user-guide/06-output-and-report.md) conventions.

## After a service restart

Task records are stored in the local database, so after a restart recent tasks can still be opened from the history list; only the **per-event detail is no longer kept** — the findings themselves remain queryable in the [vulnerability ledger](./05-ledger.md).

> **← Previous:** [Launching a Scan](./02-scan.md) ｜ **Handbook home:** [Web Console Overview](./01-overview.md) ｜ **Next →:** [Assets and Projects](./04-assets-projects.md)
