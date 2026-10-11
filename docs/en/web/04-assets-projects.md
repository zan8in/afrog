<!--
title: Assets and Projects
slug: /docs/web/assets-projects
lang: en
summary: How assets sink in and are maintained automatically, and how projects organize a set of assets and carry scan history and re-test diffs.
status: published
source: new
last_reviewed: 2026-10-10
-->

## Assets

The targets of any scan **sink in automatically as assets** (zero maintenance); you can also add or import them by hand.

| Capability | Description |
| --- | --- |
| Automatic sink | Scanned means stored, no manual registration needed |
| Tags and stars | Tag assets and star frequently used targets |
| Scan traces | Record `last_scan_at` and `last_task_id`, so you can look back at "when was this target last scanned" |
| Take to scan | Select a batch of assets to carry straight to the [Scan page](./02-scan.md) and start scanning |

Assets are the **single source of truth** for targets: projects, scans, and scheduled tasks all only reference assets and no longer each keep their own copy of the targets.

## Projects

A project organizes a set of assets into a **business unit** and is the basis for attributing scan history.

- **Scan history attribution**: a scan launched from a project is registered under that project, and the corresponding findings appear in the project's ledger filter and project report.
- **The basis for re-test diffs**: the project is how "the previous scan" is found, so only scans launched from a project can do a [re-test diff](./03-tasks.md).
- **Per-project stats and export**: findings can be aggregated per project, and reports can be exported per project.

### Typical usage

1. Group the assets of the same business system into one project;
2. Launch a "standard scan" from the project;
3. After remediation, launch a "re-test diff" from the project again to see new / fixed / still open.

## Relationship to scanning

- Scans with hand-typed targets: the targets sink in as assets, but are not attributed to any project.
- Scans launched from a project: use the **assets referenced by the project** as the only target source (hand-typed targets do not participate), keeping attribution clean and project data unpolluted.

> **← Previous:** [Tasks and Live Progress](./03-tasks.md) ｜ **Handbook home:** [Web Console Overview](./01-overview.md) ｜ **Next →:** [Ledger](./05-ledger.md)
