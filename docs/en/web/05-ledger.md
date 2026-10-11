<!--
title: Ledger
slug: /docs/web/ledger
lang: en
summary: How the vulnerability ledger aggregates findings into trackable work items, plus status transitions, notes, and AI verdicts.
status: published
source: new
last_reviewed: 2026-10-10
-->

## What the ledger solves

A scan produces a pile of findings, but "which one is real, which to read first, whether it was fixed" is what actually needs tracking. The **vulnerability ledger** aggregates findings by "PoC + target" into a single **work item**, turning the result from a "one-off list" into a "checklist you can move through".

> The ledger is a member feature. Regular users can enter the page and see a locked preview, which unlocks after upgrading.

## Status transitions

Each ledger record has a status and notes:

| Status | Meaning |
| --- | --- |
| Pending | A new finding, not yet judged by a human |
| Confirmed | Manually confirmed to be a real vulnerability |
| False positive | Judged to be a false positive |
| Fixed | Confirmed fixed |

The status is **transited manually** by you, and you can add notes to record the handling process. AI output never changes the status automatically.

## Filtering and origins

The ledger supports filtering by dimensions such as **task, project, keyword**:

- Entering from a task's details carries that task's filter;
- A scheduled scan's "view last result" jumps to a ledger view filtered by task;
- After remote-dispatched findings are backfilled, the entries are tagged with their source node.

## AI verdict

Every row in the ledger has a "Verdict" button; opening it streams, word by word, the conclusion, the basis for the judgment, the likelihood of a false positive, manual verification steps, impact, and remediation advice — compressing "reading request/response one by one" from minutes to the tens of seconds it takes to read a conclusion.

- It is called only once per click, and re-opening the same finding is served from the local cache;
- Sensitive headers such as `Cookie` / `Authorization` are masked before being sent;
- When no model is configured the button is still visible, and opening it guides you to "Settings → AI assist".

See [AI Assist](./09-ai.md).

## Relationship to re-scanning

The ledger is the end of the "track to fixed" loop: after confirming a fix, you can launch another scan (or do a per-project [re-test diff](./03-tasks.md)) to verify.

> **← Previous:** [Assets and Projects](./04-assets-projects.md) ｜ **Handbook home:** [Web Console Overview](./01-overview.md) ｜ **Next →:** [Vuln Library and PoC Editor](./06-poc-library.md)
