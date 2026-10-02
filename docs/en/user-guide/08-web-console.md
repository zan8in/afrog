<!--
title: Web Scan Workspace
slug: /docs/user-guide/web-console
lang: en
summary: Run scans from the built-in web console: start it, sign in, launch scans, follow the live event stream, and keep results.
status: published
source: new
last_reviewed: 2026-09-30
-->

## What the web console is

Besides the command line, `afrog` ships with a web console. Same engine, a graphical way to drive it: enter targets in the browser, run scans, watch progress, review results, organize assets and projects, and turn findings into a trackable ledger.

The point is not "one more UI" — it is to turn a one-off scan into a **workflow you can come back to**:

- Scans run on the server; closing the browser does not interrupt them
- Progress, discovered assets, findings, and diagnostics stream in live
- Findings are stored automatically and can be aggregated by task, project, or vulnerability
- Scheduled scans make "run it every day" stop depending on a human pressing a key

## Starting it and signing in

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

The password is random on every start. Open the console in a browser and sign in with it. **Closing the terminal stops the service**, so run it somewhere persistent.

> Note: the server does not terminate TLS itself. If you expose it publicly, put it behind a reverse proxy with TLS and access control.

## Where data lives

| Content | Location |
| --- | --- |
| Findings, assets, projects, ledger, task records | `~/.config/afrog/afrog.db` (SQLite) |
| Scheduled scan configuration | `~/.config/afrog/schedules.json` |

Findings are long-lived data and are kept indefinitely. Task records (status, targets, duration, hit counts of one scan) keep only the **most recent 200** entries to back the history list in the UI. Older tasks can still be found by task id in the ledger.

## Navigation

The sidebar groups pages by purpose:

| Group | Page | What it does |
| --- | --- | --- |
| Workspace | Overview | Data summary and recent activity |
| | Scan | Launch scans, watch running and past tasks |
| | Schedules | Re-run the same scan configuration on a timer |
| | Projects | A business unit: a set of assets plus its scan history |
| | Assets | Targets sink in automatically; tag and star them |
| Results | Reports | Filter findings by task, keyword, severity |
| | Ledger | Track finding status (pending/confirmed/false positive/fixed) and notes |
| Data | PoCs | Browse, edit, and add custom PoCs |
| | Curated | Mount status and updates for licensed curated PoCs |
| Other | Docs | In-app documentation |
| | Settings | Account, notifications, service info |

Pages marked as member features (Schedules, Ledger, Curated) are still reachable for regular users, but show a locked preview until the plan is upgraded.

## Launching a scan

Enter targets on the **Scan** page. The input recognizes and normalizes these forms, one per line or comma separated:

- URLs: `https://example.com/login`
- Domains: `example.com`
- IPs with ports: `192.168.1.10:8080`
- CIDR ranges: `10.0.0.0/24`

The scan intent decides how many PoCs run:

| Intent | When to use it |
| --- | --- |
| Quick check | One target, high-severity PoCs, an answer in seconds |
| Standard scan | Full PoC set, runs in the background, breadth first |
| Re-test diff | Compare against the project's previous scan to see what got fixed (member) |

Open **Advanced** when you need finer control: concurrency, rate, timeout, proxy, OOB, port scan, web probe, PoC scope, severity filters — all identical to the CLI flags.

A re-test diff needs the task to belong to a project: the project is how "the previous scan" is found.

## Task list and live progress

The **Scan** page splits tasks in two:

- **Running**: executing or queued behind the concurrency limit
- **History**: completed, failed, or cancelled tasks

Running tasks can be **paused, resumed, and stopped**. Pause and resume act on the scan process, and the elapsed timer freezes with it.

Open a task and the whole run streams in live:

| Tab | Content |
| --- | --- |
| Vulnerabilities | The findings, expandable down to request/response evidence |
| Assets | Port scan and web probe results (when `-w` or port scanning is on) |
| Diff | Changes against the project's previous scan: new / fixed / still open (member) |
| Stats | Hits per severity, target count, PoC count, actual executions |
| Diagnostics | Engine logs, for when you need to know why nothing ran |

When a scan is done you can export the whole task as HTML / Excel / Markdown, or print it to PDF (export is a member feature).

**Tasks show up wherever they came from**: a scheduled scan was not started from this page, yet it appears in the list tagged with its `schedule` origin. Opening it replays the events emitted since it started, so web probes, ports, and hits are not missing.

**After a restart**: task records live in the local database, so recent tasks can still be opened from the history list. Per-event detail is not kept, but the findings themselves stay queryable in the ledger.

## Multiple instances (Overview page)

The **Multi-instance** card on the Overview page aggregates the health of this instance and its peers: version, online status, active task count, CPU / memory, and heartbeat latency.

- With a single instance (no `cluster` configured) you see just this instance, plus a configuration example right in the card
- Peers are listed under `cluster.peers` in `afrog-config.yaml` and share a `cluster.token`; see [Configuration](./05-configuration.md)
- This instance reads each peer every 30 seconds and shows the reason when one is unreachable (token mismatch / outdated version / cannot connect) instead of dropping the node from the list
- The aggregated view is a Curated member feature: regular users can see how many nodes the cluster has, but only this instance is expanded

**Adding or removing nodes at runtime (members, no restart)**: **Edit nodes** at the top right of the card lets you change this instance's name, the cluster token, and the peer list. Saving writes `afrog-config.yaml` and rebuilds the heartbeat immediately — a new node shows up right away (as *probing* until its first heartbeat completes) and `afrog` does not need a restart.

The heartbeat itself stays on a fixed 30-second rhythm and the config file is read once at startup, so a config file edited by hand still needs a restart. Validation on save: addresses must be http/https (the scheme may be omitted), duplicates are dropped, at most 64 peers, and a token is required as soon as peers exist.

### Cross-node dispatch (members)

The Scan workbench now has an **Execution node** selector (online peers plus this instance, defaulting to this instance). Pick a node and hit **Start scan** and that node runs the scan.

- **The task belongs to the executor**: the task, its event stream and its findings all stay on the executing node (single source of truth); the initiator only keeps a mirrored record showing node name, status, progress and hit count
- **Read-only findings proxy**: opening a remote task on the initiator shows that node's findings read-only — no separate login to the other node required; local reports and the ledger do not include remote findings
- **Disconnection consistency**: every dispatch carries an idempotency key so retries or network flapping never start the scan twice; when the executor cannot be reached the task is flagged **node unreachable** and keeps the last reconciled status (never a false *failed*), then resumes reconciling automatically
- **Survives restarts**: mirrored records are persisted to `~/.config/afrog/remote_tasks.json`, so the task list is intact after an initiator restart and unfinished tasks resume reconciling automatically (the scan itself always runs on the executor)
- **Dispatch by project**: pick a project on the initiator and dispatch. The initiator resolves it to a concrete target list locally before sending, so the executor needs no copy of that project; the remote task scans only those targets and is not filed under any project or ledger entry on the executor
- **Schedules can dispatch too**: the schedule form offers the same **Execution node** field, so a recurring scan is handed to that node automatically when it fires (see [Scheduled scans](./09-scheduled-scans.md))
- **Requirements**: both sides must share the same `cluster.token` (an instance without a token accepts no dispatches), and only Curated members can dispatch

## Assets, projects, and the ledger

These three pages are the workspace around scanning:

- **Assets**: targets from every scan sink in automatically (zero maintenance); you can also add or import them by hand. Scanned assets record `last_scan_at` and `last_task_id`, so you can see when a target was last scanned. Select a batch of assets to hand straight to the Scan page.
- **Projects**: group assets into a business unit. Projects are how scan history, re-test diffs, and per-project rollups are attributed.
- **Ledger**: aggregate findings per (PoC, target) into a work item and track its status (pending / confirmed / false positive / fixed) plus notes. The "view last result" action on a schedule lands here, filtered by task.

## AI verdict

Every ledger row — and every finding on a task's **Vulnerabilities** tab — has a **Verdict** button. Opening it streams six sections word by word:

- **Conclusion**: whether this is a real vulnerability, with a confidence level (high/medium/low)
- **Evidence**: each point traced back to the exact request or response that supports it
- **False-positive risk**: concrete scenarios (e.g. "the payload is only echoed back, no execution result")
- **Manual verification**: confirmation steps you can follow in three moves or fewer
- **Impact** and **Remediation**

It solves "a pile of findings and no idea which one is real or which to read first": minutes of reading request/response by hand become seconds of reading a conclusion.

Constraints worth knowing before you use it:

- **Never automatic**: a request is made only when you click, so nothing burns in the background; re-opening the same finding is served from the local cache
- **Evidence-bound**: the prompt forbids introducing facts that are not in the evidence, requires saying "insufficient evidence" rather than guessing, and bans inventing CVEs or vendor advisories — the output is advice only
- **It never decides for you**: ledger status is still changed by you; a verdict never flips a finding to "confirmed"
- **Masked before sending**: `Cookie`, `Authorization`, `Set-Cookie` and similar headers are hidden and long bodies truncated — but the request and response of that finding still go to the model service you configure
- **No dead ends when unconfigured**: the button stays visible and points you to **Settings → AI assist**; the free tier allows 20 verdicts per month, Curated members are unlimited

See the `ai` field dictionary in [Configuration](./05-configuration.md), or fill it in under **Settings → AI assist** (takes effect immediately, no restart).

### Report executive summary

The Reports page also has an **AI summary** button that produces an executive summary you can paste straight into a deliverable:

- With a task in scope (e.g. arriving from a task's detail page or a schedule's "view last result"), the summary covers that scan: what was in scope, an overall risk rating, key risks, and what to do next
- Without a task it rolls up the current filter (severity / keyword) across tasks, and the prompt explicitly says it is a filtered result rather than a single scan, so the scope is never misstated
- The output has a one-click **Copy** as Markdown; re-opening the same scope is served from cache and never re-billed

Only statistics and the finding list are sent for a summary (no raw request/response), which is why it is good at the big picture and prioritisation; use **Verdict** above when you need to judge whether one specific finding is real.

### Recommended scan parameters

After pasting targets into the **Scan** workbench, click **AI recommended parameters**. Based on the scale and mix of your targets (URL / IP / CIDR / domain) and the current intent (quick check / standard scan), the model returns two to four reasons and a ready-to-use set of parameters — concurrency, rate, timeout, smart concurrency, port scan, web fingerprint, severity and so on. Click **Apply recommended parameters** at the bottom of the drawer to write them into the form (you can still tweak them afterwards); use **Regenerate** if you disagree.

- **Only a target profile is uploaded**: target count, type mix, and at most 20 samples — never the full list
- **Values stay in range**: out-of-range numbers are clamped to the form's limits and invalid severities dropped, so the form is never left unusable
- **Only recommended fields are applied**: anything the model did not return keeps your current setting
- **Re-opening the same targets is served from cache**, so the model is not called again; when no model is configured you are pointed to **Settings → AI assist**

## Relation to the CLI

The web console does not replace the CLI; both share the same engine and PoCs:

- The CLI fits one-off, scripted, custom-output work
- The web console fits continuous operation, process visibility, and results a team needs to review

Scan parameters (concurrency, rate, timeout, OOB, port scan, web probe, PoC scope) mean exactly the same thing on both sides — see [CLI Options](./04-cli-options.md).

> **← Previous:** [Practical Tips](./07-tips.md) ｜ **Handbook home:** [What afrog does](./01-overview.md) ｜ **Next →:** [Scheduled Scans](./09-scheduled-scans.md)
