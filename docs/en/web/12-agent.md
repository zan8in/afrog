<!--
title: Agent Tools (MCP)
slug: /docs/web/agent
lang: en
summary: Inspect and drive the MCP tool surface from the web console: a review queue for candidate PoCs and tuning suggestions, a tool bench to inspect and call tools, and a policy & audit panel to adjust the gate and review decisions.
status: published
source: new
last_reviewed: 2026-11-15
-->

## What this is

[`afrog mcp`](../user-guide/10-mcp.md) exposes afrog's capabilities as a set of MCP tools for an AI Agent to call under policy, budget, and audit constraints. The **Agent** group in the web console brings that same tool surface into the GUI, across three pages:

| Page | What it does | Equivalent CLI |
| --- | --- | --- |
| Review Queue | Handle candidate PoC drafts and tuning suggestions: inspect evidence, approve or reject | `afrog poc` / `afrog learn` |
| MCP Tools | View each tool's capability level and availability, call it with the same name and semantics, copy a client config | the `afrog mcp` tool surface |
| Policy & Audit | Adjust the capability mode, destructive switch, session budget, and host scope; review decision history | editing the policy YAML |

The key point: these three pages share **the same gate** as MCP, REST (`/api/v1`), and gRPC (`AgentService`) — the same tool registry, the same policy evaluation, the same budget and audit (`pkg/policy.Gate`). A policy changed here takes effect on the next tool call; the availability and remaining budget you see here are exactly the limits the Agent runs under.

For what each tool means and its inputs/outputs, see [MCP Service](../user-guide/10-mcp.md).

## Review Queue

The design stance is "the Agent can only propose; a human decides what lands." There are two review queues, each mirroring its CLI:

**Candidate PoC drafts** (produced by `poc.submit`): after a model-written draft is run in a constrained real run against a target and evidence is obtained, it enters the queue with status `pending`. Only a human clicking **Approve** here writes the draft into `~/.config/afrog/pocs-my`; **Reject** keeps the draft and a reason. The state machine is `pending → approved / rejected`.

**Tuning suggestions** (produced by `learn.record`): rule/threshold suggestions from the Learner role, stored in the `learn_suggestion` table. **Accepting only records the human decision** — afrog never parses or auto-applies the suggested diff; rule changes still go through the normal code process. The state machine is `pending → accepted / rejected`.

Both queues can be filtered by status. Opening an entry shows a detail drawer:

- A draft's drawer shows the YAML, capability level, request count, target, evidence id, and review history, with an optional rejection reason at the bottom
- A suggestion's drawer shows the suggested diff, its source, and a decision note

The top of the page shows a pipeline summary: total candidates, pending, approved, rejected, auto-ingest rate, and review records.

> Re-submitting a draft with the same id refreshes its content and **returns it to `pending`**: the YAML changed, so the old evidence no longer stands for it.

## MCP Tools

The tool catalog lists every tool:

| Field | Meaning |
| --- | --- |
| Capability | `declarative` (read-only) / `network` (sends packets) / `exec` (execution) |
| destructive | A destructive action, denied by default; requires mode `full` and an explicit opt-in |
| Availability | Allowed or blocked under the current policy; when blocked, the rule and reason are shown |

Opening a tool shows a call drawer: an argument skeleton generated from its `input_schema` is editable, and submitting goes through `POST /api/v1/call`, whose response is byte-for-byte the same as the MCP tool's. A call really consumes session budget, so the catalog refreshes the remaining budget afterwards.

The page header also shows the current mode, remaining session budget, tool count, and audit switch.

The **integration wizard** offers two copyable configurations:

- stdio: hand afrog to the client as an MCP server, `command` = `afrog` and `args` = `mcp -policy <policy-file> -audit <audit-file>`
- HTTP/REST: call `/api/v1` from scripts, authenticated with your console session (`Authorization: Bearer <token>`)

Neither path bypasses the limits — policy evaluation, budget accounting, and audit writes follow the same code path.

## Policy & Audit

The **Policy** panel edits the gate that is currently in effect:

| Item | Description |
| --- | --- |
| Capability mode | `readonly` (read-only default) / `safe` (network) / `full` (includes exec and destructive) |
| Destructive actions | Whether destructive tools such as `act.brute` are allowed; enable only on authorized targets |
| Audit log | Whether every decision is written to the audit JSONL |
| Session budget | Per-session request cap and duration (leave duration empty for no time limit) |
| Tool allow/deny | `allow` / `deny`; **deny always wins** |
| Scope | `allow_hosts` / `deny_hosts` / `deny_paths` |

The evaluation order is fixed: `deny → allowlist → mode → destructive → scope`.

Clicking **Save** writes the policy as YAML (atomically), writes the `policy` and `audit` paths back into the `agent` section of `afrog-config.yaml` (so a restart points at the same files), then discards the old gate — **the next call uses the new policy and the session budget resets**. The panel also shows the reachable capability level and the three file paths.

> The out-of-band adapter (`agent.oob`) is not edited here; it is still set in `afrog-config.yaml`. Its current value is preserved when you save the policy.

The **Audit** table shows the latest 200 decisions (newest first, capped at 1000), each with time, action, target, allow/deny, matched rule, reason, and remaining budget. An unconfigured path, a missing file, or a corrupted line never breaks the panel — it just shows a note.

## FAQ

**All tools show as "blocked"?**
The default policy is **read-only**: a freshly started service does not automatically gain packet-sending ability. Loosen the mode (`safe` / `full`) on the Policy & Audit page, or add the tools you need to `allow`.

**Why did the budget increase after saving the policy?**
Saving discards the old gate and rebuilds it, and `budget.requests` is a **per-session** cap, so the remaining budget resets. In the long-running web service, this budget is the whole process's session budget, decremented across requests.

**I approved a candidate but the PoC is not there?**
`approve` refuses a candidate whose id collides with a non-`my` source (curated / local / append / builtin), to avoid writing into `pocs-my` and then being silently ignored by dedup priority. Such a conflict reports an error instead of succeeding silently.

> **← Previous:** [Passive Scanning and Coverage](./11-passive.md) ｜ **Handbook home:** [Web Console Overview](./01-overview.md)
