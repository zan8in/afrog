<!--
title: MCP Server
slug: /docs/user-guide/mcp
lang: en
summary: Use `afrog mcp` to expose observation, probing, verification and destructive actions as MCP tools, under policy, budget and audit controls.
status: published
source: new
last_reviewed: 2026-11-14
-->

## What it is

`afrog mcp` exposes afrog's existing capabilities as a set of **MCP (Model Context Protocol) tools**, so Claude Desktop, Claude Code, Cursor or a custom agent can call them directly:

- **Observe**: list findings, fetch evidence, read the attack-surface subgraph (endpoints and parameters included), pull the observation stream
- **Probe**: send a single HTTP request, probe ports, fingerprint a web app, search PoCs, validate a PoC draft
- **Verify**: run one PoC and get replayable evidence
- **Act**: weak-credential / dictionary attempts (off by default)

The design rule is "the agent proposes, execution and evidence stay in afrog": every tool call passes policy, budget and scope checks first. Denials return a structured reason and are never silent.

## Starting it

### stdio (most common)

```bash
afrog mcp
```

Best when the client launches it as a child process; no port required.

### HTTP

```bash
afrog mcp -listen 127.0.0.1:16870 -token your-token
```

One listener serves both transports:

| Path | Purpose |
| --- | --- |
| `/mcp` | Streamable HTTP (mainstream clients since 2025-03-26) |
| `/sse` + `/messages` | Legacy HTTP+SSE |
| `/healthz` | Health check |

Security rules:

- Binding to loopback does not require a token;
- Binding to a non-loopback address **requires** `-token`, otherwise startup is refused;
- Auth accepts `Authorization: Bearer <token>` or `?token=`.

## Client configuration

stdio example (field names vary slightly per client):

```json
{
  "mcpServers": {
    "afrog": {
      "command": "afrog",
      "args": ["mcp", "-policy", "/etc/afrog/mcp-policy.yaml"]
    }
  }
}
```

Remote HTTP clients use a URL and an auth header:

```json
{
  "mcpServers": {
    "afrog": {
      "url": "http://127.0.0.1:16870/mcp",
      "headers": { "Authorization": "Bearer your-token" }
    }
  }
}
```

## Policy

The default policy is **read-only**: a freshly started server never gains the ability to send traffic. Widen it with `-policy`:

```yaml
policy:
  mode: safe                  # readonly | safe | full
  allow: ["observe.*", "probe.*", "verify.*"]
  deny:  ["act.brute"]
  scope:
    allow_hosts: ["10.0.0.0/8", "*.corp.example"]
    deny_hosts:  ["10.0.0.1"]
    deny_paths:  ["/logout"]
  budget:
    requests: 2000
    duration: 30m
  destructive: false
  audit: true
```

### Modes

| Mode | Allowed | Typical use |
| --- | --- | --- |
| `readonly` (default) | `observe.*`, `plan.*`, `poc.search`, `poc.draft`, `judge.*`, `learn.*` | Let the agent read results, reason, and write local advisories |
| `safe` | Adds `probe.*`, `verify.*`, `poc.submit` | Retest and verify without changing target state |
| `full` | Everything not explicitly denied | Full assessment in a controlled environment |

Evaluation order is fixed: `deny → allowlist → mode → destructive → scope`. **Deny always wins.**

### Budget and audit

- `budget.requests` / `budget.duration` are **per-session** limits; exceeding them rejects the call instead of silently allowing it.
- Costly actions (such as `verify.poc`) reserve the PoC's estimated request count instead of a flat 1.
- `audit: true` plus `-audit audit.jsonl` records every call: action, target, verdict, remaining budget.

## Tools

| Tool | Purpose | Capability required |
| --- | --- | --- |
| `observe.findings` | List findings by project, ledger state and severity | read-only |
| `observe.evidence` | Fetch evidence by result id or an `evd_` evidence id | read-only |
| `observe.state` | Attack-surface subgraph around an asset (upstream/downstream, endpoints/parameters, tech stack and candidate PoCs, coverage, findings) | read-only |
| `observe.observations` | Incrementally pull the observation stream by `seq` cursor: open ports, web fingerprints, HTTP transactions, passive proxy traffic, TLS certificates, and out-of-band callbacks | read-only |
| `plan.next` | Compress the attack-surface graph into next-step `Action` proposals (`verify.poc` / `probe.fingerprint`), ranked by a deterministic score with rationale | read-only |
| `poc.search` | Search PoCs by keyword and severity, return local paths | read-only |
| `poc.draft` | Validate a PoC draft: structure, capability level, request estimate; optionally save it for `verify.poc` | read-only |
| `poc.submit` | Run a draft in a restricted sandbox against one real target to obtain evidence, and stage it in the human-review queue (`afrog poc approve/reject`) on success | `verify.*` (per-draft capability; `exec`-level also needs `destructive: true`) |
| `probe.http` | Send one HTTP request; return status, headers, body, latency | `probe.*` |
| `probe.port` | Port probe on one host (top100 by default, 1000 ports max per call); return open ports and service fingerprints | `probe.*` |
| `probe.fingerprint` | Fingerprint one URL: tech stack, WAF/CDN, redirect chain, TLS summary | `probe.*` |
| `verify.poc` | Verify one target with one PoC; return evidence | `verify.*` |
| `verify.replay` | Replay evidence by id and compare id/digest to see whether the old conclusion still holds | `verify.*` |
| `act.brute` | Weak-credential / dictionary attempts | `full` + `destructive: true` |
| `act.oob_payload` | Mint a set of out-of-band callback addresses (`filter` + DNS/HTTP, …) for validations that need a reverse callback (command execution, XXE, SSRF) | `full` + `destructive: true` |
| `act.oob_wait` | Wait for an out-of-band callback; on a hit, return the evidence and write it to the observation stream (`oob_hit`) | `full` + `destructive: true` |
| `judge.brief` | For a result id or evidence id, gather the judging material: the evidence chain, nearby observations for the same target, the attack-surface subgraph, and existing judgements | Read-only |
| `judge.record` | Record a judgement (`likely_true` / `likely_false` / `uncertain`) in the `judgement` table as an advisory for human review; **it never touches the vulnerability ledger** | Read-only (writes a local advisory) |
| `learn.brief` | Fetch tuning material: pipeline stats (including the ingest rate), recent review decisions (with rejection reasons), and pending tuning suggestions | Read-only |
| `learn.record` | Record a tuning suggestion (`rule` / `threshold` / `other`) in the `learn_suggestion` table for human review; **it never applies any diff** | Read-only (writes a local advisory) |

### What evidence looks like

Every finding carries a replayable evidence object:

```json
{
  "id": "evd_...",
  "digest": "sha256:...",
  "poc_id": "redis-weak-login",
  "target": "10.0.0.5:6379",
  "steps": [{ "role": "confirm", "matched": true }],
  "replay": {
    "command": "afrog verify --poc redis-weak-login --target 10.0.0.5:6379",
    "deterministic": true
  },
  "confidence": "certain"
}
```

The evidence id is content-derived: the same finding yields the same `evd_` on any node in any task, so agents can pass references around. During cluster backfill the evidence travels with the finding, so `observe.evidence` works for remote findings too.

### What the observation stream looks like

Evidence answers "why does this finding hold"; the observation stream answers "what else was seen along the way". It is an append-only event sequence cursored by `seq`:

```json
{
  "seq": 1024,
  "id": "obs_...",
  "project_id": "",
  "source": "http",
  "kind": "http_transaction",
  "subject": "http://10.0.0.5/login",
  "ts": "2026-11-14T10:00:00Z",
  "payload": {
    "method": "GET",
    "url": "http://10.0.0.5/login",
    "status": 200,
    "matched": true,
    "latency_ms": 41,
    "request_excerpt": "GET http://10.0.0.5/login\nAccept: */*",
    "response_excerpt": "HTTP/1.1 200 OK\nServer: nginx/1.25.3\n\n..."
  }
}
```

- Seven kinds are recorded: `port_open` (port scan), `tech` (web fingerprint), `http_transaction` (requests actually sent by `probe.*` / `verify.*`), `http_passive` (real traffic seen by the passive proxy), `tls` (https certificate summary), `oob_hit` (out-of-band callback), and `dns` (hostname resolution).
- `http_passive` keeps metadata only (method, URL, status, content type, byte counts) and never stores messages; it is deduped on method + URL + status, so the same endpoint with different query values yields separate rows. Passive observations are published before detection: even if the traffic is later deduped, skipped or dropped, the fact still stands.
- `tls` records issuer, subject, expiry and SANs; `oob_hit` records which filter the target called back and the owning PoC — callback time and source IP do not take part in deduplication.
- `dns` records the addresses a web target hostname resolves to (nothing is recorded when the target is an IP literal itself); address order does not take part in deduplication.
- In `observe.state`, endpoints expose two derived children: `tech:<name>` and `poc:<id>` (edges `tech` / `candidate`). The former is the detected tech stack; the latter is a ready-made candidate matched from the PoC's `info.requires`, meaning "worth verifying" only. Use `depth: 4` to see the full chain from a hostport.
- Paging: pass the returned `next_seq` as the next `since_seq`; filter by `sources`, `kinds`, `subject` and `project_id`. With `subject_under: true`, `subject` is treated as a subtree root (a host includes its ports, an endpoint includes its parameters) rather than a plain prefix.
- Re-scanning the same fact does not add a row: the id is content-derived and deduped on `(project_id, id)`, so it is a stable reference.
- The stream is **best effort**: writes are asynchronous, the tail is dropped (and counted) when the buffer is full, each database keeps 200k rows by default (`observe.max_rows` in `afrog-config.yaml`; `0` means unlimited), and raw messages are not stored (excerpts are capped at 2 KB).

## REST entry (`/api/v1`)

The same web server also exposes REST endpoints with the same names and semantics as the MCP tools, for scripts that cannot speak MCP. Payloads are identical to the MCP tools (no `success/message` envelope), and auth reuses the web console session. Read-only queries are a fixed set of GET paths; every other tool (write actions `probe.*` / `verify.*` / `act.*` / `poc.submit`, plus the local advisories `judge.*` / `learn.*`) goes through a single `POST /api/v1/call`.

| Method | Path | Tool |
| --- | --- | --- |
| GET | `/api/v1/observe/findings` | `observe.findings` |
| GET | `/api/v1/observe/evidence/{id}` | `observe.evidence` |
| GET | `/api/v1/observe/state` | `observe.state` |
| GET | `/api/v1/observe/observations` | `observe.observations` |
| GET | `/api/v1/plan/next` | `plan.next` |
| GET | `/api/v1/poc/search` | `poc.search` |
| POST | `/api/v1/call` | any tool (write-action surface) |
| GET | `/api/v1/health` | liveness probe (no auth) |

Query parameters match the tool arguments: `project_id`, `status`, `severity`, `page`, `limit`, `subject`, `depth`, `direction`, `since_seq`, `sources`, `kinds`, `subject_under`, `keyword`. List parameters accept both `?k=a&k=b` and `?k=a,b`.

```bash
# The password is printed by `afrog web` as "Web访问密码" at startup
TOKEN=$(curl -s -X POST http://127.0.0.1:16868/api/login \
  -H 'Content-Type: application/json' \
  -d '{"password":"<web password>"}' | jq -r '.token')

curl -s "http://127.0.0.1:16868/api/v1/observe/observations?since_seq=0&limit=20" \
  -H "Authorization: Bearer $TOKEN"
```

`POST /api/v1/call` is a tool-invocation entry point fully synonymous with MCP: the body is `{"name": "<tool>", "arguments": {...}}` and the response is identical to the MCP tool's. It **shares the same policy, budget and audit machinery** as MCP (stdio/SSE/streamable), so a script hitting REST directly cannot bypass the limits — the path for policy evaluation, budget consumption and audit logging is exactly the same. Errors are distinguished by semantics: policy denial `403`, budget exhaustion `429`, unknown tool `404`, bad request `400`.

```bash
# Write-action surface: call any tool (here a restricted verification)
curl -s -X POST "http://127.0.0.1:16868/api/v1/call" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"verify.poc","arguments":{"poc_path":"/tmp/draft.yaml","target":"https://example.com"}}'
```

The write-action surface takes its policy and audit from the `agent` section of `afrog-config.yaml`; **without configuration it falls back to the read-only default** — the web server has no network-sending capability by default:

```yaml
agent:
  policy: /path/to/agent-policy.yaml   # policy YAML; empty means the read-only default
  audit: /path/to/audit.jsonl          # decision audit JSONL; empty means no logging
  oob: ceyeio                          # tool-surface OOB adapter (same values as CLI -oob); credentials come from the reverse section; empty disables act.oob_*
```

`agent.policy` uses exactly the same format as `afrog mcp -policy` (see "Policy and budget" above). Unlike a one-shot CLI process, the web server is long-lived, so `budget.requests` inside the policy is the **total session budget for the whole process**, accumulated across requests — the same long-lived semantics as `afrog mcp -listen`.

Set `agent.oob` only when you need out-of-band callbacks: it names the OOB adapter (`ceyeio` / `dnslogcn` / `alphalog` / `xray` / `revsuit` / `interactsh`, same values as CLI `-oob`), and the credentials are reused from the `reverse` section (see "What `reverse` means" in the configuration reference). Once configured, `act.oob_payload` mints addresses and `act.oob_wait` waits for a callback; when empty both report "not configured" explicitly instead of silently waiting for a callback that will never arrive.

## gRPC entry (AgentService)

For callers that cannot speak HTTP (other languages, in-cluster calls, future orchestrators), the same tool set is reachable over gRPC. The control-plane service is started by `afrog serve`:

```bash
afrog serve -listen :16869 -api-token your-token
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `-listen` | `:16869` | gRPC listen address (the web UI uses 16868; the control plane uses the adjacent port) |
| `-api-token` | randomly generated | Console API token; when empty a random one is generated and printed at startup |
| `-max-running` | concurrent scan limit | Number of tasks running at once |
| `-event-buffer` | event window | Max events retained per task |

One listener serves two service families:

| Service | Responsibility |
| --- | --- |
| `afrog.v1.AfrogScanner` | Scan tasks: submit, event stream, status, results, node management |
| `afrog.v1.AgentService` | Tool surface: `ListTools` / `Invoke`, synonymous with MCP |

`AgentService` maps one-to-one onto MCP `tools/list` / `tools/call`:

| gRPC method | MCP equivalent | Input / output |
| --- | --- | --- |
| `ListTools` | `tools/list` | Returns each tool's `name`, `description` and `input_schema_json` (the JSON-encoded input JSON Schema) |
| `Invoke` | `tools/call` | Input is `name` + `arguments_json` (JSON-encoded tool arguments; empty means none), output is `result_json` (byte-for-byte identical to the MCP / REST result) |

Tool arguments and results travel as **JSON passthrough**: the tool contract lives only in `pkg/mcp`, and the proto does not mirror a second schema, avoiding two sources of truth drifting apart (the same rationale as `Evidence.native_json`).

`AgentService` **shares the same `policy.Gate`** as MCP / REST: one tool registry, one policy evaluation, one budget consumption path, one audit log. Policy and audit likewise come from the `agent` section of `afrog-config.yaml`, and **without configuration it falls back to the read-only default** — the control plane sends no traffic by default. For the long-lived process, `budget.requests` is again the total session budget for the whole process.

Error codes match REST semantics:

| Case | gRPC | REST |
| --- | --- | --- |
| Policy denial | `PermissionDenied` | `403` |
| Budget exhaustion | `ResourceExhausted` | `429` |
| Unknown tool | `NotFound` | `404` |
| Bad request | `InvalidArgument` | `400` |

Calling it with `grpcurl` (the auth header is `authorization: Bearer <token>`):

```bash
# List tools
grpcurl -H 'authorization: Bearer your-token' \
  -plaintext 127.0.0.1:16869 afrog.v1.AgentService/ListTools

# Invoke a tool (here: read the attack-surface subgraph)
grpcurl -H 'authorization: Bearer your-token' -plaintext \
  -d '{"name":"observe.state","arguments_json":"{\"subject\":\"example.com\"}"}' \
  127.0.0.1:16869 afrog.v1.AgentService/Invoke
```

## Typical flow

1. `observe.findings` surfaces a suspicious hit;
2. `observe.evidence` reads the proof and the replay command;
3. Re-verify with `verify.poc` (or `probe.http`) when needed;
4. Re-check an old conclusion with `verify.replay`, passing only the evidence id: a successful replay with a different digest means the target or the PoC has changed;
5. `observe.state` shows the surrounding assets and what is still uncovered;
6. When you need process facts rather than verdicts, pull `observe.observations` incrementally with `since_seq`: open ports, fingerprints, round trips, passive traffic, certificates and out-of-band callbacks are all there;
7. When you are unsure which PoC to try first, use `plan.next`: it ranks `verify.poc` / `probe.fingerprint` proposals by a deterministic score with rationale. It is read-only and zero-budget; the chosen action still has to pass `verify.*` / `probe.*` policy and budget gating again;
8. After the model writes a draft, validate it with `poc.draft` (`save: true` to persist it), then run `poc.submit` to sandbox it against one real target for evidence; candidates that yield evidence land in the human-review queue, where a person decides with `afrog poc approve/reject`.

When there is a suspicious hit but no matching PoC yet, let the model write a draft, validate it with `poc.draft` (`save: true` to persist it), and hand the returned `poc_path` to `verify.poc`. Verdicts still happen only in `verify.poc`; `poc.draft` sends no requests.

### Closing the loop on candidate PoCs: `poc.submit` and `afrog poc`

`poc.submit` runs a draft once against a real target (reusing `verify.poc`'s restricted sandbox: concurrency 1, rate limit 10, stop on first match). **Only candidates that produce evidence enter the queue**; without evidence they are never staged. Once queued the status is `pending`, and promotion is a CLI-only human action — the model has no path to write into the PoC directory itself.

```bash
afrog poc pending [--json]            # list pending candidates (default subcommand)
afrog poc list --status approved      # list by status: pending|approved|rejected
afrog poc show <id> --json            # inspect one candidate (draft path, evidence id/digest)
afrog poc approve <id>                # approve and write to ~/.config/afrog/pocs-my
afrog poc reject <id> -note "false positive"   # reject, keeping the draft and reason
afrog poc stats [--json]              # pipeline metrics: ingest rate and more

afrog learn list [--status s]         # human review of tuning suggestions: list/show/accept/reject
```

- Re-submitting the same id refreshes the content and **returns it to `pending`**: the YAML changed, so the old evidence no longer stands for it.
- `approve` rejects candidates whose id collides with a non-`my` source (curated / local / append / builtin), so the entry is not silently ignored by the dedup priority after being written to `pocs-my`.
- The resulting path is the same one the web console uses for a new PoC: `~/.config/afrog/pocs-my`.

### Closing the loop on judgements and tuning: `judge.*` / `learn.*`

The **Judge** and **Learner** roles in the decision surface likewise produce advisories only, stored in tables **separate from the vulnerability ledger**:

- `judge.brief` gathers the judging material (evidence chain + nearby observations for the target + subgraph + existing judgements); after reasoning, the model records its opinion in the `judgement` table via `judge.record` (`likely_true` / `likely_false` / `uncertain`). This opinion is for human review only and **never changes the vulnerability ledger**.
- `learn.brief` gathers tuning material (pipeline stats + review history + existing suggestions); based on the ingest rate from `afrog poc stats` and the rejection reasons, the model proposes tuning suggestions via `learn.record`, landing in the `learn_suggestion` table.
- `afrog learn accept <id>` **only records the human decision**: afrog never parses or applies the diff; rule/threshold changes still go through the normal code-review flow.

## Notes

- **`act.brute` is destructive**: denied by default; requires `mode: full` and `destructive: true`. Pair it with `scope` and a small `budget`.
- `max_requests` only bounds YAML `brute` dictionaries. JS/Go PoCs loop inside their scripts; the outside cannot count or cap them, so only `timeout` and the session budget apply.
- Tools read the local `~/.config/afrog/afrog.db`, shared with the web console and CLI.
- Legacy findings created before this feature have no evidence; `observe.evidence` returns not-found for them by design.

> **← Previous:** [Scheduled Scans](./09-scheduled-scans.md) ｜ **Handbook home:** [What afrog does](./01-overview.md) ｜ **Docs home →:** [afrog Docs](../index.md)
