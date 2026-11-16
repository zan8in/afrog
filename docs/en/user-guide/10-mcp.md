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
- Auth accepts `Authorization: Bearer <token>` or `?token=`;
- Per the MCP spec the `Origin` header is validated: cross-origin requests coming from a browser get 403 (DNS-rebinding protection), while native clients and curl that send no `Origin` are unaffected.

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

The default policy is **read-only**: a freshly started server never gains the ability to send traffic. Widen it along either path; precedence is `-policy` flag > `agent.policy` in `afrog-config.yaml` (what the web console saves) > read-only default:

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
    duration: 30m             # idle window: a session ends after this long with no budgeted call
  destructive: false
  audit: true
```

Usage:

```bash
afrog mcp                                     # no -policy: follows agent.policy of afrog-config.yaml
afrog mcp -policy ./agent-policy.yaml         # explicit, overrides the config
afrog mcp -policy ./p.yaml -audit ./a.jsonl   # also set the audit file
```

> Saving in the web console under **Agent → Policy & Audit** records the path in `agent.policy`, so the plain `afrog mcp` inside your client reads the same policy; an explicit `-policy` still wins.

### Modes

| Mode | Allowed | Typical use |
| --- | --- | --- |
| `readonly` (default) | `observe.*`, `plan.*`, `poc.search`, `poc.draft`, `judge.*`, `learn.*`, `server.*` | Let the agent read results, reason, and write local advisories |
| `safe` | Adds `probe.*`, `scan.start`, `verify.replay`, `poc.submit` | Retest and verify without changing target state |
| `full` | Everything not explicitly denied | Full assessment in a controlled environment |

Evaluation order is fixed: `deny → allowlist → mode → destructive → scope`. **Deny always wins.**

### Budget and audit

- `budget.requests` is the request allowance of one session and **only counts actions that actually send traffic**; read-only calls (querying the database, fetching evidence) neither consume allowance nor are subject to any budget limit.
- `budget.duration` is the **idle window** (10 minutes by default): every successful budgeted call extends it, and once nothing budgeted happens for that long the session is over — the next call starts a fresh one with a full allowance. A long-lived service (the web console, `afrog mcp -listen`) therefore never goes dead after running for a while, and never needs a restart just to refill the allowance.
- Costly actions (such as `scan.start` / `poc.submit`) reserve the candidates' estimated request count instead of a flat 1.
- `audit: true` plus `-audit audit.jsonl` records every call: action, target, verdict, remaining budget.
- Unsure how much allowance is left or which mode is active? Call the read-only `server.status` and read `requests_remaining` / `policy.mode` — it costs nothing, unlike finding out by hitting a 403/429.

## Tools

| Tool | Purpose | Capability required |
| --- | --- | --- |
| `server.status` | Read-only introspection: the active policy mode, remaining request allowance and idle expiry, scope allow/deny lists, plus server and protocol versions; sends nothing and costs nothing | read-only |
| `observe.findings` | List findings by project, ledger state and severity | read-only |
| `observe.evidence` | Fetch evidence by result id or an `evd_` evidence id | read-only |
| `observe.state` | Attack-surface subgraph around an asset (upstream/downstream, endpoints/parameters, tech stack and candidate PoCs, coverage, findings) | read-only |
| `observe.observations` | Incrementally pull the observation stream by `seq` cursor: open ports, web fingerprints, HTTP transactions, passive proxy traffic, TLS certificates, and out-of-band callbacks | read-only |
| `plan.next` | Compress the attack-surface graph into next-step `Action` proposals (`scan.start` / `probe.fingerprint`), ranked by a deterministic score with rationale; candidates for the same origin are merged into one `scan.start` (`search` is the tech-stack keyword). An empty `proposals` means the subject has no reproducible candidate yet (run `probe.*` first, or fall back to `poc.search`) | read-only |
| `poc.search` | Search the PoCs already on this machine by keyword and severity, returning real ids, local paths, and `total` / `truncated` (the match count and whether `limit` truncated it). **It is the equivalent of `afrog -pl -s <keyword>`: precheck whether this machine has a PoC for the tech stack before scanning — if the result is empty, do not scan; afrog has no PoC for that fingerprint/product.** Prefer a fingerprint keyword (jquery, thinkphp, shiro) and, on a hit, hand the same keyword to `scan.start`; with no clue, start from `plan.next`; `severity` is only a coarse fallback filter | read-only |
| `poc.draft` | Validate a PoC draft: structure, capability level, request estimate; optionally save it for `poc.submit` to run | read-only |
| `poc.submit` | Run a draft in a restricted sandbox against one real target to obtain evidence, and stage it in the human-review queue (`afrog poc approve/reject`) on success | `verify.*` (per-draft capability; `exec`-level also needs `destructive: true`) |
| `probe.http` | Send one HTTP request; return status, headers, body, latency | `probe.*` |
| `probe.port` | Port probe on one host (top100 by default, 1000 ports max per call); return open ports and service fingerprints | `probe.*` |
| `probe.fingerprint` | Fingerprint one URL: tech stack, WAF/CDN, redirect chain, TLS summary; once you have the tech stack, precheck with `poc.search` and, if it has results, hand that keyword to `scan.start` to scan concurrently | `probe.*` |
| `scan.start` | **The main entry point replacing per-PoC verification**: run every PoC under a tech stack (`search` keyword) in one concurrent subprocess scan and return replayable evidence. afrog selects PoCs by `-s`, and fingerprint PoCs are kept regardless of the keyword, so the fingerprint stage always runs and `requires` gates open on the real fingerprint — no false negatives from a single vuln PoC being gated out, and no N serial requests for N candidates. A reverse PoC needs `agent.oob`; when missing the call fails closed with an explicit error | `scan.start` |
| `verify.replay` | Replay evidence by id and compare id/digest to see whether the old conclusion still holds | `verify.*` |
| `act.brute` | Weak-credential / dictionary attempts | `full` + `destructive: true` |
| `act.oob_payload` | Mint a set of out-of-band callback addresses (`filter` + DNS/HTTP, …) for validations that need a reverse callback (command execution, XXE, SSRF) | `full` + `destructive: true` |
| `act.oob_wait` | Wait for an out-of-band callback; on a hit, return the evidence and write it to the observation stream (`oob_hit`) | `full` + `destructive: true` |
| `judge.brief` | For a result id or evidence id, gather the judging material: the evidence chain, nearby observations for the same target, the attack-surface subgraph, and existing judgements | Read-only |
| `judge.record` | Record a judgement (`likely_true` / `likely_false` / `uncertain`) in the `judgement` table as an advisory for human review; **it never touches the vulnerability ledger** | Read-only (writes a local advisory) |
| `learn.brief` | Fetch tuning material: pipeline stats (including the ingest rate), recent review decisions (with rejection reasons), and pending tuning suggestions | Read-only |
| `learn.record` | Record a tuning suggestion (`rule` / `threshold` / `other`) in the `learn_suggestion` table for human review; **it never applies any diff** | Read-only (writes a local advisory) |

### How the tools fit together (the AI client sees the same hints)

`afrog mcp` returns an `instructions` string from `initialize` (an optional MCP field); clients fold it into the model context to explain how to use these tools — without it, the two most common misuses are verifying PoCs one by one (slow), and not knowing to look up a matching PoC in `poc.search` after a fingerprint hit. The key points mirror the table above:

1. **Precheck with `poc.search`, then `scan.start`**: take the tech-stack keyword (jquery, thinkphp, shiro) to `poc.search` (the equivalent of `afrog -pl -s`) to confirm this machine really has PoCs for that stack; if it is not empty, hand the **same keyword** to `scan.start` to scan concurrently, and if it is empty do not scan — afrog has no PoC for that fingerprint/product. For a PoC you wrote yourself, run `poc.draft` (`save: true`) first and pass the returned `poc_path` to `poc.submit` to run in the restricted sandbox.
2. **Let `plan.next` drive**: it reads the attack surface (endpoints / tech stack / existing conclusions) and gives a deterministic next step — `probe.fingerprint` for origins that are not fingerprinted yet, and a `scan.start` proposal (`search` is the tech-stack keyword, with multiple candidates for the same origin merged into one) for endpoints whose tech stack is known, skipping combinations that already have a conclusion; search yourself only when it returns nothing.
3. **Do not default to "verify PoCs by severity"**: `severity` only filters by impact and says nothing about whether the target actually runs that product — it burns the allowance and still cannot support a trustworthy "no vulnerabilities" conclusion. The right move is always "fingerprint → `poc.search` precheck → `scan.start`".
4. **Read-only tools** (`server.*` / `observe.*` / `plan.*` / `poc.search` / `poc.draft` / `judge.*` / `learn.*`) send nothing and cost nothing; `probe.*` / `scan.start` / `verify.replay` / `poc.submit` / `act.*` send traffic and debit the session allowance per request — `scan.start` runs a whole tech stack's PoCs concurrently in one shot, far cheaper in time and allowance than verifying one by one. Unsure which mode is active or how much allowance is left? Check `server.status` first.

### What the client gets at the protocol level

Beyond the tool list itself, `afrog mcp` provides a set of structured hints per the MCP spec, so "what can be auto-approved, what needs confirmation, what to try next" does not have to be guessed by the model:

- **`instructions`** (returned by `initialize`): usage notes the client folds into the model context — the points in "How the tools fit together" above.
- **Protocol version negotiation**: if the version the client reports is in the supported set (`2024-11-05` / `2025-03-26` / `2025-06-18`) it is echoed back; otherwise afrog answers with its own latest, rather than parroting a version it cannot actually speak.
- **`title` and `annotations`** (per tool): `title` is a short human-facing label; `annotations` are advisory hints — `readOnlyHint` matches afrog's own read-only set exactly (`server.*` / `observe.*` / `plan.*` / `poc.search` / `poc.draft` / `judge.*` / `learn.*`), `openWorldHint` marks tools that send traffic to external targets, and `destructiveHint` is given only to `act.brute` and `poc.submit`. They are **hints only and take no part in gating**: whether a call is allowed is still decided by policy and budget.
- **`outputSchema` and `structuredContent`**: tools with a stable return shape (such as `server.status`, `poc.search`, `plan.next`) declare `outputSchema`, and their results carry `structuredContent` so clients can read values straight off the schema; tools returning large objects declare none, so the same payload is not duplicated in both `content` and `structuredContent`.
- **Progress notifications** (`notifications/progress`): when the client asks for progress via `_meta.progressToken` on `tools/call`, long calls (such as `act.oob_wait` waiting for a callback) report "elapsed / total" once a second; Streamable HTTP is one POST, one response with nowhere to push mid-call, so that transport sends no progress.
- **Cancellation** (`notifications/cancelled`): when the client cancels a call by `requestId`, afrog cancels precisely that call rather than tearing down the whole connection; only a persistent, concurrently readable/writable connection such as stdio supports mid-call cancellation.

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
  -d '{"name":"scan.start","arguments":{"target":"https://example.com","search":"thinkphp"}}'
```

The write-action surface (REST / gRPC) and `afrog mcp` (when `-policy`/`-audit` are not given explicitly) take their policy and audit from the same place, the `agent` section of `afrog-config.yaml`; **without configuration it falls back to the read-only default** — no network-sending capability by default:

```yaml
agent:
  policy: /path/to/agent-policy.yaml   # policy YAML; empty means the read-only default
  audit: /path/to/audit.jsonl          # decision audit JSONL; empty means no logging
  oob: ceyeio                          # tool-surface OOB adapter (same values as CLI -oob); credentials come from the reverse section; empty disables act.oob_*
```

`agent.policy` uses exactly the same format as `afrog mcp -policy` (see "Policy and budget" above), and it is the very field the web console saves. Unlike a one-shot CLI process, the web server is long-lived, so `budget.requests` is a single session allowance shared by the whole process and debited across requests — the same long-lived semantics as `afrog mcp -listen`. It never fails permanently once used up: after `budget.duration` of idleness a fresh session starts with the allowance refilled.

Set `agent.oob` only when you need out-of-band callbacks: it names the OOB adapter (`ceyeio` / `dnslogcn` / `alphalog` / `xray` / `revsuit` / `interactsh`, same values as CLI `-oob`), and the credentials are reused from the `reverse` section (see "What `reverse` means" in the configuration reference). Once configured, `act.oob_payload` mints addresses and `act.oob_wait` waits for a callback; `scan.start` / `poc.submit` also use it when running a reverse PoC (containing `{{oob.*}}` or `oobCheck`) — only the adapter name is handed to the child process, which reuses the `reverse` credentials. When empty, all of these report "not configured" explicitly instead of silently waiting for a callback that will never arrive — a reverse PoC is never quietly judged "not found".

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

`AgentService` **shares the same `policy.Gate`** as MCP / REST: one tool registry, one policy evaluation, one budget consumption path, one audit log. Policy and audit likewise come from the `agent` section of `afrog-config.yaml`, and **without configuration it falls back to the read-only default** — the control plane sends no traffic by default. A long-lived process likewise shares one session allowance, refilled automatically after an idle timeout.

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
3. Re-verify with `scan.start` (scan a whole tech stack concurrently by keyword, or use `probe.http` for a single request) when needed;
4. Re-check an old conclusion with `verify.replay`, passing only the evidence id: a successful replay with a different digest means the target or the PoC has changed;
5. `observe.state` shows the surrounding assets and what is still uncovered;
6. When you need process facts rather than verdicts, pull `observe.observations` incrementally with `since_seq`: open ports, fingerprints, round trips, passive traffic, certificates and out-of-band callbacks are all there;
7. When you are unsure which PoC to try first, use `plan.next`: it ranks `scan.start` / `probe.fingerprint` proposals by a deterministic score with rationale (candidates for the same origin are merged into one `scan.start`). It is read-only and zero-budget; the chosen action still has to pass `scan.start` / `probe.*` policy and budget gating again;
8. After the model writes a draft, validate it with `poc.draft` (`save: true` to persist it), then run `poc.submit` to sandbox it against one real target for evidence; candidates that yield evidence land in the human-review queue, where a person decides with `afrog poc approve/reject`.

When there is a suspicious hit but no matching PoC yet, let the model write a draft, validate it with `poc.draft` (`save: true` to persist it), and hand the returned `poc_path` to `poc.submit` to run in the restricted sandbox. Verdicts still happen only in that run; `poc.draft` sends no requests.

### Closing the loop on candidate PoCs: `poc.submit` and `afrog poc`

`poc.submit` runs a draft once against a real target (restricted sandbox: concurrency 1, rate limit 10, stop on first match). **Only candidates that produce evidence enter the queue**; without evidence they are never staged. Once queued the status is `pending`, and promotion is a CLI-only human action — the model has no path to write into the PoC directory itself.

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

> **← Previous:** [Scheduled Scans](./09-scheduled-scans.md) ｜ **Handbook home:** [What afrog does](./01-overview.md) ｜ **Next →:** [Beginner's Guide: Connect Your AI Client to afrog](./11-mcp-quickstart.md)
