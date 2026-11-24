<!--
title: Beginner's Guide: Connect Your AI Client to afrog
slug: /docs/user-guide/mcp-quickstart
lang: en
summary: Connect afrog to common AI clients step by step: verify your build, smoke-test `afrog mcp`, configure each popular client and verify it works, then widen the capability policy when you need it.
status: published
source: new
last_reviewed: 2026-11-15
-->

## What this tutorial gets you

In one sentence: **let AI clients like Claude and Cursor read the findings afrog already produced for you.**

Through [`afrog mcp`](./10-mcp.md), afrog turns itself into an MCP server. Your AI client connects as the client side and can then call afrog tools to list findings, fetch evidence and read the attack surface.

By the end you will have done four things:

1. Confirmed that your local afrog is a "new enough" build with MCP support;
2. Run `afrog mcp` by hand and seen it answer;
3. Filled in the config for the client you actually use, and **verified that tools get called**;
4. Understood why it "can look but cannot touch" by default, and how to widen that.

> Prefer clicking to typing? The web console has a graphical version of this tutorial under **Agent → Quickstart** in the left nav, with one-click copy for every snippet.

All you need is a terminal and an AI client. No coding.

## Step 0: Confirm your afrog build is current

MCP was added to afrog later. Older builds have **no `mcp` subcommand at all**: configuring them silently fails to connect and can even hang. Spend five seconds checking:

```bash
afrog mcp -h
```

You are good if you see this (written to stderr):

```text
Usage of afrog mcp:
  -audit string
    	Path to the policy audit log (JSONL); empty falls back to agent.audit in afrog-config.yaml, then no audit
  -listen string
    	Serve over HTTP+SSE instead (e.g. 127.0.0.1:16870); empty falls back to agent.mcp.listen in afrog-config.yaml, then stdio
  -policy string
    	Path to the policy YAML; empty falls back to agent.policy in afrog-config.yaml, then the read-only default
  -token string
    	Access token for SSE mode; empty falls back to agent.mcp.token in afrog-config.yaml; required when listening on a non-local address
```

**Any of these means you are on an old build**:

- `unknown command`, or `flag provided but not defined`;
- No output at all, or it appears to hang;
- It actually starts scanning a target named `mcp`.

Get a current build instead: download the archive for your OS from [GitHub Releases](https://github.com/zan8in/afrog/releases) and unzip the executable somewhere fixed:

| OS | Archive |
| --- | --- |
| Windows | `afrog_windows_amd64.zip` (unpacks to `afrog.exe`) |
| macOS (Apple silicon) | `afrog_darwin_arm64.tar.gz` |
| macOS (Intel) | `afrog_darwin_amd64.tar.gz` |
| Linux | `afrog_linux_amd64.tar.gz` |

Already have afrog and just want to upgrade? One command:

```bash
afrog -update
```

### Note down afrog's absolute path

Every client config below needs this path in `command`:

```bash
# macOS / Linux
which afrog

# Windows (PowerShell or CMD)
where afrog
```

For example macOS prints `/usr/local/bin/afrog`, Windows prints `C:\tools\afrog\afrog.exe`, depending on your setup.

**Why an absolute path?** GUI clients (Claude Desktop, Cursor, Cherry Studio, …) are not launched from your terminal and **do not inherit your shell's PATH**. Writing plain `afrog` often fails with `spawn ENOENT`; the absolute path is the reliable choice.

## Step 1: Run `afrog mcp` by hand (30-second smoke test)

```bash
afrog mcp
```

**It will look like it hangs — that is expected.** Do not press Ctrl+C.

`afrog mcp` is a long-running process: it reads one line of JSON from stdin, writes one line to stdout, then waits for the next line. With no counterpart in the terminal, it simply waits. In normal use the AI client plays that counterpart.

To confirm it is alive right now, simulate a client and send two MCP requests.

**macOS / Linux (bash / zsh)**

```bash
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
| afrog mcp 2>/dev/null
```

**Windows (PowerShell)**

```powershell
$req1 = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
$req2 = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
$req1, $req2 | & afrog mcp 2>$null
```

You should get two lines of JSON:

```json
{"jsonrpc":"2.0","id":1,"result":{"capabilities":{"completions":{},"logging":{},"prompts":{"listChanged":false},"resources":{"listChanged":false,"subscribe":true},"tools":{"listChanged":false}},"instructions":"afrog exposes this machine's findings, attack surface and PoC ability as a set of tools…","protocolVersion":"2024-11-05","serverInfo":{"name":"afrog","version":"..."}}}
{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"act.brute",...},{"name":"judge.brief",...}, ...]}}
```

- The first line is a successful handshake; `instructions` is the usage guide the server hands to the client (clients fold it into the model context — see [MCP Server · how the tools fit together](./10-mcp.md)); all five capabilities declared in `capabilities` (`tools` / `logging` / `resources` / `prompts` / `completions`) are implemented;
- The second is the tool list: **25 tools in total** (`server.*` / `observe.*` / `probe.*` / `verify.*` / `act.*` (including `act.oob_*`) / `poc.*` / `scan.*` / `task.*` / `plan.*` / `judge.*` / `learn.*`).
- Besides tools, the server also exposes read-only **resources** (`afrog://status`, `afrog://findings`, `afrog://tasks`, and `afrog://tasks/{task_id}[/events]`) and three **prompts** templates (`scan-target` / `triage-findings` / `follow-task`); if your client supports them, you can read them from the resources/prompts panel or use them to kick off a conversation. Resources support **subscriptions** (`resources/subscribe`): once subscribed, the server pushes `notifications/resources/updated` when the resource changes (a long task finishing, for example), so the client re-reads once instead of polling. Prompt arguments and resource-template variables support **completion** (`completion/complete`): e.g. `task_id` for `follow-task` and `severity` for `triage-findings` yield candidate values, while fields the server knows nothing about return an empty list (no guessing, no inventing).

If you see both lines, afrog's side is fully ready. What remains is just getting a client to connect.

> Note: logs are deliberately written to stderr while stdout carries only protocol data. That is why the macOS / Linux command uses `2>/dev/null` and the Windows one uses `2>$null` to drop logs. Remove it if you want to watch the logs.

## Step 2: Understand "can look, cannot touch" first

This is essential, otherwise you will see a wall of "blocked" tools in your client and have no idea why.

afrog's MCP default policy is **read-only**. A freshly started server never gains the ability to send requests to targets on its own.

| Mode | What the agent may do | When to use |
| --- | --- | --- |
| `readonly` (default) | List findings, fetch evidence, read the attack surface, search PoCs, record judgements and suggestions | You just want AI to help you *read* results |
| `safe` | Everything read-only, plus probing and verification (`probe.*` / `verify.*`) | You want AI to re-test or verify a suspicious finding |
| `full` | Everything except explicit denials, including exec and destructive actions | Authorized targets in a controlled environment |

**The default is enough for testing** — the read-only tools already prove the connection works. To widen it, see Step 5.

## Step 3: Connect your client

### 3.0 Ground rules (read these first)

1. **Always use an absolute path in `command`** (the path you found in Step 0).
2. **Add one server at a time**, and name it `afrog` so it is easy to cross-check.
3. **Restart the client after editing config** — most clients do not hot-reload.
4. **Verify the same way everywhere**: once connected, just say

   > Use afrog to list the most recent findings, at most 5.

   If it calls `observe.findings` and returns a result, you have passed.
5. **Raise the timeout for long scans**: `scan.start` can run for a few minutes, while most clients default the tool-call timeout to just 60 seconds — without raising it the scan gets **cut off on the client side** halfway through (the symptom is "tool call timed out / no response", while the afrog subprocess is actually still running and burning your quota for nothing). Set it to **10 minutes**.

> **How to set it (differs per client)**:
>
> - **Cline**: write `"timeout": 600` in the config, **in seconds** (default 60, allowed range 30 seconds – 1 hour, so 600 = 10 minutes);
> - **Cherry Studio**: not in the config file — go to `Settings → MCP → Timeout` and raise it;
> - **Claude Code**: the tool-call timeout is already huge by default (about 28 hours), usually nothing to do; only set `MCP_TIMEOUT` before launch if the server starts slowly (**in milliseconds**, e.g. `MCP_TIMEOUT=60000`);
> - **VS Code / Cursor / Windsurf / Claude Desktop**: there is **no** such field in the official config, and it is ignored if written — if a long scan is cut off, look for a timeout setting in each client's own preferences.
>
> Separately, `scan.start` also has its own whole-batch `timeout_sec` (default 300 seconds, max 1800 seconds), and the client timeout should be no smaller than that.

Pick the section for the client you actually use.

---

### 3.1 Claude Desktop (desktop)

**Open the config file**

Menu bar `Claude → Settings → Developer → Edit Config` opens it for you. The path is:

| OS | Path |
| --- | --- |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

**Add the config** (replace `/usr/local/bin/afrog` with your absolute path)

```json
{
  "mcpServers": {
    "afrog": {
      "command": "/usr/local/bin/afrog",
      "args": ["mcp"]
    }
  }
}
```

**Restart**: use `Quit` in the menu bar (closing the window is not enough), then reopen Claude Desktop.

**Verify**

- In a new conversation, the tools icon below the input should list `afrog`;
- Ask: "Use afrog to list the most recent findings, at most 5." It will ask for permission and then return results.

**For remote HTTP**: Claude Desktop's JSON targets local stdio, so bridging HTTP to stdio with `mcp-remote` is the way (needs Node.js on your machine, and the HTTP server must already be running — see Step 6):

```json
{
  "mcpServers": {
    "afrog": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote", "http://127.0.0.1:16870/mcp",
        "--header", "Authorization: Bearer your-token"
      ]
    }
  }
}
```

---

### 3.2 Cherry Studio (desktop)

**Add the server**

`Settings → MCP Servers → Add Server`, type **stdio**:

| Field | Value |
| --- | --- |
| Name | `afrog` |
| Command | `/usr/local/bin/afrog` (absolute path) |
| Arguments | `mcp` |

If you already have the JSON from 3.1, click `Import from JSON` and paste the `mcpServers` block instead.

**Enable**: after saving, flip the toggle next to `afrog` in the server list.

**Timeout**: Cherry Studio's MCP timeout is **not in the config file** — go to `Settings → MCP → Timeout` and raise it (10 minutes is recommended for long scans).

**Verify**: expanding `afrog` should show 25 tools. In a chat with MCP enabled, ask "Use afrog to list the most recent findings."

**For remote HTTP**: in the same `Add Server` dialog, switch the type to **Streamable HTTP** (or **SSE**) and fill in:

| Field | Value |
| --- | --- |
| Type | Streamable HTTP (maps to `/mcp`) or SSE (maps to `/sse`) |
| URL | `http://127.0.0.1:16870/mcp` |
| Headers | `Authorization: Bearer your-token` |

---

### 3.3 Cursor (editor)

**Write the config**

- Global (all projects): `~/.cursor/mcp.json`
- Per project: `.cursor/mcp.json` in the project root

The content is identical to 3.1, with a top-level `mcpServers` key:

```json
{
  "mcpServers": {
    "afrog": {
      "command": "/usr/local/bin/afrog",
      "args": ["mcp"]
    }
  }
}
```

**Verify**

Open `Cursor Settings → MCP`; the `afrog` entry should show a green dot and a tool count. Ask in an **Agent-mode** chat (plain completion mode never calls tools).

> When the same server key exists in both files, the project-level `.cursor/mcp.json` **replaces** the global entry entirely; they are not merged.

**For remote HTTP**: switch the entry to the `url` form (Cursor's remote entry needs only `url`, no `type`):

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

---

### 3.4 VS Code (GitHub Copilot Chat)

**Write the config**

Create `.vscode/mcp.json` in your project:

```json
{
  "servers": {
    "afrog": {
      "type": "stdio",
      "command": "/usr/local/bin/afrog",
      "args": ["mcp"]
    }
  }
}
```

> **The most common trap**: VS Code uses a top-level `servers` key; every other client uses `mcpServers`. A wrong key produces no error, it simply never works.

**Verify**

After saving, a `Start` code lens appears above the entry; click it and wait for `Running with 25 tools`. You can also run `MCP: List Servers` from the command palette, then ask in Copilot Chat.

**For remote HTTP**, replace the entry with:

```json
{
  "servers": {
    "afrog": {
      "type": "http",
      "url": "http://127.0.0.1:16870/mcp",
      "headers": { "Authorization": "Bearer your-token" }
    }
  }
}
```

---

### 3.5 Cline (VS Code extension)

**Open the config**: in the Cline panel, click the `MCP Servers` icon → `Configure` tab → `Configure MCP Servers`. This opens `cline_mcp_settings.json`.

**Add** (top-level key is `mcpServers`):

```json
{
  "mcpServers": {
    "afrog": {
      "command": "/usr/local/bin/afrog",
      "args": ["mcp"],
      "timeout": 600,
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

> Here `"timeout": 600` is Cline's **single tool-call timeout, in seconds** (600 = 10 minutes) — Cline defaults to only 60 seconds, so a long scan gets cut off if you do not raise it. Cline is one of the few mainstream clients where you can set the timeout directly in the config file.

**Verify**: the MCP Servers panel should list `afrog` and its tool count. Ask in chat and approve the call.

**For remote HTTP**: switch the entry to `type: "streamableHttp"` (the recommended value in Cline; where only the legacy transport is supported, use `"sse"` and point the URL at `/sse`):

```json
{
  "mcpServers": {
    "afrog": {
      "type": "streamableHttp",
      "url": "http://127.0.0.1:16870/mcp",
      "headers": { "Authorization": "Bearer your-token" },
      "timeout": 600,
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

---

### 3.6 Windsurf (editor)

**Open the config**

- macOS / Linux: `~/.codeium/windsurf/mcp_config.json`
- Windows: `%USERPROFILE%\.codeium\windsurf\mcp_config.json`

You can also open it from the MCP icon in the Cascade panel via `Configure`.

**Add** (top-level key is `mcpServers`):

```json
{
  "mcpServers": {
    "afrog": {
      "command": "/usr/local/bin/afrog",
      "args": ["mcp"]
    }
  }
}
```

**Verify**: after saving, click `Refresh` in the MCP panel; `afrog` should show as connected. Ask in a Cascade chat.

**For remote HTTP**: switch the entry to the following — note Windsurf's field is `serverUrl`, **not** `url`:

```json
{
  "mcpServers": {
    "afrog": {
      "serverUrl": "http://127.0.0.1:16870/mcp"
    }
  }
}
```

---

### 3.7 Claude Code (command line)

Claude Code needs no hand-written JSON — one command does it:

```bash
# -s user applies to all projects; omit it (or use -s local) for the current project only
claude mcp add afrog -s user -- afrog mcp
```

**Timeout**: Claude Code's tool-call timeout is already huge by default (about 28 hours), so there is usually **nothing to do**; only set `MCP_TIMEOUT` before launch if the server starts slowly (**in milliseconds**, e.g. `MCP_TIMEOUT=60000 claude`).

**Verify**

```bash
claude mcp list          # afrog should appear in the list
claude                   # then run /mcp in the session: afrog connected, with its tool list
```

Now just ask "Use afrog to list the most recent findings."

**For remote HTTP**: switch to `--transport http` (where only the legacy transport is supported, use `--transport sse` and point the URL at `/sse`):

```bash
claude mcp add --transport http afrog -s user http://127.0.0.1:16870/mcp \
  --header "Authorization: Bearer your-token"
```

---

## Step 4: What counts as "it works"

Check these three layers in order. All three must pass.

| Layer | How to tell |
| --- | --- |
| 1. Connected | The client's MCP panel shows `afrog` connected with **25** tools |
| 2. Called | After your question, the client clearly shows it called an afrog tool |
| 3. Data | Real data comes back: with findings, `{"items":[...], "total":N, ...}`; with an empty database, `{"items":[], "total":0, ...}` |

**An empty list still counts as a pass.** It means the whole chain works and your local ledger simply has no findings yet. Run a scan first (`afrog -t <target>` or from the web console), then ask again.

If any layer stalls, use the troubleshooting table below.

## Step 5: Let the agent actually send traffic

Skip this if read-only is enough. When you want AI to re-test a finding, widen the policy.

There is only one source, and the CLI and the web console read **the same one**:

| How it is started | Where the policy comes from |
| --- | --- |
| `afrog mcp` / `afrog mcp -listen` | The `-policy` flag first; if omitted, the `agent.policy` section of `afrog-config.yaml` |
| Web console (`afrog -web`) | The `agent.policy` section of `afrog-config.yaml` |
| Neither configured | The read-only default; no network capability is granted automatically |

Pick either path; an explicit `-policy` always wins over the config file.

**Option A: use the web console** (recommended, visual)

Start the console with `afrog -web` (default `:16868`, password printed in the startup log), then go to **Agent → Policy & Audit** in the left nav and switch the mode from `readonly` to `safe` or `full`. Save. The console writes the policy to `~/.config/afrog/agent-policy.yaml` and records its path in `agent.policy` of `afrog-config.yaml` — the `afrog mcp` inside your client reads it on its next start, so let the client respawn the MCP process (restarting the client does it).

**Option B: pass `-policy` to the client** (for one client with its own dedicated policy)

Save the following as `agent-policy.yaml`:

```yaml
policy:
  mode: safe                  # readonly | safe | full
  allow: ["observe.*", "probe.*", "verify.*"]
  deny:  ["act.brute"]        # deny always wins
  scope:
    allow_hosts: ["10.0.0.0/8"]   # restrict to these ranges
    deny_hosts:  []
    deny_paths:  ["/logout"]
  budget:
    requests: 2000            # request allowance for one session; empty falls back to 5000
    duration: 30m             # idle window; empty falls back to 10 minutes
  destructive: false
  audit: true
```

Then change the client's `args` to:

```json
"args": ["mcp", "-policy", "/absolute/path/agent-policy.yaml", "-audit", "/absolute/path/audit.jsonl"]
```

Restart the client to apply (`-audit` works the same way: if omitted, `agent.audit` of `afrog-config.yaml` is used). With `-audit`, every allow/deny decision is written to the JSONL file, which makes debugging much easier.

> Tip: the wider the mode, the more important it is to constrain the blast radius with `scope.allow_hosts` and `budget`.

## Step 6: Go over HTTP (several clients sharing one afrog)

In stdio mode every client spawns its own `afrog mcp` process. To let multiple clients (or clients on other machines) share one afrog, switch to HTTP:

```bash
afrog mcp -listen 127.0.0.1:16870 -token your-token
```

`-token` is not a fixed value you look up somewhere — it is **a passphrase you define yourself** (a shared secret): whatever you pass to the server's `-token` is exactly what the client must send as `Authorization: Bearer`. Use a long random string; on macOS / Linux run `openssl rand -hex 32`, on Windows PowerShell run `[guid]::NewGuid().ToString('N')`.

- Point the client at a `url` with `Authorization: Bearer <your-token>`;
- To check the server is alive: `curl http://127.0.0.1:16870/healthz` returns `ok`;
- Listening on an address beyond this machine (e.g. `0.0.0.0:16870`) **requires** `-token`, otherwise afrog refuses to start; on `127.0.0.1` it starts even without `-token` (meaning no auth, local access only).

afrog serves both transports on the same listener; pick the one your client supports:

| Transport | Endpoint | Note |
| --- | --- | --- |
| Streamable HTTP | `http://127.0.0.1:16870/mcp` | Current spec, recommended |
| HTTP+SSE | `http://127.0.0.1:16870/sse` | 2024 legacy; some clients still only understand this |

Field names differ per client (`url` vs `serverUrl`, whether `type` is needed) — see the "For remote HTTP" note at the end of each client subsection in Step 3.

Two normal behaviours that are not failures:

- Opening `http://127.0.0.1:16870/mcp` in a browser returns **405**. That is correct — the endpoint accepts POST only, not GET.
- A request without a token returns **401**.

## Step 7: Advanced at a glance (optional)

Steps 1–6 get you connected and working. The four things below are what people ask next; each is one sentence, with links at the end.

### Audit log: look here first when something is denied

Every tool call records one JSONL line for "allowed or denied" — the fastest way to debug permission problems.

```bash
# Point at an audit file; you can also set agent.audit in afrog-config.yaml
afrog mcp -policy ./agent-policy.yaml -audit ./audit.jsonl
```

- Recording only happens when the policy sets `audit: true`;
- In the console, **Agent → Policy & Audit** shows the last 200 entries (cap 1000) in a table: time, action, target, allow/deny, matched rule, reason and remaining budget.

### Policy mode and scope: widen capability, narrow the blast radius

The default is read-only; to actually send packets you raise the mode — and you **must constrain targets with `scope`** so the agent cannot roam the whole network.

```yaml
policy:
  mode: safe                 # readonly (default) | safe | full
  deny: ["act.brute"]        # deny always wins
  scope:
    allow_hosts: ["10.0.0.0/8"]
```

- The decision order is fixed: `deny → allowlist → mode → destructive → scope`;
- Saving in the console writes the path into `agent.policy` in `afrog-config.yaml`, so the plain `afrog mcp` inside a client reads the same policy.

### Budget and 429: the session allowance

`budget.requests` is the request allowance for **one session** (default 5000). Once it is used up, packet-sending actions are refused with **429** — but after `budget.duration` of **continuous idle time** (default 10 minutes) a fresh session starts automatically and refills the allowance, **no process restart needed**.

- On 429: either raise `budget.requests`, or pause until the next budgeted call starts a new session on its own;
- **Read-only actions cost nothing**: calls that produce no network request — `server.*` / `observe.*` / `plan.*` / `judge.*` / `learn.*` / `poc.search` / `poc.draft` — never consume the allowance and are unaffected by the idle window (to see what is left, just call the read-only `server.status`);
- A policy denial (403) **does not consume budget**; actions like `scan.start` / `poc.submit` **reserve** budget for the candidates' estimated request count rather than a flat 1;
- Long-running processes (the web console, `afrog mcp -listen`) share one **process-wide session allowance**, debited across all clients and refilled the same way after the idle window.

### OOB: the prerequisite for reverse PoCs

Verification for command execution, XXE and SSRF — where the target does not echo back and only an out-of-band callback can confirm it — needs a reverse platform configured first.

```yaml
# afrog-config.yaml
agent:
  oob: ceyeio        # ceyeio | dnslogcn | alphalog | xray | revsuit | interactsh
```

- Credentials come from the `reverse` section; when unset, `scan.start` / `poc.submit` on a reverse PoC **reports an error explicitly** (fail-closed) instead of silently calling it "not vulnerable";
- If a `plan.next` proposal carries `requires_oob: true`, it concludes via an OOB callback — set up `agent.oob` before running it.

**Read more:** [MCP server](./10-mcp.md) (policy / budget & audit / tool list / REST / gRPC) | [Configuration](./05-configuration.md) (`agent` and `reverse` fields) | [Agent console](../web/12-agent.md) (review queue, tool bench, policy & audit in the UI)

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| afrog does not appear in the client | Bad config / client not restarted | Check the JSON syntax and the top-level key (VS Code uses `servers`, all others use `mcpServers`), then fully restart the client |
| `spawn afrog ENOENT` / command not found | `command` is plain `afrog`, not an absolute path | Use the path you found in Step 0 (`which afrog` on macOS / Linux, `where afrog` on Windows) |
| `afrog mcp -h` reports unknown command | Old afrog build without MCP | Download a current build from GitHub Releases, or run `afrog -update` (see Step 0) |
| `afrog mcp` in a terminal seems to hang | Expected: it is waiting on stdin | Do not Ctrl+C; use the smoke test from Step 1 |
| Tools are listed but all show "blocked" | Default policy is read-only | Widen the mode (Step 5) |
| A call returns 401 | Wrong token in HTTP mode | Make the client's `Authorization: Bearer <token>` match the server's `-token` |
| A call returns 429 | This session's request allowance is used up | Raise `budget.requests`, or wait out `budget.duration` for a fresh session to refill it |
| A long scan reports "tool call timed out" halfway | The client-side tool timeout is too short (most default to 60s) | Raise the client timeout (see 3.0 Ground rules): Cline writes `"timeout": 600` (seconds), Cherry Studio goes to `Settings → MCP → Timeout`; the afrog subprocess may still be running at this point |
| A call returns 403 | Denied by policy (`deny` or `scope`) | Read the rule name and reason in the response, adjust the policy, restart |
| It asks for out-of-band (OOB) configuration | A reverse PoC was run but `agent.oob` is unset | Configure the OOB adapter under `agent.oob` in `afrog-config.yaml` |
| Empty result list | No findings in the local ledger yet | Run a scan, then ask again |

## Next steps

- What each tool does, its arguments and return shapes → [MCP Server](./10-mcp.md)
- Review queue, tool console and policy panel in the GUI → [Agent Tool Surface (MCP)](../web/12-agent.md)
- Call it from scripts instead (no MCP client) → [MCP Server · REST entry point](./10-mcp.md)

> **← Previous:** [MCP Server](./10-mcp.md) ｜ **Handbook home:** [What afrog does](./01-overview.md) ｜ **Next →:** [MCP Tutorial](./12-mcp-tutorial.md)
