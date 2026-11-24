<!--
title: MCP Tutorial
slug: /docs/user-guide/mcp-tutorial
lang: en
summary: A user-facing walkthrough of afrog MCP: start one long-lived HTTP server with `afrog mcp -listen`, connect an AI client, verify it, and widen the policy mode as needed.
status: published
source: new
last_reviewed: 2026-11-24
-->

## What this tutorial gets you

A long-lived **afrog MCP server** lets AI clients (Claude, Cursor, Cline, VS Code…) read your afrog findings, read the attack surface, probe ports and verify PoCs — all under afrog's policy, budget and audit controls.

**Recommended setup**: run **one long-lived HTTP server** and let every client connect to it. `afrog mcp` over stdio also works, but then each client spawns its own afrog process, spreading out configuration and resources.

> Want to copy config per client? See [Beginner's guide: connect your AI client to afrog](./11-mcp-quickstart.md).

## Before you start

- afrog is installed and you can run `afrog` directly in a terminal.
- You have an AI client available (Claude Desktop, Cherry Studio, Cursor, VS Code, Cline, Windsurf or Claude Code — any one will do).

## Step 1: Start the server

```bash
afrog mcp -listen 127.0.0.1:16870 -token your-token
```

- `-token` is **a passphrase you choose yourself** (a shared secret), not a fixed value. Generate one with `openssl rand -hex 32` (macOS / Linux) or `[guid]::NewGuid().ToString('N')` (Windows PowerShell).
- The same listener serves both transports: `http://127.0.0.1:16870/mcp` (Streamable HTTP, recommended) and `http://127.0.0.1:16870/sse` (legacy clients).
- Health check: `curl http://127.0.0.1:16870/healthz` returns `ok` when the server is up.
- Listening on a non-local address (e.g. `0.0.0.0:16870`) **requires** `-token`, otherwise afrog refuses to start.

## Step 2: Connect your client

Point the client at the URL and pass the token:

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

> Field names differ per client (`url` vs `serverUrl`, whether `type` is needed, and VS Code uses a top-level `servers` key). Per-client config is in [step 3 of the beginner's guide](./11-mcp-quickstart.md#step-3-connect-your-client).

Claude Code does it in one line:

```bash
claude mcp add --transport http afrog -s user http://127.0.0.1:16870/mcp \
  --header "Authorization: Bearer your-token"
```

## Step 3: Verify

Ask your client:

> Use afrog to list the most recent findings, at most 5.

If it calls `observe.findings` and returns a result, the connection works — **an empty list still counts**.

## Step 4: Let the agent actually scan (pick a mode)

MCP is **read-only by default**: a freshly started server sends no traffic at all. What the agent may do is decided by `policy.mode`. **A real full vulnerability scan requires `mode: full`** — stop at any lower mode and something will be missing:

| `mode` | The agent may… | What is missing |
| --- | --- | --- |
| `readonly` *(default)* | read only: findings, evidence, attack surface, observations; search / draft PoCs; server status | **everything that sends traffic** — no port probe, no fingerprint, no scan, no verify |
| `safe` | probe HTTP / ports / fingerprints (`probe.*`), run PoCs (`scan.start`, JS PoCs included), replay evidence (`verify.replay`), submit PoCs (`poc.submit`) | **active attack** — `act.brute` (weak-password brute force) and active OOB (`act.oob_payload` / `act.oob_wait`) from `act.*` |
| `full` | all of the above, **plus** `act.*` | nothing — the complete capability set |

- **Stop at `readonly`**: you will not find a single vulnerability.
- **Stop at `safe`**: you can probe, scan and verify, but you **miss the active-attack `act.*` tools**.
- **Only `full` has no capability gap** — which is why a real full vulnerability scan uses `full`.
- Note: **`full` is still not the finish line** — `destructive` is an independent switch, orthogonal to the mode, and defaults to `false`: `act.brute`, active OOB, and `poc.submit` of a JS/Go (exec-level) PoC additionally require `destructive: true`; `scan.start` is declarative and is not affected by this switch.

### Recommended: configure it visually in the web console (`afrog -web`)

Prefer clicking over hand-writing YAML? The built-in web console edits **the same policy**, and saving applies it to the MCP server immediately.

1. **Start the console** (in another terminal):

   ```bash
   afrog -web
   ```

   It listens on `:16868` by default and prints this run's password: `[INF] Web访问密码: xxxxxxxxxxxxxxxx` (Web access password).

2. **Sign in in a browser**: open `http://127.0.0.1:16868` and log in with the password from step 1.

3. **Open the page**: left-hand nav **Agent → 策略与审计** (Policy & Audit).

4. **Set what you need** (matching the mode table above):
   - Set the **capacity mode** to **`full`** for a real full vulnerability scan (`safe` if you only probe / scan and do not need brute force);
   - Turn on the **destructive actions** switch only if you need weak-password brute force and the like;
   - Use the **scope** allow-hosts list to keep targets inside your authorization;
   - Adjust the **session budget** if you wish (leave blank for the defaults: 5000 requests / 10 minutes).

5. **Save**: click **Save** and you will see *"已保存，立即生效（会话预算随之重置）"* (saved, effective immediately; the session budget is reset). The page writes the policy to `agent-policy.yaml` and points the `agent` section of `afrog-config.yaml` at it.

> **The web console and `afrog mcp` read the same policy**: once saved on the page, the MCP server picks it up on its **next tool call** — no need to restart `afrog mcp` or the console.

> The OOB adapter (`agent.oob`) is not edited here; it stays in `afrog-config.yaml`. The full page reference is in [Web console: Agent surface](../web/12-agent.md).

**You can also hand-write the policy file** (the same one the web console saves):

```yaml
# agent-policy.yaml — use full for a full vulnerability scan; add destructive: true if you also need brute force
policy:
  mode: full                       # readonly (default) | safe | full
  scope:
    allow_hosts: ["10.0.0.0/8"]    # constrain the blast radius, whatever the mode
```

```bash
afrog mcp -listen 127.0.0.1:16870 -token your-token -policy ./agent-policy.yaml
```

## Keep in mind

- **Raise the client tool timeout to about 10 minutes.** Scans can run for minutes, while most clients default to 60 seconds.
- **Full-port and full-library scans are supported.** Ask for "a full port scan of `<host>`" (the tool runs `ports: "full"`), or leave the PoC keyword empty for a whole-library scan.
- Read-only calls cost no budget; packet-sending calls reserve from a per-session allowance (default 5000) that refills after 10 minutes idle. Call the read-only `server.status` any time to see what is left.

## Read more

- [Beginner's guide: connect your AI client to afrog](./11-mcp-quickstart.md) — per-client setup and troubleshooting.
- [MCP Server (reference)](./10-mcp.md) — tool list, policy and budget mechanics, HTTP deployment and security notes.

> **← Previous:** [Beginner's Guide: Connect Your AI Client to afrog](./11-mcp-quickstart.md) ｜ **Handbook home:** [What afrog does](./01-overview.md) ｜ **Docs home →:** [afrog Docs](../index.md)
