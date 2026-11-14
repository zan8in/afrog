<!--
title: Passive Scanning and Coverage
slug: /docs/web/passive
lang: en
summary: Turn real traffic into a detection entry point with the built-in MITM proxy: two-stage pipeline, coverage matrix, evidence lineage, asset relations, next-step suggestions, and the security gate.
status: published
source: new
last_reviewed: 2026-11-14
-->

## What this is

An active scan needs a target list. Passive scanning works the other way around: **let real traffic pass through afrog, and it looks for vulnerabilities in the requests you are already sending**.

Once enabled, afrog starts a local MITM proxy. Point your browser or app at it; it decrypts, observes, replays a small number of requests when needed, and writes findings into the same database as active scans:

- Findings land in **Reports** and the **Ledger**, and can be filtered, reviewed, and exported together with active-scan results.
- Scanned targets are sunk into **Assets** automatically, sharing the same model as active scans.
- Every "was it tested, and if not why" decision is recorded in the coverage ledger.

In one sentence: **an active scan answers "does this target have holes"; passive scanning answers "do the endpoints actually in use have holes".**

## Starting and certificates

Click **Start** on the **Passive Scan** page, or enable `passive.auto_start` in `afrog-config.yaml`. It listens on `127.0.0.1:16869` by default.

HTTPS requires trusting afrog's root CA: use **Download CA certificate** on the page and import it into your system's trusted root store. Without it only plain HTTP can be inspected; HTTPS fails certificate validation and cannot be decrypted.

> Listening on loopback is intentional: the proxy sees all decrypted traffic, so exposing it publicly hands that capability to everyone. Change it to `0.0.0.0` only when you need phone access, and restrict the source with a firewall.

## Configuration

```yaml
passive:
  auto_start: false          # start with afrog web
  host: 127.0.0.1            # listen address
  port: 16869                # listen port
  upstream: ""               # upstream proxy, e.g. http://127.0.0.1:8080; empty = direct
  detectors: [sqli, extract] # enabled detectors
  max_rps: 100               # global replay rate limit
  host_concurrency: 4        # per-host concurrency
  detect_workers: 4          # detection pool concurrency (the real throughput knob)
  queue_size: 4096           # gate queue capacity; drops when full, never back-pressures traffic
  project_id: ""             # owning project for findings; empty = unattributed
  scope_host_allow: []       # only scan these hosts (wildcard suffix supported)
  scope_host_deny: []        # never scan these hosts (takes precedence over allow)
  scope_path_deny: []        # never scan these paths, e.g. /logout, /pay
  scan_unsafe_methods: false # also inspect PUT/PATCH/DELETE and other non-idempotent requests
```

All of it can be edited and saved from the page; it is written back to the same config file and takes effect immediately.

Detectors:

| Name | Type | Description |
| --- | --- | --- |
| `sqli` | network | Parameter injection detection; replays requests |
| `misconfig` | local | Cookie / response header misconfigurations; zero traffic |
| `exposure` | network | One sensitive-file probe per origin (`.git`, `.env`, backups, …) with its own budget |
| `extract` | local | Sensitive data extraction (HAE-equivalent), separate from the finding ledger |
| `fingerprint` | local | Tech stack and component identification |
| `recon` | local | Extra paths and parameters discovered from traffic |

## The two-stage pipeline

Every transaction passes the **gate pool** before it may enter the **detect pool**:

1. **Gate (zero traffic)**: local detectors run (misconfig, extraction, fingerprint), and network detectors decide whether a replay is worthwhile. Static assets, out-of-scope hosts, and already-settled injection points are short-circuited here.
2. **Detect (replays)**: only transactions that truly need it enter, running at `detect_workers` concurrency. Injection detection replays the same request many times with variations.

So it is normal for "captured" to grow much faster than "inspected": most requests are judged not worth detecting at the gate.

`scan_unsafe_methods` is off by default because replaying `PUT/PATCH/DELETE` dozens of times can actually damage business data.

## Page tabs

| Tab | What you see |
| --- | --- |
| Findings | Vulnerabilities found passively, filtered by project / detector / keyword; promote individually into the ledger |
| Extractions | Phones, emails, keys, internal addresses, and other artifacts pulled from responses |
| Coverage | Per "asset × detector": was it tested, and if not why |
| Live Traffic | Disposition and reason for recent transactions (in memory only, not persisted) |
| In-flight | Transactions currently being detected, to explain "captured grows, inspected does not" |
| Diagnostics | Errors and counters from the proxy, parsing, and storage layers |

## Coverage

Coverage answers "where have we not looked", not "what did we find".

It is aggregated by **authority (`host[:port]`, lowercased, scheme-insensitive)**. Each `(project, asset, detector)` row keeps the strongest conclusion ever reached:

| State | Meaning | Priority |
| --- | --- | --- |
| `hit` | This detector found something on this asset | highest |
| `tested` | Really executed, no definite conclusion | next |
| `error` | Execution failed | next |
| `skipped` | Not executed; carries a concrete reason (static asset, out of scope, insufficient parameters, queue full, …) | lowest |

Two invariants:

- **Never downgrades**: a skip can never erase an earlier "tested", otherwise people would re-scan work that was already done.
- **Counters accumulate independently**: `samples`, `hits`, `skipped`, `errors` are tracked separately and are not overwritten by the state.

Below the matrix the page lists **uncovered assets**: they exist in the asset store but never appeared in passive traffic. Addresses that cannot be scanned (for example `21`, a port mistaken for a host) are filtered out of such lists.

## Evidence lineage

Opening a passive finding shows not just request/response evidence but where it came from and how it was judged:

- **Asset anchor**: which asset the finding belongs to; jump straight to the asset page
- **Technique**: detector, vulnerability type, injection location, technique / dialect / evasion / construct
- **Trace steps**: how many replays the verdict took
- **Coverage on the same asset**: a snapshot of every detector's conclusion on that asset

Lineage is a direct rendering of stored fields, not inference: `asset_id` is resolved when the finding is written, and recomputed from the host when it is missing.

## Asset relations

On the **Assets** page select an asset and click **Relations** to expand a parent/child graph rooted at it:

| Direction | Meaning |
| --- | --- |
| Downstream | Coarse to fine: CIDR → IP → host:port → URL |
| Upstream | The reverse: which IP / CIDR a URL belongs to |

Derivation is fully programmatic with no DNS resolution, limited to three layers:

- `authority` (host[:port]) → `url`
- `ip` / `domain` → `hostport`
- IPv4 `/24` → `ip`

IPv6 ranges and eTLD registrable domains are **not derived**: the former would explode the graph, the latter needs a complete public suffix list. Better one edge fewer than a wrong guess.

The graph stores edges, not nodes. Intermediate nodes that never entered the asset table (say, an authority that was never stored on its own) are synthesized on read and labelled **derived**, so asset counts and statistics stay clean.

## Next-step suggestions

The **Next steps** card on the Overview page is derived by deterministic rules from existing data, with no model call, and every item maps to one action:

| Rule | Criterion | Action |
| --- | --- | --- |
| Unscanned assets | No scan history and no passive coverage | Hand the targets to the scan page |
| Coverage gaps | Passive traffic exists, but every detector only reports `skipped` | Jump to coverage details |
| Stale assets | Not retested for over 30 days | Hand the targets to the scan page |
| Unpromoted findings | Passive findings passed the zero-false-positive gate but `promoted = 0` | Jump to passive findings |

"Unscanned" and "stale" are strictly mutually exclusive: the former requires never being scanned, the latter only covers scanned assets, so the same target is never listed twice.

The × on each suggestion means "don't show this for 7 days": the dismissal lives only in the current browser (localStorage) and does not affect other devices. **Ignored N · Restore** in the card header brings everything back immediately, and entries reappear automatically after 7 days.

Targets are filtered for executability first: an address such as `21` never appears in a one-click scan. At startup afrog also cleans up historical junk — only rows that were **never scanned, starred, tagged, or archived** are removed; everything else is kept.

## Security gate

Passive scanning sends its own requests (the `exposure` probe and injection replays), so high-risk actions are governed by the `security` section:

```yaml
security:
  actions:
    cluster-dispatch: allow   # remote cluster dispatch
    exposure-probe: allow     # passive sensitive-path probing
  allow_targets:              # target allowlist; non-empty means a hard boundary
    - corp.example            # exact host, excludes subdomains
    - "*.corp.example"        # wildcard suffix, includes the apex
    - 10.0.0.0/24             # CIDR
```

Semantics:

- **Everything defaults to allow**: upgrading never silently changes behavior.
- **mode**: `allow` permits, `deny` rejects, `ask` requires human confirmation — on an unattended server that means "reject and record", never a silent pass.
- **The allowlist is a hard boundary**: once configured, targets outside it are rejected regardless of mode. This prevents a leaked cluster token from turning this host into a pivot.
- **Exact hosts do not cover subdomains**: use `*.example.com` for that.

Where it applies:

- `cluster-dispatch`: validates targets before accepting a remote dispatch. A rejected dispatch does not consume its `dispatch_id`, so it can be retried after the allowlist is updated.
- `exposure-probe`: decided once per origin at the gate stage; when rejected no probe is sent, and coverage records `skipped` with the rejection reason. Decisions are cached per origin, so the audit log is not flooded per request.

The **Gate details** drawer on the Overview page is read-only: it shows action modes, the allowlist, and recent decisions. Decisions are appended to `~/.config/afrog/guard_audit.jsonl`, so denials and allows survive a restart; the UI shows the latest 200, and the file is trimmed to the latest 1000 once it exceeds 1 MB. Change policy in the config file — that keeps a stray click from disabling your own scan boundary.

## FAQ

**No traffic at all?**
Check that the browser/device proxy points at `127.0.0.1:16869`; for HTTPS also confirm the root CA is trusted. Then look for proxy-level errors on the Diagnostics tab.

**Captured grows but inspected does not?**
Check **In-flight** and **Live Traffic**: most likely the gate decided it was not worth detecting (static asset, out of scope, injection point already settled), or the detect pool/queue is saturated. `dropped-detect` means detection was warranted but capacity was exhausted — a real miss risk.

**Coverage is all `skipped`?**
Read the reason column: usually no parameters, a tiny response body, a target outside the scan scope, or a rejection by the security gate.

**Do passive findings duplicate active scans?**
Same database and same ledger. Deduplication aggregates by `(project, fingerprint)`, so repeated hits only increase the count.

> **← Previous:** [Settings](./10-settings.md) ｜ **Handbook home:** [Web Console Overview](./01-overview.md)
