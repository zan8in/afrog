<!--
title: Multiple Instances and Remote Dispatch
slug: /docs/web/cluster
lang: en
summary: The multi-instance status summary and node registration on the Overview page, plus the full mechanism for dispatching a scan to an online peer node.
status: published
source: new
last_reviewed: 2026-10-10
-->

## Multi-instance status

The **Multi-instance** card on the **Overview** page aggregates the health of this machine and its peer `afrog` instances: version, online status, active task count, CPU / memory, and heartbeat latency.

- With a single instance (no `cluster` configured) you see just this machine's row, and the card also shows a configuration example
- Peers are registered under `cluster.peers` in `afrog-config.yaml`, and the same cluster shares a `cluster.token`
- This instance reads peer status every 30 seconds; when a peer is unreachable it shows the reason honestly (token mismatch / outdated version / cannot connect) instead of letting the node drop off the list

### Adding or removing nodes at runtime (members)

**Edit nodes** at the top right of the card lets you directly change this node's name, the cluster token, and the peer list. Saving writes back to `afrog-config.yaml` and rebuilds the heartbeat immediately — a new node enters the list right away (shown as *probing* during its first probe), with no restart needed.

> The 30-second heartbeat is a fixed rhythm: the config is read once at service startup and the file is not re-read afterwards; a hand-edited `afrog-config.yaml` still needs a restart to take effect. Validation on save: addresses must be http/https (the scheme prefix may be omitted), duplicate addresses are de-duplicated automatically, at most 64 peers, and a cluster token is required once peers are configured.

## Cross-node dispatch (members)

The **Scan** workbench has an **Execution node** selector (listing online peers, defaulting to this machine). Pick a node and hit **Start scan** and that node runs the scan.

- **The task belongs to the executing node**: the task, its event stream and its finding details all stay on the executing node (single source of truth); the initiator only keeps a mirrored record showing node name, status, progress and hit count
- **Read-only findings proxy**: opening a remote task on the initiator lets you view that node's finding details read-only, with no separate login to that node
- **Findings backfill (once the task settles)**: as soon as a remote task reaches a terminal state the initiator backfills its findings into the local results database — reports, the ledger and exports can all find them, with entries tagged with their source node. The backfill is idempotent: the task's rows are cleared first and rewritten as a batch, so retries never produce duplicates, and the raw request/response is preserved alongside
- **Disconnection consistency**: dispatch carries an idempotency key, so network flapping or retries never start the scan twice; when the executing node cannot be reached the task is flagged **node unreachable** and keeps the last reconciled status (never a false *failed*), and resumes reconciling automatically once it recovers
- **Survives restarts**: mirrored records are persisted to `~/.config/afrog/remote_tasks.json`, so the task list displays as usual after the initiator process restarts, and unfinished tasks resume reconciling automatically
- **Dispatch by project**: select a project on the initiator and dispatch. The initiator resolves the project into a concrete target list locally before sending, so the executing node needs no copy of that project; when the initiator backfills the findings it registers them under the originating project
- **Schedules can dispatch too**: the schedule form also offers the **Execution node** field, so a scan is handed to that node automatically when it fires.

### Requirements

- Both sides must configure the same `cluster.token` (an instance without a token accepts no dispatches)
- Only Curated members can dispatch.

## Related configuration

For the configuration fields of nodes and tokens see the `cluster` section of the [configuration file reference](../user-guide/05-configuration.md).

> **← Previous:** [Scheduled Scans](./07-scheduled-scans.md) ｜ **Handbook home:** [Web Console Overview](./01-overview.md) ｜ **Next →:** [AI Assist](./09-ai.md)
