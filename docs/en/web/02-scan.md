<!--
title: Launching a Scan
slug: /docs/web/scan
lang: en
summary: Enter targets, choose a scan intent, configure advanced parameters, use AI recommended parameters, and pick an execution node in the web console.
status: published
source: new
last_reviewed: 2026-10-10
-->

## Target input

Enter targets on the **Scan** page to get going. The input box automatically recognizes and normalizes the following forms, one per line:

- URL: `https://example.com/login`
- Domain: `example.com`
- IP with port: `192.168.1.10:8080`
- CIDR: `10.0.0.0/24`

You can also skip typing them by hand and select a batch of targets from the [Assets](./04-assets-projects.md) page to carry over to the Scan page, or launch from a [Project](./04-assets-projects.md) (using the project's assets as the only target source).

## Scan intent

The scan intent decides how many PoCs run:

| Intent | When to use |
| --- | --- |
| Quick check | Single target, high-severity PoCs, an answer in tens of seconds |
| Standard scan | Full PoC set, can run in the background, breadth first |
| Re-test diff | Automatically compares against the project's previous scan to see whether it was fixed (member) |

> "Re-test diff" requires the task to belong to a project: the project is how "the previous scan" is found, so only a scan launched from a project can do the comparison.

## Advanced parameters

When you need finer control, expand "Advanced"; these parameters are exactly the same as on the command line:

- Concurrency, rate, timeout, retries
- Proxy, request headers
- OOB out-of-band detection
- Port scan, web probing and fingerprinting
- PoC scope (source / manually selected PoCs / keyword)
- Severity filtering

The "PoC and scope" group lets you **manually select which PoCs to run** (searchable, multi-select); if you select none, they are recommended automatically by severity.

## AI recommended parameters

After pasting the targets, click "AI recommended parameters". Based on the scale and type of the targets (URL / IP / CIDR / domain) and the current intent, the AI returns 2–4 reasons and organizes concurrency, rate, timeout, smart concurrency, port scan, web fingerprint, severity, and so on into a ready-to-use configuration. Click "Apply recommended parameters" at the bottom of the drawer to write them back into the form (you can still fine-tune them by hand afterwards).

- **Only a target profile is uploaded**: what is sent is the target count, the type distribution, and at most 20 samples — not the full target list.
- **Values stay within bounds**: out-of-range numbers are clamped back to the allowed range, and invalid severities are dropped.
- **Only recommended fields are overwritten**: fields the model did not provide keep your current settings.
- Re-opening the same batch of targets is served from cache; when no model is configured you are guided to "Settings → AI assist".

See [AI Assist](./09-ai.md).

## Choosing an execution node (member)

The "Scan" workbench has an "Execution node" selector (listing online peers, defaulting to this instance). After selecting a node, click "Start scan" and this scan is handed to that node to run; see [Multiple Instances and Remote Dispatch](./08-cluster.md).

## Starting the scan

Click "Start scan" and the front end assembles the targets, PoC scope, and parameters into one scan request submitted to the server:

- The server registers the task immediately and returns a task ID; the front end subscribes to the event stream and displays it in real time.
- Tasks have a **concurrency limit** (default 6, adjustable via the `AFROG_MAX_RUNNING_TASKS` environment variable); tasks beyond it are queued.

After submitting you land in the task list and details; see [Tasks and Live Progress](./03-tasks.md).

> **← Previous:** [Web Console Overview](./01-overview.md) ｜ **Handbook home:** [Web Console Overview](./01-overview.md) ｜ **Next →:** [Tasks and Live Progress](./03-tasks.md)
