<!--
title: JavaScript PoC
slug: /docs/poc/javascript
lang: en
summary: afrog javascript protocol reference — drive network interaction with a JS script, then judge the result with CEL expressions and extractors.
status: published
source: docs/zh/poc/11-javascript.md
last_reviewed: 2026-10-11
-->

Besides the declarative `tcp` / `ssl` multi-step sessions, `afrog` also supports `javascript` PoCs: when a protocol interaction cannot be expressed as a fixed `read` / `write` sequence, you can write a small JS script to do the work, while the match logic still reuses afrog's CEL `expression` and `extractors`.

> **Note: `javascript` is disabled by default.** Because it executes script code embedded in PoC files, afrog does not load javascript PoCs unless you opt in. At startup it prints "javascript PoC detected (skipped)". Enable it explicitly with `-enable-js-poc`, and only after confirming the PoC source is trusted.

This page helps with four questions:

- Should I use `tcp` / `steps`, or `javascript`
- How to write `code`, `args`, and `pre-condition`
- Which modules `require` exposes, and which built-in functions exist
- How script output reaches `expression` and `extractors`

## When you need javascript

A good order of preference:

1. If an HTTP request can express it: use a default HTTP rule
2. If it is a fixed request/response or multi-step session: use `tcp` / `ssl` with `steps`
3. Only when the interaction needs branching, loops, or protocol parsing: use `javascript`

The value of `javascript` is that it is *programmable*. For example, reading a banner and branching on version, doing a second pass over the response, or deciding what to send next based on earlier output — these are awkward to express with declarative `steps`.

## Basic structure

```yaml
id: js-demo-ssh-banner

info:
  name: SSH Banner (JavaScript PoC Demo)
  author: afrog
  severity: info
  tags: js,demo,ssh

rules:
  detect:
    request:
      type: javascript
      pre-condition: |
        isPortOpen(Host, Port)
      code: |
        var m = require("afrog/ssh");
        var c = m.SSHClient();
        var info = c.ConnectSSHInfoMode(Host, Port);
        Export(info.ServerID.Raw);
      args:
        Host: "{{Host}}"
        Port: "{{Port}}"
    expression: response_text.contains("SSH-2.0-")

expression: detect()
```

Key points:

- `request.type` must be `javascript`
- `code` is the JS script body
- `args` are script inputs, rendered and injected as same-named globals
- `pre-condition` is optional; `code` runs only if it evaluates to true
- Matching is still written with CEL in `expression` / `extractors`

## `request` fields

| Field | Common | Purpose |
| --- | --- | --- |
| `type` | required | Always `javascript` |
| `code` | required | The JS script |
| `args` | common | Script inputs, injected as globals after rendering |
| `pre-condition` | optional | Pre-expression; `code` runs only when it is true |

### `code`

`code` is plain JS. afrog creates a fresh JS runtime for each execution, and the script can use the globals injected from `args`.

### `args`

`args` values support variable rendering, so you can use the network target variables afrog injects:

- `{{Host}}`: target hostname
- `{{Port}}`: target port
- `{{Hostname}}`: `host:port`

If your target is `1.2.3.4:2222`, then `Host: "{{Host}}"` and `Port: "{{Port}}"` yield `1.2.3.4` and `2222` directly.

### `pre-condition`

`pre-condition` is a JS expression; the boolean value of its last expression decides:

```yaml
pre-condition: |
  isPortOpen(Host, Port)
```

`code` runs only when it is true — handy for port liveness pruning.

## Built-in functions

Every script runtime provides these globals:

| Function | Purpose |
| --- | --- |
| `Export(value)` | Converts the value to a string and appends it to script output as `response` |
| `isPortOpen(host, port, [timeoutSec])` | Checks whether a TCP port is open; default timeout is 5s |
| `to_json(value)` | Serializes an object to a JSON string |
| `ToString(...)` | Joins arguments into a string |
| `log(value)` | Debug output |

`Export` decides how results flow back: whatever it writes becomes `response_text` / `response.raw` for the following CEL.

## Modules via `require`

`require` currently exposes two afrog-native modules under the `afrog/` namespace:

| Module | Purpose |
| --- | --- |
| `afrog/ssh` | SSH interaction (banner, auth, run command) |
| `afrog/net` | Arbitrary TCP / TLS read and write |

### `afrog/ssh`

```javascript
var m = require("afrog/ssh");
var c = m.SSHClient();
c.SetTimeout(10);

// Only performs the SSH version exchange and reads the server identification
// string. No authentication required.
var info = c.ConnectSSHInfoMode(Host, Port);
Export(info.ServerID.Raw);

// When authentication is needed
// var ok = c.Connect(Host, Port, "root", "password");
// var out = c.Run("id");
// c.Close();
```

`ConnectSSHInfoMode` returns an object whose `ServerID.Raw` looks like `SSH-2.0-Serv-U_15.2.3.742`.

### `afrog/net`

```javascript
var net = require("afrog/net");
var c = net.TCPClient();
// var c = net.TLSClient(); // for TLS
c.SetTimeout(5);
c.SetReadSize(4096);
c.Connect(Host, Port);

c.Send("CAPA\r\n");
var resp = c.RecvUntil("\r\n");   // includes the delimiter, same as tcp read-until
c.Close();
Export(resp);
```

`afrog/net` client methods:

| Method | Purpose |
| --- | --- |
| `Connect(host, port)` | Opens the connection; returns a boolean |
| `Send(data)` | Sends a string |
| `SendHex(hexStr)` | Sends hex-encoded data |
| `Recv([size])` | Reads one response chunk |
| `RecvUntil(delim, [size])` | Reads until the delimiter (delimiter included) |
| `SetTimeout(sec)` / `SetReadSize(n)` | Configure timeout and read cap |
| `Close()` | Closes the connection |

## How results reach CEL

What the script writes via `Export` is stored in two variables:

- `response_text`: string form
- `response`: structured response (`response.raw` as bytes)

So `expression` / `extractors` are written exactly as for any other protocol:

```yaml
rules:
  detect:
    request:
      type: javascript
      code: |
        var m = require("afrog/ssh");
        var c = m.SSHClient();
        var info = c.ConnectSSHInfoMode(Host, Port);
        Export(info.ServerID.Raw);
      args:
        Host: "{{Host}}"
        Port: "{{Port}}"
    expression: response_text.contains("SSH-2.0-Serv-U")

extractors:
  - type: regex
    extractor:
      version: '"SSH-2.0-Serv-U_(?P<version>[0-9.]+)".submatch(response_text)["version"]'

expression: detect() && versionCompare(version, "<", "15.2.3.742")
```

For extractor and function details, see [Helper Functions](./03-helper-functions.md) and [PoC Syntax](./02-syntax.md).

## Full example: SSH version detection

For CVE-2021-35211 (Serv-U) style "read banner + compare version":

```yaml
id: js-servu-ssh-version

info:
  name: SolarWinds Serv-U SSH - Version Detect
  author: your-name
  severity: critical
  tags: js,ssh,servu

rules:
  detect:
    request:
      type: javascript
      pre-condition: |
        isPortOpen(Host, Port)
      code: |
        var m = require("afrog/ssh");
        var c = m.SSHClient();
        var info = c.ConnectSSHInfoMode(Host, Port);
        Export(info.ServerID.Raw);
      args:
        Host: "{{Host}}"
        Port: "{{Port}}"
    expression: response_text.contains("SSH-2.0-Serv-U")

extractors:
  - type: regex
    extractor:
      version: '"SSH-2.0-Serv-U_(?P<version>[0-9.]+)".submatch(response_text)["version"]'

expression: detect() && versionCompare(version, "<", "15.2.3.742")
```

## Limits and common mistakes

### Putting match logic inside JS

`Export` only returns data; the match decision belongs in `expression` / `extractors`. That keeps results readable, reproducible, and reusable with afrog's regex and version-comparison helpers.

### Forgetting to use the return value

Without an `Export` call, afrog uses the value of the script's last expression as output. Prefer an explicit `Export` for readability.

### Using `javascript` for plain HTTP

For plain HTTP, a default HTTP rule is simpler and faster.

### Ignoring timeouts

`isPortOpen` and module methods have default timeouts; the script-wide execution cap is controlled by `-js-script-timeout` (default 60s; set to 0 to disable the script-level cap, in which case only the task-level timeout applies). For slow targets, tune module `SetTimeout` down first, or lower `-js-script-timeout`.

When the scan stops or a task times out, a running script is interrupted immediately instead of waiting for the cap.

### Binary responses

`Export` and `Recv` / `RecvUntil` pass data as strings, which is fine for text protocols. For pure binary protocols, extract only the fragment you need before `Export`.

## One-line takeaway

The `javascript` protocol exists to handle "interaction that needs programming"; the match decision still belongs to afrog's CEL. Each side does its own job.

> **← Previous:** [PoC Contributors](./10-contributors.md) ｜ **Handbook home:** [PoC Quickstart](./01-quickstart.md) ｜ **Docs home →:** [afrog Docs](../index.md)
