<!--
title: JavaScript PoC
slug: /docs/poc/javascript
lang: en
summary: afrog javascript protocol reference — drive network interaction with a JS script, then judge the result with CEL expressions and extractors.
status: published
source: docs/zh/poc/11-javascript.md
last_reviewed: 2026-10-13
-->

Besides the declarative `tcp` / `ssl` multi-step sessions, `afrog` also supports `javascript` PoCs: when a protocol interaction cannot be expressed as a fixed `read` / `write` sequence, you can write a small JS script to do the work, while the match logic still reuses afrog's CEL `expression` and `extractors`.

> **`javascript` is enabled by default.** It executes script code embedded in PoC files (a script can only make network requests — it cannot read files or run commands). In sensitive environments, disable it with `-enable-js-poc=false`; when disabled, startup prints "javascript PoC detected (skipped)". An optional [trust and signing](#trust-and-signing) mechanism is also available to verify a script's origin and integrity.

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
| `ExportAs(key, value)` | Stores the value under `key` so `expression` / `extractors` can reference it directly |
| `isPortOpen(host, port, [timeoutSec])` | Checks whether a TCP port is open; default timeout is 5s |
| `to_json(value)` | Serializes an object to a JSON string |
| `ToString(...)` | Joins arguments into a string |
| `log(value)` | Debug output |

`Export` decides how results flow back: whatever it writes becomes `response_text` / `response.raw` for the following CEL.

`ExportAs` returns **structured, named results**: after `ExportAs("banner", info.ServerID.Raw)` you can write `expression: banner.contains("SSH-2.0-")` directly. `key` must be a valid identifier (start with a letter or underscore, then letters, digits, or underscores), and should be written as a string literal: afrog scans the script and pre-declares every `ExportAs` key, so a branch that did not run leaves the variable as an empty string and `expression` still compiles. When one script produces several fields, or an extractor needs a value by name, this is far clearer than concatenating strings.

## Modules via `require`

`require` currently exposes two afrog-native modules under the `afrog/` namespace:

| Module | Purpose |
| --- | --- |
| `afrog/ssh` | SSH interaction (banner, auth, run command) |
| `afrog/net` | Arbitrary TCP / TLS read and write |
| `afrog/bytes` | Binary buffer for assembling packets before sending |
| `afrog/structs` | Binary pack / unpack (struct-style formats) |
| `afrog/mysql` | MySQL handshake / login (version detect, weak credentials) |

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

`ConnectSSHInfoMode` returns an object whose `ServerID.Raw` looks like `SSH-2.0-Serv-U_15.2.3.742`. On failure `ServerID.Raw` / `Banner` are empty strings and the reason is in `c.LastError()` (module methods never throw — see the `afrog/net` note below).

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
| `Connect(host, port)` | Opens the connection; returns `true` / `false` |
| `Send(data)` | Sends a string; returns the number of bytes written |
| `SendHex(hexStr)` | Sends hex-encoded data; returns the number of bytes written |
| `Recv([size])` | Reads one response chunk; returns a string |
| `RecvUntil(delim, [size])` | Reads until the delimiter (delimiter included); returns a string |
| `SetTimeout(sec)` / `SetReadSize(n)` | Configure timeout and read cap |
| `Close()` | Closes the connection |
| `LastError()` | Description of the last method error; empty string when there is none |

> **Module methods never throw.** Expected failures such as a refused connection or a read timeout do not throw — the method returns a zero value (`false` / `0` / `""`) and the reason is recorded in `LastError()`. So there is no need to wrap calls in `try/catch`; just check the return value. Only API misuse (e.g. an invalid `ExportAs` key) throws.

Timeouts match `tcp` / `ssl` PoCs: module defaults are the smaller of afrog's global `-timeout` and a base value (3s dial, 6s read, 3s write), and `SetTimeout(sec)` overrides them. When the script ends, afrog closes any connection you forgot to `Close()`, so nothing leaks.

### `afrog/bytes`

A buffer for assembling binary packets from several pieces:

```javascript
var bytes = require("afrog/bytes");
var b = bytes.NewBuffer();
b.WriteString("GET /");
b.WriteHex("0d0a");
b.Pack(">H", 8009);        // append using a struct format
Export(b.Hex());
// c.Send(b.String());
```

| Method | Purpose |
| --- | --- |
| `NewBuffer([initial])` | Creates a buffer; accepts strings / byte arrays |
| `Write(...)` | Appends strings / byte arrays |
| `WriteString(s)` / `WriteHex(hexStr)` | Appends a string / hex-encoded data |
| `WriteUint8(n)` / `WriteUint16(n)` / `WriteUint32(n)` / `WriteUint64(n)` | Appends big-endian integers |
| `Pack(format, ...values)` | Packs with a struct format and appends |
| `String()` / `Bytes()` / `Hex()` / `Len()` / `Reset()` | Read the result or reset |

### `afrog/structs`

Binary pack / unpack, using a subset of Python's struct format:

```javascript
var structs = require("afrog/structs");
var payload = structs.Pack(">HI", 0x1234, 0x100);   // raw bytes, ready for Send
var vals = structs.Unpack(">HI", response);          // array of values
var size = structs.CalcSize(">HI");                  // 6
```

- Byte order: `<` little-endian, `>` / `!` big-endian (big-endian by default)
- Types: `b` / `B` int8/uint8, `h` / `H` int16/uint16, `i` / `I` int32/uint32, `q` / `Q` int64/uint64, `s` fixed-length string (e.g. `4s`), `x` pad byte
- Repeat counts are supported, e.g. `2H`, `4s`
- A value/format mismatch or too-short data throws (that is API misuse)

### `afrog/mysql`

MySQL protocol interaction: read the server handshake (**the version is available before auth**) and complete password authentication.

```javascript
var mysql = require("afrog/mysql");
var c = mysql.MySQLClient();
c.SetTimeout(5);
if (c.Connect(Host, Port)) {
  var hs = c.Handshake();          // Version / ThreadID / Charset / Capabilities / AuthPlugin / Salt
  ExportAs("version", hs.Version); // server version, before any auth
  if (c.Login("root", "root")) {
    var r = c.Query("select version()");
    ExportAs("dbver", r.Rows[0][0]);  // first column of the first row
  }
  c.Close();
}
```

| Method | Purpose |
| --- | --- |
| `Connect(host, port)` | Opens the connection and reads the handshake; returns `true` / `false` |
| `Handshake()` | Returns the handshake object (`Version`, `ThreadID`, `Charset`, `Capabilities`, `AuthPlugin`, `Salt`) |
| `Login(user, password)` | Authenticates; returns `true` on success |
| `Query(sql)` | Sends SQL and parses the response; returns `{ Columns, Rows, AffectedRows, LastInsertID, ErrNo, ErrMsg }` |
| `Close()` | Closes the connection |
| `LastError()` | Description of the last method error |

Supports `mysql_native_password` and `caching_sha2_password`, and follows the server's Auth Switch request. `Query` covers text-protocol result sets (column names + rows) as well as OK / ERR responses; on a server error `ErrNo` / `ErrMsg` carry the code and message.

## Trust and signing

Because a `javascript` PoC executes script code, afrog offers an optional signature check to confirm that "this code really comes from the source it claims, and has not been tampered with". Only PoCs carrying code / privileged capability participate; purely declarative `http` / `tcp` PoCs are not involved.

### What a signature looks like

The signature is a `# digest:` comment appended as the **last line** of the file; it does not participate in YAML parsing:

```yaml
id: js-demo
# ... rest of the content ...
expression: r0()
# digest: uvKInOS6sizVvUzrAmHcLYse6gYidD75RZ7VdqeDMo8Wi/i8+fRTkjZtA8gHk38vIcJalQaiAxKOBFj0Py38Bg==
```

The algorithm is ed25519, and the signature covers all content before the signature line. The signature line must be the last line — if anything follows it, afrog treats the PoC as unsigned, preventing someone from appending YAML after the signature to bypass the check.

### Lenient by default

The default is **lenient mode**: verify if a signature is present, warn (but do not block) if it fails, and run unsigned PoCs as usual. This keeps "user-authored PoCs work out of the box". For stricter control, enable strict mode:

```bash
afrog -require-signed-js-poc ...
```

In strict mode, `javascript` PoCs that are unsigned or carry an invalid signature are skipped, and the skipped PoCs (with reasons) are listed at startup.

### Signing your own PoCs

A built-in tool signs a file or a whole directory in place; the key is generated automatically on first use:

```bash
afrog -pocsign my-poc.yaml
afrog -pocsign ./my-pocs/
```

It prints something like:

```text
signed=3 key=eLNAXRGlIcY4
pubkey=eLNAXRGlIcY4xxx...==
```

`key` is the public key fingerprint, `pubkey` is the full base64 public key. Key locations:

- Private key: `~/.config/afrog/keys/signing.key` (mode `0600`)
- Public key: `~/.config/afrog/keys/verification.pub`

### Which public keys are trusted

afrog accepts a public key from any of the following sources when verifying:

1. **Official key**: embedded in the binary and injected at release build time (`-ldflags "-X .../pkg/pocsign.officialPublicKeyB64=<...>"`). In a development source tree it is empty, meaning official verification is not enabled.
2. **Your own key**: i.e. `~/.config/afrog/keys/verification.pub`, so your own signed PoCs verify automatically.
3. **The `AFROG_POC_PUBKEY_B64` environment variable**: adds one more base64 public key, handy for CI or internal enterprise distribution.

### Signing official PoCs (maintainers)

Official PoCs are distributed two ways, and both must be signed with the **same official private key**:

- `pocs/afrog-pocs/`, embedded into the binary: sign it in the release pipeline, before the build;
- `afrog-pocs.zip`, downloaded by runtime updates: sign it in the pipeline that packages that zip.

**Prepare the key pair once.** Use the self-sign tool to generate one, then move it into CI:

```bash
# Sign any file to auto-generate the key pair under ~/.config/afrog/keys/
afrog -pocsign any-poc.yaml

# Private key -> store as a CI secret (the file text is already base64)
cat ~/.config/afrog/keys/signing.key
# Public key -> store as a CI secret, or use the output below directly
cat ~/.config/afrog/keys/verification.pub
```

> The private key lives only in the CI secret (`AFROG_POC_SIGNING_KEY_B64`); it **never** goes into the repository.

**Sign and build in the pipeline:**

```bash
# 1) Sign official PoCs with the official private key (the env var overrides the
#    user key and writes nothing to the user's key directory)
AFROG_POC_SIGNING_KEY_B64="$OFFICIAL_KEY" afrog -pocsign pocs/afrog-pocs
#    -> signed=1234 key=<fingerprint>
#    -> pubkey=<base64 public key>

# 2) Inject the pubkey above via -ldflags so the binary embeds the official key
go build -ldflags "-X github.com/zan8in/afrog/v3/pkg/pocsign.officialPublicKeyB64=<base64 public key>" ./cmd/afrog
```

The repo's `.goreleaser.yaml` already wires that `-X` to the `AFROG_POC_PUBKEY_B64` environment variable (empty string when unset), and
`.github/workflows/release.yml` already runs `-pocsign` before the build and exports the derived public key to goreleaser —
so maintainers only need to set the `AFROG_POC_SIGNING_KEY_B64` secret and everything else is automatic.

## How results reach CEL

What the script writes via `Export` is stored in two variables:

- `response_text`: string form
- `response`: structured response (`response.raw` as bytes)

Values written with `ExportAs(key, value)` are additionally stored under `key`; both channels can be mixed in the same rule's `expression`:

```yaml
    code: |
      var info = c.ConnectSSHInfoMode(Host, Port);
      ExportAs("banner", info.ServerID.Raw);   // named, referenced below
      Export(info.ServerID.Raw);               // also returned as response_text
    expression: |
      response_text.contains("Serv-U") && banner.contains("SSH-2.0")
```

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

When the scan stops or a task times out, a running script is interrupted immediately — including scripts blocked on network reads such as `Connect` / `Recv`: afrog propagates the task context cancellation to module dialing and I/O, so the connection is torn down right away instead of waiting for the module timeout.

### Binary responses

`Export` and `Recv` / `RecvUntil` pass data as strings, which is fine for text protocols. For pure binary protocols, extract only the fragment you need before `Export`.

## One-line takeaway

The `javascript` protocol exists to handle "interaction that needs programming"; the match decision still belongs to afrog's CEL. Each side does its own job.

> **← Previous:** [PoC Contributors](./10-contributors.md) ｜ **Handbook home:** [PoC Quickstart](./01-quickstart.md) ｜ **Docs home →:** [afrog Docs](../index.md)
