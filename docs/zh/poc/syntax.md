---
title: PoC 语法参考
slug: /docs/poc/syntax
lang: zh
summary: afrog PoC 顶层字段和基础语法的权威参考页。
status: published
source: docs/afrog-poc-guide.md
last_reviewed: 2026-09-16
---

本页用于沉淀 `afrog` PoC 的基础语法和字段结构，偏向“字段定义”和“写法边界”，不以教程为主。

## 顶层结构

一个 PoC 文件最常见的顶层键包括：

- `id`
- `info`
- `set`
- `rules`
- `expression`

基础示例：

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

## `info`

常用字段如下：

- 必填：`name`、`author`、`severity`
- 可选：`description`、`tags`、`created`、`reference`、`verified`、`requires`、`requires-mode`

严重级别支持：

- `critical`
- `high`
- `medium`
- `low`
- `info`

示例：

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

## `set`

`set` 用于定义可复用变量，变量可以在请求和表达式中通过 `{{var}}` 引用。

示例：

```yaml
set:
  username: admin
  password: admin
  randstr: randomLowercase(8)
```

## `rules`

每条规则通常由：

- `request`
- `expression`

组成。

### `request`

常见字段：

- `method`
- `path`
- `headers`
- `body`
- `follow_redirects`

示例：

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

### `expression`

`afrog` 使用 CEL 表达式进行判断。

常见对象：

- `response.status`
- `response.body`
- `response_text`
- `response.headers`
- `response.raw_header`
- `response.latency`

常见判断函数：

- 文本：`contains`、`icontains`、`rmatches`、`submatch`、`submatchall`
- 字节：`bcontains`、`ibcontains`、`bmatches`、`bsubmatch`、`bsubmatchall`

示例：

```yaml
expression: |
  response.status == 200 &&
  "((u|g)id|groups)=[0-9]{1,4}\\([a-z0-9]+\\)".rmatches(response_text) &&
  !response_text.icontains("error")
```

### 文本匹配与字节匹配的迁移建议

如果你要处理中文页面、已解码响应或正则提取，推荐优先使用 `response_text` 及其对应函数。

旧写法：

```yaml
'"(?P<title>.+)"'.bsubmatch(response.body)
```

推荐写法：

```yaml
'"(?P<title>.+)"'.submatch(response_text)
```

## 顶层 `expression`

顶层 `expression` 用来组织多个规则的关系。

示例：

```yaml
expression: ping() && version()
```

如果只有一条规则，也需要显式写出顶层表达式。

## `output` 与 `extractors`

`afrog` 支持从响应中提取变量，供后续规则继续使用。

### `output`

推荐写法之一：

```yaml
rules:
  r0:
    request:
      method: GET
      path: /profile
    expression: response.status == 200
    output:
      web_title: '"<title>(?P<webtitle>.+)</title>".submatch(response_text)'
```

### `extractors`

等价的提取方式也可以写成：

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
```

## 动态多值提取

需要提取多个值并逐个验证时，推荐组合：

- `submatchall` / `bsubmatchall`
- `brute`

示例：

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

## 相关文档

- [PoC 编写快速开始](./quickstart.md)
- [内置函数参考](./helper-functions.md)
- [requires 指纹门控](./requires.md)
- [brute 机制](./brute.md)
- [OOB 带外检测](./oob.md)
- [Raw HTTP](./raw-http.md)
- [TCP / SSL](./tcp.md)
