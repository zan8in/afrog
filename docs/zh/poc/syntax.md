---
title: PoC 语法参考
slug: /docs/poc/syntax
lang: zh
summary: afrog PoC 语法与字段参考，先帮助你判断该写什么，再支持按字段深查。
status: published
source: docs/afrog-poc-guide.md
last_reviewed: 2026-09-16
---

这页不是“从零到一”的教程，而是 PoC 作者在真正落笔时最常回来看的一页。

你可以把它当成两层工具：

- 外层：先判断“这一条 PoC 该由哪些部分组成”
- 内层：再精确查某个字段、某种请求类型或某种写法边界

如果你还没有写出第一条 PoC，先看 [PoC 编写快速开始](./quickstart.md)；如果你已经开始写规则，这页更适合常驻开着查。

## 先建立心智模型

大多数 `afrog` PoC 都可以拆成 5 个问题：

1. 这条 PoC 叫什么，属于什么漏洞: `id` + `info`
2. 有没有要复用的变量: `set` / `payloads`
3. 要发什么请求: `rules.*.request`
4. 每条规则什么时候算成功: `rules.*.expression`
5. 多条规则如何组成最终命中: 顶层 `expression`

## 顶层结构

一个 PoC 文件最常见的顶层键如下：

| 顶层键 | 是否常用 | 作用 | 什么时候需要 |
| --- | --- | --- | --- |
| `id` | 必需 | PoC 唯一标识 | 所有 PoC |
| `info` | 必需 | 元信息、严重级别、标签、requires | 所有 PoC |
| `set` | 常用 | 定义可复用变量 | 需要随机值、拼接变量、复用常量时 |
| `payloads` | 进阶 | 提供多组输入组合 | 爆破、枚举、组合验证时 |
| `rules` | 必需 | 规则主体，包含请求与判断逻辑 | 所有 PoC |
| `expression` | 必需 | 组织多个规则的最终关系 | 所有 PoC |
| `transport` | 可选 | 指定默认传输方式 | 非默认 HTTP 场景 |
| `gopoc` | 可选 | 绑定 Go PoC | 逻辑无法用普通 YAML 表达时 |
| `extractors` | 少见 | 顶层提取器 | 需要全局提取时 |

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

### 一个健康的最小 PoC 应该满足什么

最少应包含：

- 一个稳定的 `id`
- 一组最基本的 `info`
- 至少一条 `rules`
- 一个显式的顶层 `expression`

如果你写完后发现自己只写了 `rules`，但没有顶层 `expression`，通常就是还没收尾。

## `info`

`info` 是这条 PoC 的“身份卡”和“检索面”。它既影响文档可读性，也影响 CLI 筛选、PoC 管理和后续归档。

### `info` 字段字典

| 字段 | 是否常用 | 作用 | 说明 |
| --- | --- | --- | --- |
| `name` | 必需 | PoC 展示名称 | 建议可读、能体现漏洞点 |
| `author` | 必需 | 作者 | 支持后续归属和筛选 |
| `severity` | 必需 | 严重级别 | 影响 `-S` 等筛选 |
| `description` | 常用 | 补充说明 | 简短说明检测目标 |
| `reference` | 常用 | 参考链接 | CVE、公告、官方说明等 |
| `tags` | 常用 | 标签 | 便于检索和批量筛选 |
| `verified` | 可选 | 是否已验证 | 用于标识成熟度 |
| `affected` | 可选 | 影响范围 | 版本、组件范围等 |
| `solutions` | 可选 | 修复建议 | 输出给使用者时更友好 |
| `requires` | 进阶 | 指纹门控条件 | 只在特定应用/中间件上运行 |
| `requires-mode` | 进阶 | requires 匹配模式 | 控制门控逻辑 |
| `classification` | 进阶 | CVE / CWE / CVSS 信息 | 做标准化归档时有用 |
| `created` | 可选 | 创建时间 | 便于维护和回溯 |

`requires` 在源码里兼容多种写法：

- 数组写法
- 逗号分隔字符串写法
- `requires-mode` / `requiresMode` / `requires_mode`

最终都会被规范化。

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

适合放在 `set` 里的内容通常有：

- 随机字符串
- 登录用户名、密码
- 复用 token
- 反连域名
- 多条规则都要用的公共片段

示例：

```yaml
set:
  username: admin
  password: admin
  randstr: randomLowercase(8)
```

## `rules`

`rules` 是 PoC 的主体。可以把它理解为“若干可命名的探测步骤”。

### 单条规则的字段字典

| 字段 | 是否常用 | 作用 | 说明 |
| --- | --- | --- | --- |
| `request` | 必需 | 发起请求 | HTTP / TCP / UDP / SSL / raw / go 等 |
| `expression` | 常用 | 单条表达式判断 | 最常见写法 |
| `expressions` | 进阶 | 多条表达式列表 | 某些场景下更方便拆开写 |
| `output` | 常用 | 提取变量供后续规则使用 | 规则间传值的常用方式 |
| `extractors` | 常用 | 结构化提取内容 | 另一种提取风格 |
| `brute` | 进阶 | 爆破 / 笛卡尔组合 | 枚举多组输入时使用 |
| `stop_if_match` | 可选 | 当前规则命中后停止 | 用于提早结束 |
| `stop_if_mismatch` | 可选 | 当前规则不命中后停止 | 用于快速剪枝 |
| `before_sleep` | 可选 | 规则执行前延迟 | 需要等待状态变化时 |

### `request`

`request` 的写法取决于你在验证什么协议。

### HTTP 请求字段字典

| 字段 | 是否常用 | 作用 | 说明 |
| --- | --- | --- | --- |
| `method` | 必需 | HTTP 方法 | 如 `GET`、`POST` |
| `path` | 必需 | 请求路径 | 可带变量 |
| `headers` | 常用 | 请求头 | YAML map |
| `body` | 常用 | 请求体 | 常见于 JSON / form |
| `follow_redirects` | 可选 | 是否跟随跳转 | 默认按引擎行为 |
| `raw` | 进阶 | 原始 HTTP 请求 | 适合要精确控制报文时 |

### 网络类请求字段字典

当 `request.type` 为 `tcp` / `udp` / `ssl` / `go` 等非默认 HTTP 类型时，还会用到：

| 字段 | 是否常用 | 作用 | 说明 |
| --- | --- | --- | --- |
| `type` | 必需 | 请求类型 | `http` / `tcp` / `udp` / `ssl` / `go` |
| `host` | 常用 | 主机名 | 网络协议更常见 |
| `port` | 常用 | 端口 | 可选，低于 `host:port` 显式端口优先级 |
| `data` | 常用 | 发送内容 | TCP / UDP 常见 |
| `data-type` | 可选 | 数据类型 | 控制发送格式 |
| `read-size` | 可选 | 读取长度 | 网络协议常见 |
| `read-timeout` | 可选 | 读取超时 | 网络协议常见 |
| `steps` | 进阶 | 多步读写 | TCP / SSL 对话式协议时有用 |

### `steps` 什么时候用

如果你面对的是“一发一收”之外的协议交互，例如：

- 先读 banner
- 再写入 payload
- 再读响应

这时就更适合写成 `steps`，而不是只写一个简单 `data`。

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

这部分最常见的使用方式其实只有三类：

1. 判断状态码、头、正文中是否出现某个特征
2. 用正则提取再继续判断
3. 把多条条件组合成更稳定的命中逻辑

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

常见模式：

- `r0()`：只有一条规则
- `login() && probe()`：先完成前置动作，再做验证
- `fingerprint() && exploit() && verify()`：多阶段验证

经验上，顶层 `expression` 最好表达“最终结论”，而不是把所有细节都塞进单条规则。

## `output` 与 `extractors`

`afrog` 支持从响应中提取变量，供后续规则继续使用。

### 什么时候用 `output`

如果你只是想把前一条规则里拿到的值传给下一条规则，`output` 往往是最直观的写法。

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

## `classification`

如果你希望 PoC 在归档、资产管理或标准化展示上更完整，可以补充 `classification`：

| 字段 | 作用 |
| --- | --- |
| `cvss-metrics` | CVSS 向量 |
| `cvss-score` | CVSS 分值 |
| `cve-id` | CVE 编号 |
| `cwe-id` | CWE 编号 |

示例：

```yaml
info:
  name: Example CVE
  author: your-name
  severity: high
  classification:
    cve-id: CVE-2024-0001
    cwe-id: CWE-79
    cvss-score: 8.8
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
```

## 写 PoC 时最常查的 3 组问题

### 我到底该先看哪一页

- 想先跑通第一条：看 [PoC 编写快速开始](./quickstart.md)
- 想确认字段怎么写：看本页
- 想确认函数怎么用：看 [内置函数参考](./helper-functions.md)
- 想处理特殊场景：看 `requires / brute / OOB / Raw HTTP / TCP`

### 我该优先用哪些字段

对大多数 HTTP PoC，优先把下面这些写对就够了：

- `id`
- `info.name`
- `info.author`
- `info.severity`
- `rules.*.request.method`
- `rules.*.request.path`
- `rules.*.expression`
- 顶层 `expression`

### 哪些字段是进阶能力

这些通常不是“第一条 PoC 必需”，但在复杂场景里很有价值：

- `requires`
- `brute`
- `output`
- `extractors`
- `payloads`
- `raw`
- `steps`
- `classification`

## 相关文档

- [PoC 编写快速开始](./quickstart.md)
- [内置函数参考](./helper-functions.md)
- [requires 指纹门控](./requires.md)
- [brute 机制](./brute.md)
- [OOB 带外检测](./oob.md)
- [Raw HTTP](./raw-http.md)
- [TCP / SSL](./tcp.md)
