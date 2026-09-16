---
title: PoC 编写快速开始
slug: /docs/poc/quickstart
lang: zh
summary: 帮助 PoC 作者写出第一条可运行的 afrog PoC。
status: draft
source: docs/afrog-poc-guide.md, docs/tutorial/rumen-dao-rutu/04-poc-basics.md
last_reviewed: 2026-09-15
---

这一页的目标很简单：先写出一条能跑起来的 `afrog` PoC。

## 一条最小可运行 PoC

```yaml
id: demo-basic

info:
  name: 基础结构示例
  author: your-name
  severity: info

rules:
  r0:
    request:
      method: GET
      path: /status
    expression: response.status == 200

expression: r0()
```

这条 PoC 的结构已经包含了最核心的几个部分：

- `id`：PoC 唯一标识
- `info`：基础信息
- `rules`：具体请求与判断逻辑
- 顶层 `expression`：定义最终命中条件

## 最小结构怎么理解

### `id`

用于唯一标识一个 PoC，建议稳定、可读、便于检索。

### `info`

最常用的必填字段包括：

- `name`
- `author`
- `severity`

### `rules`

每个规则由两部分组成：

- `request`：发什么请求
- `expression`：如何判断这一条规则成功

### 顶层 `expression`

用于组织多个规则的关系。最简单的写法就是：

```yaml
expression: r0()
```

如果有多个规则，也可以写成：

```yaml
expression: step1() && step2()
```

## 一个稍微完整一点的例子

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

这个例子多了几件常见事情：

- 在 `set` 中定义变量
- 在请求头和请求体中引用变量
- 在表达式中检查状态码和响应体

## 本地验证

编写 PoC 后，建议先用单目标和单 PoC 做最小验证，例如：

```bash
afrog -t https://example.com -P ./mypocs -debug
```

如果只是想先检查语法是否正确，可以优先使用 `-validate`。

## 常见错误

### YAML 缩进不正确

`afrog` PoC 基于 YAML，缩进错误会直接导致加载失败。建议统一使用空格缩进。

### 把字节匹配和文本匹配混用

常见对象：

- `response.body`：字节流，常配合 `bcontains`、`bmatches`、`bsubmatch`
- `response_text`：文本，常配合 `icontains`、`rmatches`、`submatch`

涉及中文页面、编码不一致或正则提取时，优先考虑 `response_text`。

### 顶层 `expression` 漏写

即使 `rules` 中已经有规则，也仍然需要顶层 `expression` 来定义最终判定逻辑。

## 下一步

写出第一条 PoC 后，建议继续阅读：

- [PoC 语法参考](./syntax.md)
- [内置函数参考](./helper-functions.md)
- [requires 指纹门控](./requires.md)
- [brute 机制](./brute.md)
- [OOB 带外检测](./oob.md)
- [TCP / SSL](./tcp.md)
