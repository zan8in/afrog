<!--
title: PoC 编写快速开始
slug: /docs/poc/quickstart
lang: zh
summary: 用最短路径写出第一条可运行的 afrog PoC，并知道下一步该查哪一页。
status: published
source: docs/afrog-poc-guide.md, docs/tutorial/rumen-dao-rutu/04-poc-basics.md
last_reviewed: 2026-09-16
-->

这一页的目标很简单：先写出一条能跑起来的 `afrog` PoC。

它不是完整参考手册，而是给第一次写 PoC 的作者一条最短路径。

如果你已经知道：

- 字段该怎么写
- 函数该怎么选
- `requires / brute / OOB / TCP` 分别解决什么问题

那你更适合直接去对应专题页；如果你现在只是想“先写出第一条能跑的”，就按这页往下走。

## 先判断你现在要写哪种 PoC

大多数新作者，其实只需要先在下面三种里选一种起步：

| 我现在要做什么 | 先从哪种 PoC 开始 |
| --- | --- |
| 验证一个普通 Web 路径或接口 | 普通 HTTP PoC |
| 验证某个登录、口令、枚举场景 | HTTP PoC + 后续再看 `requires / brute` |
| 验证非 HTTP 协议或多步会话 | 先看 `TCP / SSL` |

如果你还不确定，就从**最普通的 HTTP PoC**开始，因为它最容易写、最容易调、也最适合作为模板。

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

## 第一次写 PoC 的最短工作流

建议直接按这个顺序做：

1. 先找一个最稳定、最容易验证的目标路径
2. 先写一条只有一个 `rules` 的 PoC
3. 先只判断一个最可靠的响应特征
4. 跑通以后，再补变量、更多规则或专题能力

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

## 什么时候该停在“最小版本”

第一次写 PoC 时，很容易一上来就想把这些都塞进去：

- 多规则
- OOB
- brute
- requires
- 动态提取

更稳妥的方式是：

先把“最小能命中”的版本写通，再逐步升级。

## 本地验证

编写 PoC 后，建议先用单目标和单 PoC 做最小验证，例如：

```bash
afrog -t https://example.com -P ./mypocs -debug
```

如果只是想先检查语法是否正确，可以优先使用 `-validate`。

## 第一次调试时最有用的 3 个习惯

1. 单目标验证，不要一开始扫一批资产
2. 单 PoC 验证，不要一开始把目录全塞进去
3. 命中条件先简单，确认跑通后再提高稳定性

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

### 第一次就选了过难的目标

如果一开始就拿复杂登录流、异步触发、带编码差异的页面来练手，调试成本会明显更高。第一次更适合挑简单、可重复、稳定的目标。

## 本书目录

- [PoC 语法参考](./02-syntax.md)
- [内置函数参考](./03-helper-functions.md)
- [requires 指纹门控](./04-requires.md)
- [brute 机制](./05-brute.md)
- [OOB 带外检测](./06-oob.md)
- [Raw HTTP](./07-raw-http.md)
- [TCP / SSL](./08-tcp.md)
- [按漏洞类型的编写指南](./09-category-guide.md)
- [PoC 贡献者荣誉墙](./10-contributors.md)

> **← 文档首页：** [afrog 文档](../index.md) ｜ **下一篇 →：** [PoC 语法参考](./02-syntax.md)
