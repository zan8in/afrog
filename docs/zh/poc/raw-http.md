---
title: Raw HTTP
slug: /docs/poc/raw-http
lang: zh
summary: 介绍 afrog PoC 中原始 HTTP 报文的适用场景和推荐写法。
status: published
source: docs/afrog-poc-guide.md
last_reviewed: 2026-09-16
---

`Raw HTTP` 适用于那些用普通 `method/path/headers/body` 很难准确表达的请求，例如：

- 特殊头顺序
- 协议升级
- 复杂原始报文
- 想更接近真实请求样貌的场景

## 什么时候考虑用 Raw HTTP

优先顺序建议是：

1. 先尝试普通结构化写法
2. 确实表达不了时，再切到 Raw HTTP

因为普通写法更容易维护、复用和阅读。

## 基本写法

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

## 适合的典型场景

### WebSocket / Upgrade

例如需要精确保留升级相关头时，Raw HTTP 会更直接。

### 特殊协议交互前的 HTTP 探测

有些场景对头顺序、空行、特殊报文格式比较敏感，也更适合 Raw 写法。

## 使用建议

1. 只在结构化请求不够用时再上 Raw HTTP
2. 仍然可以配合变量，例如 `{{Hostname}}`
3. `expression` 的写法与普通 HTTP 规则一致
4. 对响应判断时，可根据场景选 `response.raw_header`、`response.body` 或 `response_text`

## 常见误区

### Raw HTTP 不是“更高级的默认写法”

它只是为少数复杂场景准备的表达方式，不建议把所有 PoC 都写成 Raw。

### 只写 raw，不代表不用做响应判断

真正决定 PoC 是否命中的，仍然是 `expression`。

## 相关文档

- [PoC 语法参考](./syntax.md)
- [PoC 编写快速开始](./quickstart.md)
