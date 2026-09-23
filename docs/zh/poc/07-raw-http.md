---
title: Raw HTTP
slug: /docs/poc/raw-http
lang: zh
summary: afrog Raw HTTP 参考，帮助你判断什么时候该放弃结构化请求，转向原始报文写法。
status: published
source: docs/afrog-poc-guide.md
last_reviewed: 2026-09-16
---

`Raw HTTP` 适用于那些用普通 `method/path/headers/body` 很难准确表达的请求。

这页最适合解决三类问题：

- 我到底要不要用 Raw HTTP
- Raw HTTP 最常见的使用场景是什么
- 写成原始报文后，响应判断该怎么接着写

如果结构化写法已经足够表达，就没必要切到 Raw HTTP；只有当你真的需要“尽量按原始报文样貌发出去”时，它才是更合适的工具。

最典型的场景包括：

- 特殊头顺序
- 协议升级
- 复杂原始报文
- 想更接近真实请求样貌的场景

## 什么时候考虑用 Raw HTTP

优先顺序建议是：

1. 先尝试普通结构化写法
2. 确实表达不了时，再切到 Raw HTTP

因为普通写法更容易维护、复用和阅读。

## 先判断什么时候该用

适合切到 Raw HTTP 的场景：

- 需要精确保留某些头顺序
- 需要发 `Upgrade` / `Connection` 这类协议升级请求
- 需要控制空行、原始行格式、特殊报文结构
- 目标对“看起来像真实客户端报文”比较敏感

不一定需要 Raw HTTP 的场景：

- 普通 GET / POST
- 只是多几个 header
- 只是 body 比较长
- 结构化 `request` 已经能清楚表达

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

### 你可以把它理解成什么

切到 Raw HTTP 后，变化的只是“请求怎么写”，**不是判定逻辑怎么写**。

也就是说：

- `request.raw` 负责把报文发出去
- `expression` 仍然负责定义命中条件

## 字段速查

| 项目 | 作用 | 常见写法 |
| --- | --- | --- |
| `request.type` | 显式声明 HTTP 类型 | `http` |
| `request.raw` | 原始 HTTP 报文 | 多行 YAML 文本块 |
| `{{Hostname}}` | 当前目标主机 | Raw 报文里很常用 |
| `response.raw_header` | 原始响应头 | 适合判断 Upgrade 等场景 |
| `response.body` | 原始响应体 bytes | 二进制或精准字节判断 |
| `response_text` | 文本化响应体 | 页面文本、正则提取更顺手 |

## 适合的典型场景

### WebSocket / Upgrade

例如需要精确保留升级相关头时，Raw HTTP 会更直接。

### 特殊协议交互前的 HTTP 探测

有些场景对头顺序、空行、特殊报文格式比较敏感，也更适合 Raw 写法。

### 特殊请求行或特殊 Host 写法

如果目标对请求行、绝对 URL、Host 表达形式有特别要求，Raw HTTP 也通常更直观。

## 最小工作流

写 Raw HTTP 时，建议沿这个顺序：

1. 先确认结构化请求确实表达不了
2. 把原始报文最小化，只保留必要字段
3. 用最稳定的响应特征写 `expression`
4. 再按需加变量和额外头部

## 使用建议

1. 只在结构化请求不够用时再上 Raw HTTP
2. 仍然可以配合变量，例如 `{{Hostname}}`
3. `expression` 的写法与普通 HTTP 规则一致
4. 对响应判断时，可根据场景选 `response.raw_header`、`response.body` 或 `response_text`
5. 初版尽量先跑通最小原始报文，不要一开始就塞很多头

## 常见误区

### Raw HTTP 不是“更高级的默认写法”

它只是为少数复杂场景准备的表达方式，不建议把所有 PoC 都写成 Raw。

### 只写 raw，不代表不用做响应判断

真正决定 PoC 是否命中的，仍然是 `expression`。

### 把 Raw HTTP 当作“更专业”的默认写法

它只是更底层，不代表更适合日常维护。很多普通 HTTP PoC 用结构化写法会更清楚。

## 一句话经验

Raw HTTP 的价值不在于“更复杂”，而在于“更接近你真正想发的报文”。只有当结构化写法失真时，它才值得上场。

> **← 上一篇：** [OOB 带外检测](./06-oob.md) ｜ **本手册首页：** [PoC 编写快速开始](./01-quickstart.md) ｜ **下一篇 →：** [TCP / SSL](./08-tcp.md)
