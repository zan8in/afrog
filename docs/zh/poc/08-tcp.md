---
title: TCP / SSL
slug: /docs/poc/tcp
lang: zh
summary: afrog TCP / SSL 参考，帮助你判断什么时候该用多步会话，以及 read、write、save-as 怎么配合。
status: published
source: docs/TCP/tcp-ssl-multi-step-session.md, docs/afrog-poc-guide.md
last_reviewed: 2026-09-16
---

`afrog` 不只支持 HTTP PoC，也支持 `tcp` 和 `ssl` 类型的网络协议检测。

这页最适合解决四类问题：

- 我这个协议场景该不该用 TCP / SSL PoC
- 什么时候只写一次 `data` 就够，什么时候必须用 `steps`
- `read` / `write` / `save-as` 该怎么配合
- 读出来的结果到底该存成 bytes、string 还是默认结构

对于需要“先读 banner，再写命令，再读响应”的服务，`steps` 通常就是正确的路径。

## 什么时候用 TCP / SSL

适合场景：

- POP3 / IMAP / SMTP / FTP 这类先发 banner 的协议
- 数据库或中间件的协议识别
- 需要在同一连接内连续读写多次的服务

不太需要 TCP / SSL 页的场景：

- 纯 HTTP 检测
- 单个结构化 HTTP 请求就能验证的问题
- 不涉及连接内多步交互的普通 Web PoC

## 基本结构

最简单的 TCP 检测示例：

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

如果是 TLS 场景，则将 `type` 换成 `ssl`。

## 先判断什么时候该用 `steps`

一发一收就能完成的场景，通常可以先写：

- `type`
- `host`
- `port`
- `data`

但只要出现下面这些情况，就更适合改成 `steps`：

- 连接建立后服务端先发 banner
- 需要连续多次读写
- 需要按阶段保存中间结果
- 需要处理多行响应或分隔符结束的响应

## 为什么需要 `steps`

以前 `tcp/ssl` 规则更适合“发一次、读一次”的简单交互。但很多真实协议需要：

1. 建连后先读服务端 banner
2. 再发命令
3. 再读取后续多行响应

这时就应该使用 `request.steps`。

## `steps` 的基本写法

```yaml
request:
  type: tcp
  host: "{{host}}"
  steps:
    - read:
        read-size: 4096
        read-timeout: 3
        read-until: "\r\n"
        read-type: bytes
        save-as: banner
    - write:
        data: "CAPA\r\n"
    - read:
        read-size: 8192
        read-timeout: 3
        read-until: "\r\n.\r\n"
        read-type: bytes
        save-as: capa
expression: banner.bcontains(b"+OK") && capa.bcontains(b"+OK")
```

### 这段流程在做什么

1. 先读欢迎 banner，保存为 `banner`
2. 再写入 `CAPA`
3. 再把多行能力结果读出来，保存为 `capa`
4. 最后在 `expression` 里判断两段内容

## 字段速查

| 字段 | 作用 | 常见写法 |
| --- | --- | --- |
| `request.type` | 协议类型 | `tcp` / `ssl` |
| `request.host` | 目标主机 | `"{{Hostname}}"` |
| `request.port` | 目标端口 | 如 `3306` |
| `request.data` | 简单单次发送内容 | 适合一发一收 |
| `request.steps` | 多步读写流程 | 适合会话型协议 |
| `read-size` | 本次最大读取字节数 | 如 `4096` |
| `read-timeout` | 本次读取超时 | 如 `3` |
| `read-until` | 分隔符结束条件 | 如 `"\r\n"` |
| `read-type` | 保存类型 | `bytes` / `string` |
| `save-as` | 保存到变量名 | 如 `banner` |

## `read` 常用字段

- `read-size`：本次最多读取多少字节
- `read-timeout`：本次读取最长等待时间
- `read-until`：读到指定分隔符时结束
- `read-type`：保存成什么类型
- `save-as`：把读取结果存到哪个变量

## `write` 常用字段

- `data`：发送内容
- `data-type`：可选，常见默认为字符串；特殊场景可用十六进制等形式

## `read-type`

这是写多步协议时最关键的字段之一。

### `bytes`

保存结果为字节流，适合：

- `bcontains`
- `ibcontains`
- 其它 bytes 相关匹配

### `string`

保存结果为字符串，适合：

- `icontains`
- `toLower`
- 其它字符串处理

### 不写 `read-type`

默认保存为结构化响应对象，适合你想读取更多结构字段的场景。

## 怎么选 `read-type`

最简单的经验：

- 想做 bytes 匹配：选 `bytes`
- 想做字符串判断：选 `string`
- 想保留更完整结构：先不写 `read-type`

## `read-until` 的边界

- 如果在 `read-size` 范围内找到了分隔符，会返回到分隔符结束的位置
- 如果没找到分隔符，则会在读满上限或超时后返回已读内容
- 常见转义写法可直接使用，例如：
  - `"\r\n"`
  - `"\r\n.\r\n"`

## POP3 示例为什么典型

POP3 常见流程就是：

1. 服务端先发 `+OK` banner
2. 客户端发 `CAPA`
3. 服务端返回多行能力列表

如果只写一次 `data`，容易遇到：

- banner 没读干净
- 多行响应被截断
- 状态判断不稳定

`steps` 就是为这种协议交互准备的。

## 最小工作流

写 TCP / SSL PoC 时，建议按这个顺序：

1. 先判断是单次交互还是多步会话
2. 单次交互先尝试 `data`
3. 多步会话就切到 `steps`
4. 用 `save-as` 把关键阶段结果保存下来
5. 在 `expression` 里只保留最稳定的判断条件

## 使用建议

1. 服务器先发 banner 的协议，第一步通常先 `read`
2. 需要多行结尾符时，优先用 `read-until`
3. 用 `save-as` 保存关键中间结果，便于后续表达式判断
4. 如果要支持 TLS 端口，通常额外再写一个 `type: ssl` 的规则即可
5. 先把读写轮次压到最少，再逐步补复杂交互

## 常见误区

### 只因为不是 HTTP，就一上来写很多 `steps`

如果协议本身一发一收就够，直接 `data` 往往更简单。

### 没有 `save-as`，后面却想复用中间结果

多步协议里，中间结果经常就是后续判断的依据，关键数据最好及时保存。

### `read-until` 过短或不准确

分隔符写错时，最容易出现响应截断或误判。

## 一句话经验

TCP / SSL PoC 的难点通常不在“怎么发包”，而在“怎么把会话拆成几步，并把关键结果留住”。

> **← 上一篇：** [Raw HTTP](./07-raw-http.md) ｜ **本手册首页：** [PoC 编写快速开始](./01-quickstart.md) ｜ **下一篇 →：** [PoC 贡献者荣誉墙](./09-contributors.md)
