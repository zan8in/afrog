---
title: TCP / SSL
slug: /docs/poc/tcp
lang: zh
summary: 介绍 afrog 在 TCP 和 SSL 场景下的多步会话写法与变量保存方式。
status: draft
source: docs/TCP/tcp-ssl-multi-step-session.md, docs/afrog-poc-guide.md
last_reviewed: 2026-09-15
---

`afrog` 不只支持 HTTP PoC，也支持 `tcp` 和 `ssl` 类型的网络协议检测。对于需要“先读 banner，再写命令，再读响应”的服务，推荐使用 `steps`。

## 什么时候用 TCP / SSL

适合场景：

- POP3 / IMAP / SMTP / FTP 这类先发 banner 的协议
- 数据库或中间件的协议识别
- 需要在同一连接内连续读写多次的服务

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

## 使用建议

1. 服务器先发 banner 的协议，第一步通常先 `read`
2. 需要多行结尾符时，优先用 `read-until`
3. 用 `save-as` 保存关键中间结果，便于后续表达式判断
4. 如果要支持 TLS 端口，通常额外再写一个 `type: ssl` 的规则即可

## 相关文档

- [PoC 语法参考](./syntax.md)
- [Raw HTTP](./raw-http.md)
