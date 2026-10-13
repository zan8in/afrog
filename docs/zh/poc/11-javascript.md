<!--
title: JavaScript PoC
slug: /docs/poc/javascript
lang: zh
summary: afrog javascript 类型 PoC 参考，用 JS 脚本完成网络交互，再用 CEL 表达式与提取器完成判断。
status: published
source: new
last_reviewed: 2026-10-11
-->

`afrog` 除了声明式的 `tcp` / `ssl` 多步交互，还支持 `javascript` 类型的 PoC：当协议交互没法用固定 `read` / `write` 序列表达时，可以直接写一段 JS 脚本来完成，判断逻辑仍然复用 afrog 的 CEL `expression` 与 `extractors`。

> **注意：`javascript` 类型默认关闭。** 由于它会执行 PoC 文件中的脚本代码，afrog 默认不加载 javascript PoC，启动时会提示「检测到 javascript PoC（已跳过）」。需要显式使用 `-enable-js-poc` 开启；开启前请确认 PoC 来源可信。

这页适合解决四类问题：

- 我该用 `tcp` / `steps`，还是 `javascript`
- `code`、`args`、`pre-condition` 分别怎么写
- `require` 能拿到哪些模块、内置函数有哪些
- 脚本结果怎么进入 `expression` 和 `extractors`

## 什么时候需要 javascript

优先顺序建议是：

1. HTTP 请求能表达：用默认 HTTP 规则
2. 协议是固定的一发一收或多步读写：用 `tcp` / `ssl` + `steps`
3. 交互需要分支、循环、协议解析等逻辑：再用 `javascript`

`javascript` 的价值在于「可编程」。例如读取 banner 后按版本分支、对响应做二次解析、按条件决定下一步发什么，这些用声明式 `steps` 表达会很别扭。

## 基本结构

```yaml
id: js-demo-ssh-banner

info:
  name: SSH Banner (JavaScript PoC Demo)
  author: afrog
  severity: info
  tags: js,demo,ssh

rules:
  detect:
    request:
      type: javascript
      pre-condition: |
        isPortOpen(Host, Port)
      code: |
        var m = require("afrog/ssh");
        var c = m.SSHClient();
        var info = c.ConnectSSHInfoMode(Host, Port);
        Export(info.ServerID.Raw);
      args:
        Host: "{{Host}}"
        Port: "{{Port}}"
    expression: response_text.contains("SSH-2.0-")

expression: detect()
```

要点：

- `request.type` 固定写 `javascript`
- `code` 是 JS 脚本主体
- `args` 是脚本入参，渲染后作为同名全局变量注入脚本
- `pre-condition` 可选，求值为真才执行 `code`
- 判断仍然写在 `expression` / `extractors` 里，用 CEL

## `request` 字段速查

| 字段 | 是否常用 | 作用 |
| --- | --- | --- |
| `type` | 必需 | 固定为 `javascript` |
| `code` | 必需 | JS 脚本内容 |
| `args` | 常用 | 脚本入参，渲染后注入为全局变量 |
| `pre-condition` | 可选 | 前置表达式，为真才执行 `code` |

### `code`

`code` 就是普通的一段 JS。afrog 为每次执行创建一个独立的 JS 运行时，脚本里可以直接使用 `args` 注入的变量。

### `args`

`args` 的值支持变量渲染，因此可以直接使用 afrog 注入的网络目标变量：

- `{{Host}}`：目标主机名
- `{{Port}}`：目标端口
- `{{Hostname}}`：`host:port`

如果你的目标是 `1.2.3.4:2222`，`args` 里写 `Host: "{{Host}}"`、`Port: "{{Port}}"` 就能直接拿到 `1.2.3.4` 和 `2222`。

### `pre-condition`

`pre-condition` 是一段 JS 表达式，取最后一个表达式的布尔值判断：

```yaml
pre-condition: |
  isPortOpen(Host, Port)
```

只有为真才会执行 `code`，适合做端口存活探测这类前置剪枝。

## 内置函数

脚本运行时默认提供以下全局函数：

| 函数 | 作用 |
| --- | --- |
| `Export(value)` | 把值转成字符串追加到脚本输出，作为 `response` 内容 |
| `isPortOpen(host, port, [timeoutSec])` | 判断 TCP 端口是否开放，超时缺省 5 秒 |
| `to_json(value)` | 把对象序列化为 JSON 字符串 |
| `ToString(...)` | 把参数拼接为字符串 |
| `log(value)` | 调试输出 |

`Export` 决定了结果如何回传：它写入的内容会成为后续 CEL 里的 `response_text` / `response.raw`。

## `require` 模块

`require` 目前提供两个 afrog 原生模块，命名空间为 `afrog/`：

| 模块 | 用途 |
| --- | --- |
| `afrog/ssh` | SSH 交互（banner、认证、执行命令） |
| `afrog/net` | 任意 TCP / TLS 读写 |

### `afrog/ssh`

```javascript
var m = require("afrog/ssh");
var c = m.SSHClient();
c.SetTimeout(10);

// 只做 SSH 版本交换，读取服务端标识串，不需要认证
var info = c.ConnectSSHInfoMode(Host, Port);
Export(info.ServerID.Raw);

// 需要认证时
// var ok = c.Connect(Host, Port, "root", "password");
// var out = c.Run("id");
// c.Close();
```

`ConnectSSHInfoMode` 返回对象的 `ServerID.Raw` 形如 `SSH-2.0-Serv-U_15.2.3.742`。

### `afrog/net`

```javascript
var net = require("afrog/net");
var c = net.TCPClient();
// var c = net.TLSClient(); // TLS 场景
c.SetTimeout(5);
c.SetReadSize(4096);
c.Connect(Host, Port);

c.Send("CAPA\r\n");
var resp = c.RecvUntil("\r\n");   // 返回内容包含分隔符，与 tcp read-until 一致
c.Close();
Export(resp);
```

`afrog/net` 客户端方法：

| 方法 | 作用 |
| --- | --- |
| `Connect(host, port)` | 建立连接，返回布尔值 |
| `Send(data)` | 发送字符串 |
| `SendHex(hexStr)` | 发送十六进制表示的数据 |
| `Recv([size])` | 读取一次响应 |
| `RecvUntil(delim, [size])` | 读到分隔符为止（含分隔符） |
| `SetTimeout(sec)` / `SetReadSize(n)` | 设置超时与读取上限 |
| `Close()` | 关闭连接 |

## 结果如何进入 CEL

脚本通过 `Export` 写出的内容会同时写入两个变量：

- `response_text`：字符串形式
- `response`：结构化响应对象（`response.raw` 为字节）

因此 `expression` / `extractors` 的写法和其它协议完全一致：

```yaml
rules:
  detect:
    request:
      type: javascript
      code: |
        var m = require("afrog/ssh");
        var c = m.SSHClient();
        var info = c.ConnectSSHInfoMode(Host, Port);
        Export(info.ServerID.Raw);
      args:
        Host: "{{Host}}"
        Port: "{{Port}}"
    expression: response_text.contains("SSH-2.0-Serv-U")

extractors:
  - type: regex
    extractor:
      version: '"SSH-2.0-Serv-U_(?P<version>[0-9.]+)".submatch(response_text)["version"]'

expression: detect() && versionCompare(version, "<", "15.2.3.742")
```

提取器与函数的具体写法见 [内置函数参考](./03-helper-functions.md) 与 [PoC 语法参考](./02-syntax.md)。

## 完整示例：SSH 版本检测

对应 CVE-2021-35211（Serv-U）这类「读 banner + 版本比较」的场景：

```yaml
id: js-servu-ssh-version

info:
  name: SolarWinds Serv-U SSH - Version Detect
  author: your-name
  severity: critical
  tags: js,ssh,servu

rules:
  detect:
    request:
      type: javascript
      pre-condition: |
        isPortOpen(Host, Port)
      code: |
        var m = require("afrog/ssh");
        var c = m.SSHClient();
        var info = c.ConnectSSHInfoMode(Host, Port);
        Export(info.ServerID.Raw);
      args:
        Host: "{{Host}}"
        Port: "{{Port}}"
    expression: response_text.contains("SSH-2.0-Serv-U")

extractors:
  - type: regex
    extractor:
      version: '"SSH-2.0-Serv-U_(?P<version>[0-9.]+)".submatch(response_text)["version"]'

expression: detect() && versionCompare(version, "<", "15.2.3.742")
```

## 边界与常见误区

### 把判断逻辑也写进 JS

`Export` 只负责回传数据，命中判断应放在 `expression` / `extractors`。这样结果可读、可复现，也便于复用 afrog 的正则与版本比较函数。

### 忽略返回值直接当输出

没有调用 `Export` 时，afrog 会用脚本最后一个表达式的值作为输出。为了可读性，建议显式 `Export`。

### 用 `javascript` 做纯 HTTP 检测

纯 HTTP 场景用默认 HTTP 规则更简单，也更快。

### 忘了设置超时

`isPortOpen` 与各模块方法都有默认超时；脚本整体执行上限由 `-js-script-timeout` 控制（默认 60 秒，设为 0 表示不设脚本级上限，此时只跟随任务级超时）。遇到慢目标时，优先调小模块的 `SetTimeout`，或降低 `-js-script-timeout`。

扫描停止或任务超时时，正在执行的脚本会被立即中断，不会一直等到上限。

### 二进制响应

`Export` 与 `Recv` / `RecvUntil` 以字符串传递，文本类协议没问题；纯二进制协议建议只取需要的片段再 `Export`。

## 一句话经验

`javascript` 类型解决的是「协议交互需要编程」这一件事，结果判断仍然交给 afrog 的 CEL，两条线各司其职。

> **← 上一篇：** [PoC 贡献者荣誉墙](./10-contributors.md) ｜ **本手册首页：** [PoC 编写快速开始](./01-quickstart.md) ｜ **文档首页 →：** [afrog 文档](../index.md)
