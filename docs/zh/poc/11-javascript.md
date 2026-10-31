<!--
title: JavaScript PoC
slug: /docs/poc/javascript
lang: zh
summary: afrog javascript 类型 PoC 参考，用 JS 脚本完成网络交互，再用 CEL 表达式与提取器完成判断。
status: published
source: new
last_reviewed: 2026-10-13
-->

`afrog` 除了声明式的 `tcp` / `ssl` 多步交互，还支持 `javascript` 类型的 PoC：当协议交互没法用固定 `read` / `write` 序列表达时，可以直接写一段 JS 脚本来完成，判断逻辑仍然复用 afrog 的 CEL `expression` 与 `extractors`。

> **`javascript` 类型默认启用。** 它会执行 PoC 文件中的脚本代码（脚本只能发起网络请求，无法读写文件或执行命令）。敏感场景可用 `-enable-js-poc=false` 关闭，关闭时会提示「检测到 javascript PoC（已跳过）」。此外还提供可选的 [信任与签名](#信任与签名) 机制，用于校验脚本来源与完整性。

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
| `ExportAs(key, value)` | 把值以 `key` 为名写入变量表，供 `expression` / `extractors` 直接引用 |
| `isPortOpen(host, port, [timeoutSec])` | 判断 TCP 端口是否开放，超时缺省 5 秒 |
| `to_json(value)` | 把对象序列化为 JSON 字符串 |
| `ToString(...)` | 把参数拼接为字符串 |
| `log(value)` | 调试输出 |

`Export` 决定了结果如何回传：它写入的内容会成为后续 CEL 里的 `response_text` / `response.raw`。

`ExportAs` 用于回传**结构化、可命名的结果**：`ExportAs("banner", info.ServerID.Raw)` 之后，规则里可以直接写 `expression: banner.contains("SSH-2.0-")`。`key` 必须是合法标识符（字母或下划线开头，后接字母、数字、下划线），且建议写成字符串字面量：afrog 会扫描脚本预声明所有 `ExportAs` 键，未执行到的分支对应变量为空串，`expression` 因此始终能编译。当一个脚本要产出多个字段，或需要在提取器里按名字引用某个值时，用它比拼接字符串清晰得多。

## `require` 模块

`require` 目前提供两个 afrog 原生模块，命名空间为 `afrog/`：

| 模块 | 用途 |
| --- | --- |
| `afrog/ssh` | SSH 交互（banner、认证、执行命令） |
| `afrog/net` | 任意 TCP / TLS 读写 |
| `afrog/bytes` | 二进制缓冲区：拼装报文后再发送 |
| `afrog/structs` | 二进制打包 / 解包（struct 风格格式） |
| `afrog/mysql` | MySQL 握手 / 登录（版本探测、弱口令） |

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

`ConnectSSHInfoMode` 返回对象的 `ServerID.Raw` 形如 `SSH-2.0-Serv-U_15.2.3.742`。失败时 `ServerID.Raw` / `Banner` 为空串，原因见 `c.LastError()`（模块方法不抛异常，见下文 `afrog/net` 说明）。

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
| `Connect(host, port)` | 建立连接，返回 `true` / `false` |
| `Send(data)` | 发送字符串，返回写入字节数 |
| `SendHex(hexStr)` | 发送十六进制表示的数据，返回写入字节数 |
| `Recv([size])` | 读取一次响应，返回字符串 |
| `RecvUntil(delim, [size])` | 读到分隔符为止（含分隔符），返回字符串 |
| `SetTimeout(sec)` / `SetReadSize(n)` | 设置超时与读取上限 |
| `Close()` | 关闭连接 |
| `LastError()` | 最近一次方法的错误描述；无错误时为空串 |

> **模块方法不抛异常。** 连接失败、读写超时这类预期内错误不会抛异常，方法返回零值（`false` / `0` / `""`），原因记录在 `LastError()`。因此不需要用 `try/catch` 包裹调用，直接判断返回值即可；只有用错 API（例如 `ExportAs` 的 key 非法）才会抛异常。

超时口径与 `tcp` / `ssl` PoC 保持一致：模块默认取「afrog 全局 `-timeout`」与基准值中的较小者（连接 3 秒、读 6 秒、写 3 秒），也可用 `SetTimeout(sec)` 覆盖。脚本结束时若仍有未关闭的连接，afrog 会兜底关闭，不会因为忘记 `c.Close()` 而泄漏。

### `afrog/bytes`

拼装二进制报文的缓冲区，适合把多段数据拼成一个报文再发送：

```javascript
var bytes = require("afrog/bytes");
var b = bytes.NewBuffer();
b.WriteString("GET /");
b.WriteHex("0d0a");
b.Pack(">H", 8009);        // 按 struct 格式追加
Export(b.Hex());
// c.Send(b.String());
```

| 方法 | 作用 |
| --- | --- |
| `NewBuffer([初始内容])` | 创建缓冲区，可传入字符串 / 字节数组 |
| `Write(...)` | 追加字符串 / 字节数组 |
| `WriteString(s)` / `WriteHex(hexStr)` | 追加字符串 / 十六进制数据 |
| `WriteUint8(n)` / `WriteUint16(n)` / `WriteUint32(n)` / `WriteUint64(n)` | 大端追加整数 |
| `Pack(format, ...values)` | 按 struct 格式打包并追加 |
| `String()` / `Bytes()` / `Hex()` / `Len()` / `Reset()` | 取结果或重置 |

### `afrog/structs`

二进制打包 / 解包，格式是 Python struct 风格的子集：

```javascript
var structs = require("afrog/structs");
var payload = structs.Pack(">HI", 0x1234, 0x100);   // 返回原始字节串，可直接 Send
var vals = structs.Unpack(">HI", response);          // 返回值数组
var size = structs.CalcSize(">HI");                  // 6
```

- 字节序：`<` 小端，`>` / `!` 大端（缺省大端）
- 类型：`b` / `B` int8/uint8，`h` / `H` int16/uint16，`i` / `I` int32/uint32，`q` / `Q` int64/uint64，`s` 定长字符串（如 `4s`），`x` 填充字节
- 支持重复计数，如 `2H`、`4s`
- 值个数与格式不匹配、数据长度不足会抛异常（属于用错 API）

### `afrog/mysql`

MySQL 协议交互：读取服务端握手包（**认证前即可拿到版本**），并完成密码认证。

```javascript
var mysql = require("afrog/mysql");
var c = mysql.MySQLClient();
c.SetTimeout(5);
if (c.Connect(Host, Port)) {
  var hs = c.Handshake();          // Version / ThreadID / Charset / Capabilities / AuthPlugin / Salt
  ExportAs("version", hs.Version); // 认证前就能拿到服务端版本
  if (c.Login("root", "root")) {
    var r = c.Query("select version()");
    ExportAs("dbver", r.Rows[0][0]);  // 结果集首行首列
  }
  c.Close();
}
```

| 方法 | 作用 |
| --- | --- |
| `Connect(host, port)` | 建立连接并读取握手包，返回 `true` / `false` |
| `Handshake()` | 返回握手信息对象（`Version`、`ThreadID`、`Charset`、`Capabilities`、`AuthPlugin`、`Salt`） |
| `Login(user, password)` | 完成认证，成功返回 `true` |
| `Query(sql)` | 发送 SQL 并解析响应，返回 `{ Columns, Rows, AffectedRows, LastInsertID, ErrNo, ErrMsg }` |
| `Close()` | 关闭连接 |
| `LastError()` | 最近一次方法的错误描述 |

支持 `mysql_native_password` 与 `caching_sha2_password`，并会跟随服务端的 Auth Switch 请求。`Query` 覆盖文本协议结果集（列名 + 行）与 OK / ERR 响应；服务端报错时 `ErrNo` / `ErrMsg` 会带上错误码与消息。

## 信任与签名

`javascript` PoC 会执行脚本代码，因此 afrog 为它提供了一层可选的签名校验，用来确认「这段代码确实来自它声称的来源，且没有被篡改」。只有携带代码 / 特权能力的 PoC 参与签名，纯声明式的 `http` / `tcp` PoC 不涉及。

### 签名长什么样

签名是一个以注释形式追加在文件**最后一行**的 `# digest:`，不参与 YAML 解析：

```yaml
id: js-demo
# ... 其余内容 ...
expression: r0()
# digest: uvKInOS6sizVvUzrAmHcLYse6gYidD75RZ7VdqeDMo8Wi/i8+fRTkjZtA8gHk38vIcJalQaiAxKOBFj0Py38Bg==
```

算法是 ed25519，签名覆盖的是签名行之前的全部正文。签名行必须是最后一行——如果它后面还有内容，afrog 会直接视为未签名，防止有人在签名之后追加 YAML 绕过校验。

### 默认宽松

默认是**宽松模式**：有签名就验，验不过只告警、不拦截；没有签名也照常运行。这保证了「用户自写 PoC 开箱即用」。需要更严格时可开启严格模式：

```bash
afrog -require-signed-js-poc ...
```

严格模式下，未签名或签名无效的 `javascript` PoC 会被跳过，并在启动时列出被跳过的 PoC 及原因。

### 为自己的 PoC 签名

用内置工具就地签名一个文件或整个目录，密钥首次使用时自动生成：

```bash
afrog -pocsign my-poc.yaml
afrog -pocsign ./my-pocs/
```

输出形如：

```text
signed=3 key=eLNAXRGlIcY4
pubkey=eLNAXRGlIcY4xxx...==
```

`key` 是公钥指纹，`pubkey` 是完整的 base64 公钥。密钥存放位置：

- 私钥：`~/.config/afrog/keys/signing.key`（权限 `0600`）
- 公钥：`~/.config/afrog/keys/verification.pub`

### 谁的公钥受信任

afrog 在验签时会接受以下任一来源的公钥：

1. **官方公钥**：内嵌在二进制中，发布构建时注入（`-ldflags "-X .../pkg/pocsign.officialPublicKeyB64=<...>"`）。开发态的源码树里为空，表示未启用官方验签。
2. **你自己的公钥**：即 `~/.config/afrog/keys/verification.pub`，所以自签的 PoC 天然自验通过。
3. **环境变量 `AFROG_POC_PUBKEY_B64`**：追加一个 base64 公钥，便于 CI 或企业内部分发。

### 官方 PoC 的签名（维护者）

官方 PoC 有两条分发路径，都需要用**同一个官方私钥**签名：

- 随二进制内嵌的 `pocs/afrog-pocs/`：在发布流水线里、构建之前签名；
- 运行期更新下载的 `afrog-pocs.zip`：在打包该 zip 的流水线里签名。

**一次性准备密钥对。** 先用自签工具生成一对，再把它们挪到 CI：

```bash
# 任意签一个文件即可在 ~/.config/afrog/keys/ 下自动生成密钥对
afrog -pocsign any-poc.yaml

# 私钥 -> 存为 CI secret（内容即文件文本，已是 base64）
cat ~/.config/afrog/keys/signing.key
# 公钥 -> 存为 CI secret，或直接用下面的输出
cat ~/.config/afrog/keys/verification.pub
```

> 私钥只保存在 CI secret（`AFROG_POC_SIGNING_KEY_B64`）里，**绝不进仓库**。

**在流水线里签名并构建：**

```bash
# 1) 用官方私钥签名官方 PoC（环境变量会覆盖用户密钥，不会写入用户目录）
AFROG_POC_SIGNING_KEY_B64="$OFFICIAL_KEY" afrog -pocsign pocs/afrog-pocs
#    -> signed=1234 key=<指纹>
#    -> pubkey=<base64 公钥>

# 2) 把上一步输出的 pubkey 注入 -ldflags，让二进制内嵌官方验签公钥
go build -ldflags "-X github.com/zan8in/afrog/v3/pkg/pocsign.officialPublicKeyB64=<base64 公钥>" ./cmd/afrog
```

仓库的 `.goreleaser.yaml` 已把该 `-X` 接到环境变量 `AFROG_POC_PUBKEY_B64`（未设置则注入空串），
`.github/workflows/release.yml` 也已在构建前调用 `-pocsign` 并自动把派生出的公钥导出给 goreleaser——
所以维护者只需要配置好 secret `AFROG_POC_SIGNING_KEY_B64`，其余全自动。

## 结果如何进入 CEL

脚本通过 `Export` 写出的内容会同时写入两个变量：

- `response_text`：字符串形式
- `response`：结构化响应对象（`response.raw` 为字节）

通过 `ExportAs(key, value)` 写出的值会额外以 `key` 为名写入变量表，两种通道可以在同一条规则的 `expression` 里混用：

```yaml
    code: |
      var info = c.ConnectSSHInfoMode(Host, Port);
      ExportAs("banner", info.ServerID.Raw);   // 具名，供下面引用
      Export(info.ServerID.Raw);               // 同时回传为 response_text
    expression: |
      response_text.contains("Serv-U") && banner.contains("SSH-2.0")
```

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

`isPortOpen` 与各模块方法都有默认超时；脚本整体执行上限由 `-js-script-timeout` 控制（默认 180 秒，设为 0 表示不设脚本级上限，此时只跟随任务级超时）。

扫描停止或任务超时时，正在执行的脚本会被立即中断——包括阻塞在 `Connect` / `Recv` 等网络读写上的脚本：afrog 会把任务上下文的取消传递到模块的拨号与读写，连接会立刻被打断，而不是等模块超时。

### 二进制响应

`Export` 与 `Recv` / `RecvUntil` 以字符串传递，文本类协议没问题；纯二进制协议建议只取需要的片段再 `Export`。

## 一句话经验

`javascript` 类型解决的是「协议交互需要编程」这一件事，结果判断仍然交给 afrog 的 CEL，两条线各司其职。

> **← 上一篇：** [PoC 贡献者荣誉墙](./10-contributors.md) ｜ **本手册首页：** [PoC 编写快速开始](./01-quickstart.md) ｜ **文档首页 →：** [afrog 文档](../index.md)
