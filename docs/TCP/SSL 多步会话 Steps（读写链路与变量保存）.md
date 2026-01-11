## TCP/SSL 多步会话 Steps（读写链路与变量保存）
          
**这次新增的功能是什么**
- 以前 `tcp/ssl` 规则只能用 `request.data` 发一次、读一次，拿到的只是一段“单次响应”。
- 现在支持 `request.steps`：在同一条连接里按顺序执行多次 `read` / `write`，并且每次 `read` 的结果可以用 `save-as` 保存成变量，供后续表达式或其他逻辑使用。示例就是你打开的 [pop3-detect.yaml](../pocs/afrog-pocs/fingerprinting/pop3-detect.yaml)。

---

**以 pop3-detect 为例：为什么要 steps**
POP3 的真实交互一般是：
1) 连接后服务端先发欢迎语 `+OK ...`（banner）
2) 客户端再发 `CAPA\r\n`（询问能力）
3) 服务端回多行能力列表，以 `\r\n.\r\n` 结束

如果只用一次 `data: "CAPA\r\n"`，有些服务端可能还没把 banner 发完/你没读到 banner，就开始收 CAPA，导致响应不稳定；或者能力列表是多行，单次读取可能截断。`steps` 就是为这种“多步收发”设计的。

---

**pop3-detect.yaml 逐段讲解**


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

- `type: tcp`
  - 表示走 TCP（如果是 `ssl` 则走 TLS 连接），这条规则仍然用原来的 `type` 选择协议执行器

- `steps:`（核心）
  - 是一个数组，按顺序执行，每个元素要么是 `read:`，要么是 `write:`

1) 第一步 `read`：读 banner
- `read-size: 4096`
  - 本次读最多读 4096 字节（不是“必须读满”）
- `read-timeout: 3`
  - 本次读最多等 3 秒（有数据就读；超时也会返回已读到的数据）
- `read-until: "\r\n"`
  - 读到分隔符为止（会把 `\r\n` 转成真正的 CRLF），并在分隔符处截断返回数据
  - 这个能力由 `ReceiveUntil` 
- `read-type: bytes`
  - 把 `save-as` 的变量类型设为 bytes，这样表达式里可以直接用 `bcontains/ibcontains` 之类的 bytes 函数
  - 对应的 CEL 类型声明会跟着变成 bytes
- `save-as: banner`
  - 把本次读到的数据保存到变量 `banner`
  - 注意：`banner` 是你自定义变量名，后面表达式就直接引用它

2) 第二步 `write`：发送 CAPA 命令
- `data: "CAPA\r\n"`
  - 写入的内容，会做变量渲染（例如 `{{xxx}}` 会替换）
- `data-type`（这里没写，默认 string）
  - 如果写 `data-type: hex`，则会把 data 按十六进制解码后发送

3) 第三步 `read`：读 CAPA 多行响应
- `read-until: "\r\n.\r\n"`
  - POP3 多行响应通常以 `\r\n.\r\n` 结尾，这样能一次拿到完整能力列表
- `save-as: capa`
  - 保存能力响应到 `capa`（bytes）

最后的 `expression`
- `banner.bcontains(b"+OK") && capa.bcontains(b"+OK")`
  - 这里 `banner` / `capa` 是 bytes，所以用 `b"..."` 字面量与 `bcontains`
  - 如果你把 `read-type` 写成 `string`，那表达式就该写 `banner.icontains("+OK")` 这种字符串函数（而不是 `bcontains`）

---

**`read-type` 三种用法（很关键）**
在 `read` 里：
- `read-type: bytes`
  - `save-as` 得到的是 `[]byte`，适合 `bcontains/ibcontains/bstartsWith` 这类 bytes 操作
- `read-type: string`
  - `save-as` 得到的是 `string`，适合 `icontains/toLower/replaceAll` 这类字符串操作
- 不写 `read-type`（默认）
  - `save-as` 得到的是 `proto.Response` 对象（和原来 `response` 变量类型一致）
  - 适合你想用 `saveAs.body` / `saveAs.raw` 这种结构化字段（取决于 proto.Response 暴露的字段）

---

**`read-until` 的行为边界（写 PoC 时最常踩坑）**
- 如果在 `read-size` 上限内找到了分隔符：返回内容会截断到分隔符结束（包含分隔符）
- 如果没找到分隔符：
  - 读到 `read-size` 上限就停
  - 或者 `read-timeout` 超时（但已读到数据）也会返回
- `read-until` 支持常见转义：`\r` `\n` `\t`，例如 `"\r\n.\r\n"`、`"\r\n"`

---

**写 tcp/ssl 多步 PoC 的通用模板**
- 服务器“先发 banner”的协议（SMTP/POP3/IMAP/FTP 等）：
  - 第一步先 `read` banner（通常 `read-until: "\r\n"`）
  - 再 `write` 命令
  - 再 `read` 命令结果（有多行结尾符就用多行结尾符）

如果你想把 POP3 同时支持 `ssl:995`，就像 IMAP 那样加一个 `r1` 规则，把 `type: tcp` 换成 `type: ssl`，steps 逻辑完全一样。
