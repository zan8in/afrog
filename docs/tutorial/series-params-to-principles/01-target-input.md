# #01：-t / -T 目标输入的设计与坑位

> “你以为你在喂目标，其实你在给扫描系统定‘战场形态’。”

上一期我们用 `afrog -t http://example.com` 跑通了最基本的一次扫描。  
但从开发者视角看，`-t/-T` 不是“输入框”这么简单——它决定了：

- 后续要不要补协议、怎么补
- 目标会被拆成 URL / Host / host:port / 网段段范围 哪一类
- `-ps`（端口预扫）要扫哪些 host
- 网络类 PoC / Web 类 PoC 该喂哪些资产集合
- 以及：你会不会因为目标文件写得不规范，白白浪费一晚上

---

## 这期讲哪些参数

- `-t, --target`：命令行直接传目标（支持逗号分隔多目标）
- `-T, --target-file`：从文件读目标（一行一个）

参数定义在 [options.go](file:///Users/zanbin/Documents/gowork/github/zan8in/afrog/pkg/config/options.go#L240-L248)。

---

## 一句话建议（先拿结论）

- 目标少、临时验证：用 `-t`
- 目标多、跑批、可复现：用 `-T`
- 目标既有 URL 又有 IP/CIDR：都能喂，但你要清楚它们会走不同的“后续链路”

---

## 为什么要有 -t 和 -T（而不是只留一个）

从设计者角度，这俩参数解决的是两个不同问题：

- `-t` 解决“交互速度”：复制粘贴即开跑（还支持逗号分隔，适合临时打点）
- `-T` 解决“工程化”：可沉淀、可复盘、可分批、可交接（你把 targets.txt 扔给队友，他能原样复现你的战果）

更重要的是：`-T` 是跑批的最小可追溯单位。你后面做 `--resume`、做告警、做输出归档，都离不开“目标文件”这个锚点。

---

## 核心实现原理：目标是怎么进引擎的

### 1) 目标汇总：三路输入统一进 options.Targets

Afrog 会把 `-t`、`-T`、以及测绘导入（`-cs/-q`）拿到的目标，统一 append 到 `options.Targets` 里，并用 `seen` 做一次去重。

实现位置：[runner.go](file:///Users/zanbin/Documents/gowork/github/zan8in/afrog/pkg/runner/runner.go#L162-L210)

关键行为：

- `-t`：每个 target `TrimSpace` 后加入
- `-T`：逐行读取，每行 `TrimSpace`，空行丢弃
- 三路输入统一去重：避免同一个目标重复扫两次

### 2) 目标文件读取：朴素到你必须知道它的边界

`targets.txt` 的读取是纯逐行读取：[file.go](file:///Users/zanbin/Documents/gowork/github/zan8in/afrog/pkg/utils/file.go#L15-L32)

它的“朴素后果”：

- 不会自动跳过 `# 注释行`
- 不会自动忽略 BOM
- 只负责“读”，真正的“过滤空行/去空格”发生在 runner 汇总阶段

使用建议：targets.txt 里别写注释行；如果要分组，用多个文件更稳。

---

## 目标“分类”的设计：URL / Host / host:port / 网段段范围

很多人以为 Afrog 看到什么就扫什么。实际上它会先做“目标索引”（TargetIndex），把输入拆成四类：

- URLs：`https://a.com/x`
- Hosts：`a.com`、`1.2.3.4`
- HostPorts：`1.2.3.4:8080`
- Expandable：`192.168.1.0/24`、`192.168.1.1-192.168.1.254`

入口在：[index.go](file:///Users/zanbin/Documents/gowork/github/zan8in/afrog/pkg/targets/index.go#L25-L75)

### 1) 先识别“可展开目标”（CIDR/段范围）

CIDR 和 IP 段范围会被优先识别为 Expandable：[index.go](file:///Users/zanbin/Documents/gowork/github/zan8in/afrog/pkg/targets/index.go#L166-L192)

这也是为什么你输入 `192.168.1.0/24` 时，后面 `-ps` 能自然接上：它天生就是“资产扩展型输入”。

### 2) URL 的识别：只在它“看起来像 URL”时才会被当成 URL

URL 识别逻辑里有个关键设计：没写 scheme 且没有 `/ ? #` 时，不把它当 URL。[index.go](file:///Users/zanbin/Documents/gowork/github/zan8in/afrog/pkg/targets/index.go#L194-L227)

也就是说：

- `example.com` → 更像 Host（让后续去补协议/做探活）
- `example.com/path` → 更像 URL（会被推断成 `http://example.com/path`）

设计者直觉是：裸域名/裸 IP 通常想扫 Web 面或资产面；带路径通常就是要打这个路由。

### 3) Host:Port 的识别：严格限制端口合法性

`host:port` 会被解析并校验端口范围，最终规范化：[index.go](file:///Users/zanbin/Documents/gowork/github/zan8in/afrog/pkg/targets/index.go#L260-L305)

好处：把明显错误的输入尽早挡住，避免把无意义目标拖进后续流程。

---

## “为什么我没写 http/https，它也能跑？”——协议补全与探活的真相

当目标不是 URL 时，会走协议探测：探测成功会把目标更新为 `http(s)://...`；探测失败会累计错误，超过阈值会被拉黑，避免拖垮全局跑批。

实现位置：[monitor.go](file:///Users/zanbin/Documents/gowork/github/zan8in/afrog/pkg/runner/monitor.go#L90-L125)

---

## 实战建议：-t/-T 怎么用才不浪费子弹

### 1) 三种输入形态，对应三种写法

```bash
# 1) 精准打点：你确定这是一个 Web 服务
afrog -t https://example.com

# 2) 你只知道域名/主机，让 Afrog 自己补协议、做探活
afrog -t example.com

# 3) 资产面起手：网段/段范围（后面通常接 -ps）
afrog -t 192.168.1.0/24 -ps
```

### 2) targets.txt 推荐规范（简单但有效）

- 一行一个目标
- 不写注释行（`#` 这种别写）
- 不要混入描述性文本
- 尽量统一大小写（`EXAMPLE.com` 和 `example.com` 在早期去重阶段不一定会被认为是同一个）

### 3) 跑批常用基线（稳）

```bash
afrog -T targets.txt -S high,critical -ja result.json
```

---

## 这期你应该记住的“设计答案”

- `-t` 是快，`-T` 是可控、可追溯、可复现
- Afrog 不只是“读取目标”，它会先做“目标分类与规范化”
- 裸域名/裸 IP 不等于 URL：补协议与探活是系统的一部分
- 目标文件越干净，你的扫描越像“工程”，越不靠运气

---

## 下期预告

下一期我们继续把“目标输入”打穿：  
**#02：`-cs/-q/-qc` 空间测绘导入为什么这么设计，怎么避免把自己跑死。**

