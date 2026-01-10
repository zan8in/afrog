# requires 指纹门控：用法教程与问题答疑

本文介绍 Afrog PoC 新增的 `requires`/`requires-mode` 门控能力：让高成本（弱口令/爆破/默认口令等）PoC 仅在目标命中指定指纹后执行，从而显著降低无效请求与扫描耗时。

---

## 1. 功能定位（解决什么问题）

在真实扫描中，弱口令/爆破类 PoC 往往非常耗时。如果对“所有端口 / 所有 HTTP 站点”都无差别执行，会带来：

- 扫描时间被大幅拉长（尤其是端口资产多、服务类型杂时）
- 误扫误打扰（对不相关的服务发送认证/登录请求）
- 用户体验不符合“专业漏扫”的常识流程（应先识别是什么，再做针对性检测）

`requires` 的目标就是把流程变为：

1) 先跑指纹识别（fingerprinting stage）  
2) 只有命中相关指纹的目标，才执行对应的高成本 PoC

---

## 2. PoC 作者需要写什么字段

这两个字段写在 `info:` 下：

- `requires`: 依赖的“指纹标签（tag）”列表
- `requires-mode`: 门控模式（可选，默认 strict）

### `requires` 支持两种写法（语义等价）

- 数组写法（推荐）

  - 示例：`requires: [nacos,redis]`

- 字符串写法（逗号分隔）

  - 示例：`requires: "nacos,redis"`

`requires` 会被做以下标准化：去空格、转小写、去重。

---

## 3. `requires` 是怎么判定“允许执行”的

核心规则非常简单：

- 如果 PoC 没写 `requires`：不启用门控（行为不变）
- 如果 PoC 写了 `requires`：只有当该 target 的“指纹命中 tags”与 `requires` 有交集时，才允许执行

这里的“指纹命中 tags”来自指纹阶段命中的指纹 PoC 的 `info.tags`：

- 指纹 PoC 通常会带 `fingerprint` tag
- 系统会忽略 `fingerprint` 这个 tag，本质上是用它来区分“这是指纹 PoC”
- 其它 tag（例如 `ftp`、`mysql`、`nacos` 等）会作为“命中指纹 tags”参与门控匹配

### `requires` 多值语义：OR（任意命中即可）

如果你写：

- `requires: [nacos, seata]`

含义是：“目标只要命中 nacos 或 seata 任意一种指纹，就执行该 PoC”。

---

## 4. `requires-mode` 的完整语义（strict vs opportunistic）

`requires-mode` 用于控制“没有指纹结果”时怎么办。

### A. `requires-mode: strict`（默认）

strict 会在以下情况跳过 PoC：

1) 指纹阶段没有结果（例如禁用了指纹阶段、或指纹 PoC 未覆盖、或目标没有命中）  
2) 有指纹结果，但与 `requires` 不匹配

适用场景：

- 弱口令/爆破
- 默认口令
- 登录类高频探测
- 任何你不希望“对不相关目标也跑一遍”的 PoC

### B. `requires-mode: opportunistic`

opportunistic 的行为是：

- 如果指纹阶段没有结果：不拦截，照常执行
- 如果有指纹结果但不匹配 requires：仍然跳过

适用场景：

- 你希望“有指纹就精准收敛，但没指纹也尽量不漏扫”的中低成本 PoC

---

## 5. target 形式与门控命中（非常关键）

门控需要把当前扫描的 target 映射成一个 key，才能关联到该 target 的指纹结果。建议遵循：

- Web 场景：使用带 scheme 的 URL
  - 例如：`http://1.2.3.4:8848`
- 网络服务：使用 `host:port`
  - 例如：`1.2.3.4:21`

在 strict 模式下，如果 target 既不是 URL 也不是 `host:port`，可能会因为无法关联指纹结果而被跳过。

---

## 6. 典型场景：HTTP 应用“先指纹后弱口令”（以 Nacos 为例）

目标：只对确认为 Nacos 的站点执行 Nacos 默认口令/弱口令 PoC。

PoC 作者的表达方式：

- 指纹 PoC（fingerprinting）在 `info.tags` 中包含：`nacos,fingerprint`
- 弱口令/默认口令 PoC 在 `info` 中声明：
  - `requires: [nacos]`
  - `requires-mode: strict`

运行效果：

- 命中 Nacos 指纹的目标：执行弱口令/默认口令 PoC
- 未命中 Nacos 指纹的目标：跳过，不做无意义请求

---

## 7. 典型场景：网络服务“先指纹后登录探测”（以 FTP 匿名登录为例）

目标：只对确认为 FTP 的 `host:21` 执行匿名登录检测。

PoC 作者的表达方式：

- 指纹 PoC 的 `info.tags`：至少包含 `ftp,fingerprint`
- 匿名登录/弱口令类 PoC：
  - `requires: [ftp]`
  - `requires-mode: strict`

运行效果：

- 只有命中 ftp 指纹的 `host:21` 才会执行匿名登录检测
- 其它开放端口不会被无关的登录探测打扰

---

## 8. 运行时你必须知道的开关：禁用指纹阶段会影响 strict

如果你让某些 PoC 使用 strict requires，就意味着它们强依赖“指纹阶段”产出。

Afrog 命令行中：

- `-nf`：禁用指纹阶段（跳过带 `fingerprint` tag 的 PoC）

因此：

- 不加 `-nf`：指纹先跑，strict requires 才能正常放行对应 PoC
- 加了 `-nf`：指纹不跑，strict requires 大概率会跳过（因为没有指纹 tags 可匹配）

---

## 9. 指纹 tags 与 requires 如何对齐（推荐规范）

为了让 requires 门控稳定可靠，建议团队统一约定：

- 指纹 PoC 的 `info.tags` 必须包含：
  - `fingerprint`
  - 一个“主 tag”（产品/服务名，例如 `mysql`/`ftp`/`nacos`/`redis`）
- 弱口令/爆破/默认口令 PoC 的 `requires` 只依赖“主 tag”
- 分类 tag（例如 `network`/`db`/`middleware`）不建议写进 requires

这样能避免 `requires: [network]` 这类过宽依赖导致门控失效。

---

## 10. 常见服务：门控写法模板（文字模板）

以下为“主 tag”建议（指纹 PoC 产出主 tag；高成本 PoC 依赖主 tag）：

- FTP：主 tag `ftp`，目标建议 `ip:21`
- MySQL：主 tag `mysql`，目标建议 `ip:3306`
- Redis：主 tag `redis`，目标建议 `ip:6379`
- PostgreSQL：主 tag `postgresql`，目标建议 `ip:5432`
- SSH：主 tag `ssh`，目标建议 `ip:22`
- RDP：主 tag `rdp`，目标建议 `ip:3389`
- SMB：主 tag `smb`，目标建议 `ip:445`
- Nacos：主 tag `nacos`，目标建议 `http(s)://ip:8848`

---

## 11. 两个最常见的“为什么没跑”排障点

### 坑 1：target 形式不规范导致无法关联指纹结果

strict 模式下，如果 target 不是 `http(s)://...` 或 `host:port`，可能无法命中指纹 key，从而被跳过。

建议：

- 网络服务一律使用 `ip:port`
- Web 一律使用带 scheme 的 URL

### 坑 2：指纹阶段没跑出结果（或被禁用）

strict requires 的设计目标就是：没有指纹结果就不跑高成本 PoC。

如果你希望“没指纹也尽量扫一遍”，把该 PoC 设置为 opportunistic 更合适。

---

## 12. 与现有 tags 过滤机制的关系（如何理解两者）

Afrog 已有基于 tags 的收敛机制，用于在指纹结果存在时减少不相关 PoC 的执行。

`requires` 是一种更“显式”的声明方式：

- tags 过滤更偏“系统侧的智能收敛”
- requires 更偏“PoC 作者明确声明依赖”，尤其适合弱口令/爆破类 PoC

两者可以同时存在：requires 用于表达强依赖，tags 过滤用于进一步收敛与优化。

---

## 快速自检清单（写 PoC 前 30 秒检查）

- 指纹 PoC 的 `info.tags` 是否包含主 tag + `fingerprint`
- 弱口令/爆破 PoC 是否写了 `requires`，并使用 `requires-mode: strict`
- 运行时是否误加了 `-nf` 导致 strict 被全部门控
- target 是否使用了 `http(s)://...` 或 `host:port`

