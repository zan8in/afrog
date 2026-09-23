<!--
title: requires 指纹门控
slug: /docs/poc/requires
lang: zh
summary: afrog PoC 指纹门控参考，帮助你判断什么时候该用 requires，以及为什么它会跳过。
status: published
source: docs/requires-gating-guide.md
last_reviewed: 2026-09-16
-->

`requires` 和 `requires-mode` 是 PoC 的“先识别、再验证”开关。

这页最适合解决两类问题：

- 我这个 PoC 到底该不该加 `requires`
- 为什么这个 PoC 明明存在，却没有执行

如果你只是在写第一条普通 HTTP PoC，通常不需要先看这页；如果你在写弱口令、默认口令、爆破或高成本验证型 PoC，这页就很关键。

## 先判断什么时候该用

最简单的判断标准：

- 低成本、通用型检测：通常 **不用** `requires`
- 高成本、只对特定产品有意义的检测：通常 **应该用** `requires`

最典型的适用场景：

- 弱口令
- 默认口令
- 爆破
- 明确只针对某个中间件、产品或协议的登录探测

不太需要 `requires` 的场景：

- 普通路径探测
- 轻量的 HTTP 回显验证
- 本身就不会明显增加目标负担的规则

## 解决什么问题

如果对所有目标都无差别执行高成本 PoC，通常会带来几个问题：

- 扫描时间明显变长
- 对无关服务发送无意义的登录或认证请求
- 扫描流程不够“专业”，缺少先识别后验证的收敛过程

`requires` 的目标就是把流程变成：

1. 先跑指纹阶段
2. 只有命中相关指纹的目标，才执行对应 PoC

## PoC 里要写什么

这两个字段都放在 `info` 下：

- `requires`
- `requires-mode`

示例：

```yaml
info:
  name: Nacos 默认口令
  author: your-name
  severity: high
  requires: [nacos]
  requires-mode: strict
```

### 字段速查

| 字段 | 是否常用 | 作用 | 默认行为 |
| --- | --- | --- | --- |
| `requires` | 常用 | 声明需要哪些指纹 tag 命中后才执行 | 不写则不门控 |
| `requires-mode` | 常用 | 控制没有指纹结果时是否跳过 | 默认 `strict` |

## `requires` 的写法

支持两种形式，语义等价：

### 数组写法

推荐写法：

```yaml
requires: [nacos, redis]
```

### 字符串写法

```yaml
requires: "nacos,redis"
```

系统会对这些值做标准化处理：

- 去空格
- 转小写
- 去重

源码层还兼容：

- `requires-mode`
- `requiresMode`
- `requires_mode`

## 怎么判定允许执行

规则很简单：

- 没写 `requires`：不启用门控
- 写了 `requires`：只有目标命中的指纹 tags 与 `requires` 有交集时，才允许执行

这里的“命中指纹 tags”来自指纹阶段命中的指纹 PoC 的 `info.tags`。

### 你可以把它理解成一条简单规则

只有当下面这件事成立时，PoC 才会执行：

> 当前目标的指纹 tags 和 `requires` 里声明的 tags 至少有一个交集

否则，就会被跳过。

## 多值语义

`requires` 是 OR 语义，也就是任意命中即可。

例如：

```yaml
requires: [nacos, seata]
```

含义是：目标只要命中 `nacos` 或 `seata` 任意一种指纹，就允许执行这个 PoC。

## `requires-mode`

`requires-mode` 用于控制“没有指纹结果时”该怎么处理。

### `strict`

默认就是 `strict`。

在以下情况会跳过 PoC：

1. 指纹阶段没有结果
2. 指纹结果和 `requires` 不匹配

适合场景：

- 弱口令
- 默认口令
- 爆破
- 其它你不希望对无关目标也尝试一遍的高成本检测

一句话理解：**没有足够把握，就不跑。**

### `opportunistic`

行为是：

- 没有指纹结果时：不拦截，照常执行
- 有指纹结果但不匹配：仍然跳过

适合“有指纹就收敛，没指纹也尽量不漏”的中低成本 PoC。

一句话理解：**有指纹时就收敛，没指纹时先放行。**

## target 形式为什么重要

门控要把当前扫描目标映射到指纹结果上，因此 target 形式必须尽量规范。

建议：

- Web 目标使用带 scheme 的 URL，例如 `http://1.2.3.4:8848`
- 网络服务使用 `host:port`，例如 `1.2.3.4:21`

在 `strict` 模式下，如果 target 既不是 URL 也不是 `host:port`，可能因为无法关联指纹结果而被跳过。

## 最常见的两种写法

### 产品登录探测

```yaml
info:
  name: Nacos 默认口令
  author: your-name
  severity: high
  requires: [nacos]
  requires-mode: strict
```

### 有指纹就收敛、没指纹也尝试

```yaml
info:
  name: 某中低成本应用检测
  author: your-name
  severity: medium
  requires: [seata]
  requires-mode: opportunistic
```

## 典型场景

### HTTP 应用先指纹后弱口令

例如 Nacos：

- 指纹 PoC 的 `info.tags` 包含 `nacos,fingerprint`
- 弱口令 PoC 写：

```yaml
requires: [nacos]
requires-mode: strict
```

效果就是：

- 命中 Nacos 指纹时执行
- 没命中时跳过

### 网络服务先指纹后登录探测

例如 FTP 匿名登录：

- 指纹 PoC 的 `info.tags` 至少包含 `ftp,fingerprint`
- 登录探测类 PoC 写：

```yaml
requires: [ftp]
requires-mode: strict
```

这样就只会对确认是 FTP 的目标发登录探测请求。

## 与 `-nf` 的关系

`-nf` 会禁用指纹阶段。

因此：

- 不加 `-nf`：`strict` 模式能正常依赖指纹结果
- 加了 `-nf`：`strict` 模式下大概率会跳过，因为没有指纹结果可供匹配

这也是“为什么某些 requires PoC 没跑”的最常见原因之一。

## 使用建议

1. 高成本 PoC 默认优先 `strict`
2. `requires` 里尽量只放主产品 tag，不要放过宽泛的分类词
3. 指纹 PoC 的 `info.tags` 建议稳定包含一个主 tag 和 `fingerprint`
4. 如果你加了 `-nf`，就要意识到 `strict` 模式大概率会跳过
5. target 形式尽量规范，不要一会儿 URL 一会儿裸 host

## 排障思路

当你发现 PoC 没有执行时，优先检查：

1. target 是否用了规范格式
2. 指纹阶段是否被禁用
3. 指纹 PoC 是否真的产出了对应主 tag
4. 当前 PoC 是否更适合改成 `opportunistic`

## 一句话经验

如果你希望扫描流程更专业，`requires` 的作用不是“限制功能”，而是让 PoC 更像真正的验证流程：先识别，再下手。

> **← 上一篇：** [内置函数参考](./03-helper-functions.md) ｜ **本手册首页：** [PoC 编写快速开始](./01-quickstart.md) ｜ **下一篇 →：** [brute 机制](./05-brute.md)
