---
title: requires 指纹门控
slug: /docs/poc/requires
lang: zh
summary: 介绍 afrog PoC 中 requires 和 requires-mode 的门控语义与使用方式。
status: published
source: docs/requires-gating-guide.md
last_reviewed: 2026-09-16
---

`requires` 和 `requires-mode` 用来表达 PoC 对指纹结果的依赖关系，尤其适合弱口令、默认口令、爆破类这类高成本检测。

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

## 怎么判定允许执行

规则很简单：

- 没写 `requires`：不启用门控
- 写了 `requires`：只有目标命中的指纹 tags 与 `requires` 有交集时，才允许执行

这里的“命中指纹 tags”来自指纹阶段命中的指纹 PoC 的 `info.tags`。

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

### `opportunistic`

行为是：

- 没有指纹结果时：不拦截，照常执行
- 有指纹结果但不匹配：仍然跳过

适合“有指纹就收敛，没指纹也尽量不漏”的中低成本 PoC。

## target 形式为什么重要

门控要把当前扫描目标映射到指纹结果上，因此 target 形式必须尽量规范。

建议：

- Web 目标使用带 scheme 的 URL，例如 `http://1.2.3.4:8848`
- 网络服务使用 `host:port`，例如 `1.2.3.4:21`

在 `strict` 模式下，如果 target 既不是 URL 也不是 `host:port`，可能因为无法关联指纹结果而被跳过。

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

## 推荐规范

为了让门控稳定可靠，建议统一约定：

- 指纹 PoC 的 `info.tags` 包含：
  - `fingerprint`
  - 一个主 tag，例如 `mysql`、`ftp`、`nacos`
- 高成本 PoC 的 `requires` 只依赖主 tag
- 不建议把过宽的分类 tag 写进 `requires`

## 排障思路

当你发现 PoC 没有执行时，优先检查：

1. target 是否用了规范格式
2. 指纹阶段是否被禁用
3. 指纹 PoC 是否真的产出了对应主 tag
4. 当前 PoC 是否更适合改成 `opportunistic`

## 相关文档

- [PoC 编写快速开始](./quickstart.md)
- [PoC 语法参考](./syntax.md)
