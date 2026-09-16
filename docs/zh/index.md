---
title: afrog 文档
slug: /docs
lang: zh
summary: afrog 官方文档首页，先按任务与角色引导，再提供可深查的参考入口。
status: published
source: new
last_reviewed: 2026-09-16
---

欢迎来到 `afrog` 官方文档。

`afrog` 是一个面向漏洞验证、PoC 编写和集成开发的安全工具。

这套文档的设计目标不是把所有信息直接摊成“参数堆”，而是分成两层：

- 外层先解决“我现在要做什么”
- 内层再提供“我需要精确查什么”的参考入口

如果你是第一次进入文档，建议先走下面的任务入口；如果你已经有明确问题，也可以直接跳到“按主题速查”。

## 按任务开始

### 我想先跑起来

这是从安装到第一次拿到结果的最短路径：

1. [安装](./getting-started/install.md)
2. [第一次扫描](./getting-started/first-scan.md)
3. [CLI 参数总览](./reference/cli-options.md)
4. [配置文件说明](./user-guide/configuration.md)
5. [输出与报告](./user-guide/output-and-report.md)

### 我想写 PoC

建议按这个顺序进入：

1. [PoC 编写快速开始](./poc/quickstart.md)
2. [PoC 语法参考](./poc/syntax.md)
3. [内置函数参考](./poc/helper-functions.md)
4. [requires 指纹门控](./poc/requires.md)
5. [OOB 带外检测](./poc/oob.md)

### 我想把 afrog 集成进程序

1. [SDK 快速开始](./sdk/quickstart.md)
2. [SDK 同步与异步](./sdk/sync-and-async.md)
3. [SDK 回调与流](./sdk/handlers-and-streams.md)
4. [SDK 配置参考](./sdk/config-reference.md)
5. [SDK API 参考](./sdk/api-reference.md)

## 按角色开始

### 我是使用者

如果你想尽快装好并开始扫描，建议按这个顺序阅读：

1. [安装](./getting-started/install.md)
2. [第一次扫描](./getting-started/first-scan.md)
3. [CLI 参数总览](./reference/cli-options.md)
4. [配置文件说明](./user-guide/configuration.md)
5. [输出与报告](./user-guide/output-and-report.md)

### 我是 PoC 作者

如果你准备自己写规则，建议先从这几页开始：

1. [PoC 编写快速开始](./poc/quickstart.md)
2. [PoC 语法参考](./poc/syntax.md)
3. [内置函数参考](./poc/helper-functions.md)
4. [PoC 贡献者荣誉墙](./community/contributors.md)

后续还会继续补齐：

- [requires](./poc/requires.md)
- [brute](./poc/brute.md)
- [OOB](./poc/oob.md)
- [Raw HTTP](./poc/raw-http.md)
- [TCP / SSL](./poc/tcp.md)

### 我是 SDK 用户

如果你要把 `afrog` 集成进自己的 Go 程序，先看：

1. [SDK 快速开始](./sdk/quickstart.md)
2. [输出与报告](./user-guide/output-and-report.md)

后续会继续补充：

- 同步与异步
- 回调与流
- 配置项参考
- API 参考

## 当前已可阅读的核心页面

- [安装](./getting-started/install.md)
- [第一次扫描](./getting-started/first-scan.md)
- [CLI 参数总览](./reference/cli-options.md)
- [配置文件说明](./user-guide/configuration.md)
- [输出与报告](./user-guide/output-and-report.md)
- [PoC 编写快速开始](./poc/quickstart.md)
- [PoC 语法参考](./poc/syntax.md)
- [内置函数参考](./poc/helper-functions.md)
- [PoC 贡献者荣誉墙](./community/contributors.md)
- [requires 指纹门控](./poc/requires.md)
- [brute 机制](./poc/brute.md)
- [OOB 带外检测](./poc/oob.md)
- [Raw HTTP](./poc/raw-http.md)
- [TCP / SSL](./poc/tcp.md)
- [SDK 快速开始](./sdk/quickstart.md)
- [SDK 同步与异步](./sdk/sync-and-async.md)
- [SDK 回调与流](./sdk/handlers-and-streams.md)
- [SDK 配置参考](./sdk/config-reference.md)
- [SDK API 参考](./sdk/api-reference.md)
- [SDK 示例程序](./sdk/examples.md)
- [SDK 常见问题](./sdk/faq.md)

## 按主题速查

如果你已经知道自己要查什么，可以直接从这里进入：

### 扫描与运行

- [CLI 参数总览](./reference/cli-options.md)
- [配置文件说明](./user-guide/configuration.md)
- [输出与报告](./user-guide/output-and-report.md)

### PoC 编写

- [PoC 语法参考](./poc/syntax.md)
- [内置函数参考](./poc/helper-functions.md)
- [requires 指纹门控](./poc/requires.md)
- [brute 机制](./poc/brute.md)
- [OOB 带外检测](./poc/oob.md)
- [Raw HTTP](./poc/raw-http.md)
- [TCP / SSL](./poc/tcp.md)

### SDK 集成

- [SDK 配置参考](./sdk/config-reference.md)
- [SDK API 参考](./sdk/api-reference.md)
- [SDK 示例程序](./sdk/examples.md)
- [SDK 常见问题](./sdk/faq.md)

### 社区与贡献

- [PoC 贡献者荣誉墙](./community/contributors.md)

## 当前状态

新文档结构已经建立，后续会继续把旧文档内容迁移到这里，并逐步收敛 `README`、`docs/`、`wiki` 之间的重复入口。
