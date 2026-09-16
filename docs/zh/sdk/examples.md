---
title: 示例程序
slug: /docs/sdk/examples
lang: zh
summary: 汇总 afrog SDK 相关示例程序及其适用场景。
status: published
source: docs/SDK使用指南_中文.md
last_reviewed: 2026-09-16
---

如果你已经看完 [SDK 快速开始](./quickstart.md)，最适合下一步的方式通常不是继续读概念，而是直接跑示例程序。

## 示例目录

仓库中的 `examples/` 已提供多种可运行示例，默认会自动定位到仓库内的 `pocs/afrog-pocs`，也可以通过 `-pocs` 参数覆盖。

## 常用示例

### 基础扫描器

```bash
go run ./examples/basic_scan
```

适合场景：

- 最小可运行集成
- 理解最基本的 `sdk.New + Execute + Results`

### 完整输出

```bash
go run ./examples/full_output -json
```

适合场景：

- 查看完整请求与响应数据
- 观察结构化结果如何落 JSON

### 异步扫描器

```bash
go run ./examples/async_scan
```

适合场景：

- 了解异步执行
- 结合 `Start / Wait / Done`

### 进度扫描器

```bash
go run ./examples/progress_scan
```

适合场景：

- 展示扫描进度
- 观察进度相关接口如何接入

### OOB 扫描器

```bash
go run ./examples/oob_scan -oob dnslogcn -oob-domain your.dnslog.cn
```

适合场景：

- 带外检测
- OOB 配置验证

### SDK 端口扫描

```bash
go run ./examples/sdk_portscan -target 127.0.0.1
```

适合场景：

- 预扫描开放端口
- 观察 `OpenPorts()` 结果

### 漏洞扫描

```bash
go run ./examples/vuln_scan -target https://example.com
```

适合场景：

- 更接近真实业务集成
- 流式消费漏洞结果

### 端口扫描

```bash
go run ./examples/port_scan -targets 127.0.0.1
```

适合场景：

- 单独使用端口扫描能力
- 了解 `portscan` 相关用法

## 怎么选示例

一般建议：

- 想先跑通：`basic_scan`
- 想看完整数据：`full_output`
- 想做异步任务：`async_scan`
- 想看进度：`progress_scan`
- 想做 OOB：`oob_scan`

## 相关文档

- [SDK 快速开始](./quickstart.md)
- [同步与异步](./sync-and-async.md)
- [API 参考](./api-reference.md)
