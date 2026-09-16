---
title: 常见问题
slug: /docs/sdk/faq
lang: zh
summary: 汇总 afrog SDK 集成中最常见的问题与处理建议。
status: published
source: docs/SDK使用指南_中文.md
last_reviewed: 2026-09-16
---

本页收集 `afrog` SDK 集成里最常见的一批问题。

## 指定了 PoC 目录，为什么内置 PoC 没有执行

最常见原因是启用了：

```go
WithPocPathsOnly()
```

它的语义是“只用显式指定的 PoC”，因此不会再与内置 PoC 合并。如果你想保留内置 PoC，同时追加本地目录，请去掉这个选项。

## 扫描卡住不动了

优先检查是否订阅了某个流，但没有消费。

原因是 SDK 为了不丢结果，在流通道写满时会阻塞发送。如果你订阅了流却没人读，扫描流程可能会被自己堵住。

## 为什么 `Wait` 返回 `context.Canceled`

通常表示：

- 调用了 `Stop()`
- 外部 `context` 被取消
- 收到了中断信号

这并不意味着结果全部丢失；此时仍可以通过 `Results()` 获取已经产出的结果。

## 大规模扫描时内存增长过快

优先组合：

```go
sdk.WithRequestResponse(false)
sdk.WithMaxStoredResults(1000)
```

同时建议：

- 用回调实时落库
- 用流实时消费
- 不要只依赖 `Results()` 在内存里无限累计

## 什么时候用同步，什么时候用异步

经验上：

- 简单任务、批处理：先用同步
- 需要进度、流式消费、平台集成：用异步

## 多个扫描器能不能并行跑

不建议同一进程里并行运行多个扫描器实例，因为部分网络状态是进程级共享的，可能相互覆盖代理、超时或速率配置。

更稳妥的方式是串行运行多个实例，或由外层进程调度。

## 相关文档

- [SDK 快速开始](./quickstart.md)
- [配置参考](./config-reference.md)
- [API 参考](./api-reference.md)
