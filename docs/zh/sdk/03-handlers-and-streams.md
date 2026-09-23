---
title: 回调与流
slug: /docs/sdk/handlers-and-streams
lang: zh
summary: 介绍 afrog SDK 的事件回调、流式订阅和消费注意事项。
status: published
source: docs/SDK使用指南_中文.md
last_reviewed: 2026-09-16
---

如果你希望在扫描过程中实时拿到结果，而不是等扫描结束后再统一读取，`afrog` SDK 提供了两类能力：

- 回调
- 流

## 回调

回调适合把扫描事件直接接入已有业务逻辑，比如落库、告警、统计。

示例：

```go
scanner, _ := sdk.New(ctx,
  sdk.WithResultHandler(saveToDatabase),
  sdk.WithResultHandler(sendAlert),
  sdk.WithFailureHandler(func(f sdk.Failure) {
    log.Printf("PoC %s 在 %s 上失败: %v", f.PocID, f.Target, f.Err)
  }),
  sdk.WithPortHandler(func(p sdk.PortEvent) { /* ... */ }),
  sdk.WithHostHandler(func(h sdk.HostEvent) { /* ... */ }),
  sdk.WithWebProbeHandler(func(w sdk.WebProbeEvent) { /* ... */ }),
  sdk.WithProgressHandler(func(p sdk.PhaseProgress) { /* ... */ }),
  sdk.WithScanInfoHandler(func(i sdk.ScanInfo) { /* ... */ }),
)
```

要点：

- 同一种回调可以注册多个
- 回调由扫描协程并发触发
- 实现方需要自己保证并发安全

## 流

流适合你希望自己消费事件通道的场景，比如：

- WebSocket 推送
- 前端实时面板
- 自定义队列或 worker

示例：

```go
results := scanner.ResultStream()

scanner.Start(ctx)

go func() {
  for r := range results {
    fmt.Println(r.PocID, r.FullTarget)
  }
}()

scanner.Wait(ctx)
```

## 可订阅的流

| 方法 | 事件类型 |
| --- | --- |
| `ResultStream()` | `Result` |
| `PortStream()` | `PortEvent` |
| `HostStream()` | `HostEvent` |
| `WebProbeStream()` | `WebProbeEvent` |
| `ProgressStream()` | `PhaseProgress` |
| `ScanInfoStream()` | `ScanInfo` |

## 使用流时最重要的一条

一旦订阅，就必须消费。

原因是 SDK 为了避免漏洞结果被静默丢弃，在通道写满时会阻塞发送，而不是直接丢事件。也就是说：

- 如果你订阅了流但没人读
- 扫描流程可能被你自己堵住

取消 `context` 或调用 `Stop()` 可以释放这类阻塞。

## 订阅时机

推荐在 `Start(ctx)` 之前先完成订阅：

```go
results := scanner.ResultStream()
progress := scanner.ProgressStream()
```

这样可以避免错过早期事件。

## 扫描结束后再订阅会怎样

扫描结束后再订阅，会拿到一个已关闭的通道。此时 `range` 会立即退出，不会死锁。

## 高级：引擎原始结果

如果结构化 `Result` 还不够，你也可以直接订阅引擎内部结果：

```go
sdk.WithRawResultHandler(func(r *result.Result) {
  _ = persist(r)
})
```

需要注意：

- `result.Result` 属于内部类型
- 不在 SDK 的稳定兼容承诺范围内
- 能用 `WithResultHandler` 时，优先用结构化结果

## 如何选择

一般建议：

- 想直接执行副作用：用回调
- 想自己控制消费节奏：用流
- 想拿稳定输出：优先结构化 `Result`
- 想拿内部细节：再考虑原始结果

> **← 上一篇：** [同步与异步](./02-sync-and-async.md) ｜ **本手册首页：** [SDK 快速开始](./01-quickstart.md) ｜ **下一篇 →：** [配置参考](./04-config-reference.md)
