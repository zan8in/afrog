---
title: 同步与异步
slug: /docs/sdk/sync-and-async
lang: zh
summary: 介绍 afrog SDK 的同步执行、异步执行和生命周期控制。
status: published
source: docs/SDK使用指南_中文.md
last_reviewed: 2026-09-16
---

`afrog` SDK 同时支持同步和异步两种执行方式。选择哪一种，取决于你是想用最短路径跑完扫描，还是想自己接管进度、状态和调度。

## 同步执行

同步方式最直接，调用 `Execute(ctx)` 后会一直阻塞到扫描结束。

```go
if err := scanner.Execute(ctx); err != nil {
  log.Fatal(err)
}
results := scanner.Results()
```

适合场景：

- 命令式批处理
- 简单服务端任务
- 先求跑通、后求扩展的集成

## 异步执行

如果你需要边扫边看进度、或把扫描过程纳入自己的事件循环，可以使用：

- `Start(ctx)`
- `Wait(ctx)`
- `Done()`

示例：

```go
if err := scanner.Start(ctx); err != nil {
  log.Fatal(err)
}

go func() {
  ticker := time.NewTicker(time.Second)
  defer ticker.Stop()
  for {
    select {
    case <-ticker.C:
      fmt.Printf("进度: %.1f%%\n", scanner.Progress())
    case <-scanner.Done():
      return
    }
  }
}()

if err := scanner.Wait(ctx); err != nil {
  log.Printf("扫描出错: %v", err)
}
```

适合场景：

- 需要实时展示进度
- 需要和其他任务并行运行
- 需要自定义调度和状态控制

## 生命周期方法

| 方法 | 说明 |
| --- | --- |
| `Execute(ctx)` | 同步执行，直到扫描结束才返回 |
| `Start(ctx)` | 异步启动，立即返回 |
| `Wait(ctx)` | 阻塞等待扫描结束，返回扫描错误 |
| `Done()` | 返回扫描结束时关闭的通道 |
| `Err()` | 返回扫描错误，未结束时为 `nil` |
| `Stop()` | 请求停止，立即返回 |
| `Close()` | 停止扫描、等待协程退出并释放资源 |
| `Pause()` / `Resume()` / `IsPaused()` | 暂停控制 |
| `IsStopping()` / `IsRunning()` | 状态查询 |

## 一次性语义

扫描器实例是一次性的：

```go
scanner.Execute(ctx) // 第一次：正常
scanner.Execute(ctx) // 第二次：返回 ErrAlreadyFinished
```

如果要重新执行一次扫描，请新建一个 `Scanner` 实例。

## `Close()` 的建议用法

`Close()` 是幂等的，建议在 `New` 成功后立即：

```go
defer scanner.Close()
```

这样无论同步还是异步路径，都能更稳地释放后台资源。

## 如何选择

优先建议：

- 想快速集成：先用同步
- 想做平台化、实时展示、流式消费：改用异步

## 相关文档

- [SDK 快速开始](./quickstart.md)
- [回调与流](./handlers-and-streams.md)
- [配置参考](./config-reference.md)
