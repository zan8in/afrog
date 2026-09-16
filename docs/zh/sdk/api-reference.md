---
title: API 参考
slug: /docs/sdk/api-reference
lang: zh
summary: 汇总 afrog SDK 常用构造方法、结果读取方法和信息查询接口。
status: published
source: docs/SDK使用指南_中文.md
last_reviewed: 2026-09-16
---

本页汇总 `afrog` SDK 中最常用的一批方法，方便在集成时快速查询“有哪些入口”和“能拿到哪些结果”。

## 构造

| 方法 | 返回值 |
| --- | --- |
| `New(ctx, options...)` | `*Scanner, error` |
| `NewOptions()` | `*Options` |

### `New`

这是创建扫描器的主入口。

```go
scanner, err := sdk.New(ctx,
  sdk.WithTargets("https://example.com"),
  sdk.WithPocPaths("./pocs"),
)
```

### `NewOptions`

适合你先构造一份完整配置，再统一传入或复用的场景。

## 结果读取

| 方法 | 返回值 |
| --- | --- |
| `Results()` | `[]Result` |
| `ResultCount()` | `int` |
| `HasResults()` | `bool` |
| `OpenPorts()` | `map[string][]int` |
| `Stats()` | `Stats` |
| `Progress()` | `float64` |

### `Results()`

返回结构化结果列表，是大多数集成最常用的读取入口。

### `ResultCount()` / `HasResults()`

适合快速判断有没有命中结果。

### `OpenPorts()`

当启用了端口预扫描时，可读取发现的开放端口。

### `Stats()` / `Progress()`

适合做扫描统计和进度显示。

## PoC 与扫描信息

| 方法 | 返回值 |
| --- | --- |
| `Pocs()` | `[]poc.Poc` |
| `PocCount()` | `int` |
| `PocDiagnostics()` | `[]config.PocLoadError` |
| `Info()` | `ScanInfo` |
| `OOBStatus()` | `bool, string` |
| `CuratedError()` | `error` |

### `Pocs()` / `PocCount()`

用于检查当前实际加载了哪些 PoC，以及总数是多少。

### `PocDiagnostics()`

当某些 PoC 被跳过、路径无效或 YAML 解析失败时，可以从这里查看原因。

### `Info()`

返回当前扫描的总体信息，适合做摘要展示。

### `OOBStatus()`

检查带外平台是否可用。

### `CuratedError()`

用于查看 curated PoC 源是否有可选错误。它通常不是致命错误，不会阻断主扫描流程。

## 并发限制

单个扫描器实例本身是并发安全的，可以从多个协程调用它的方法。

但同一进程内不建议多个扫描器并行运行，因为 HTTP 客户端、限速器和探测缓存存在进程级共享状态，多个扫描器同时运行时可能互相覆盖代理、超时和速率配置。

推荐做法是串行复用：

```go
for _, group := range targetGroups {
  scanner, _ := sdk.New(ctx, sdk.WithTargets(group...), sdk.WithPocPaths(pocPath))
  if err := scanner.Execute(ctx); err != nil {
    log.Print(err)
  }
  results = append(results, scanner.Results()...)
  scanner.Close()
}
```

## 典型集成片段

### CI 安全门禁

```go
scanner, err := sdk.New(ctx,
  sdk.WithTargetsFile("staging-urls.txt"),
  sdk.WithPocPaths("/security/pocs"),
  sdk.WithSeverity("high,critical"),
)
if err != nil {
  log.Fatal(err)
}
defer scanner.Close()

if err := scanner.Execute(ctx); err != nil {
  log.Fatal(err)
}

if results := scanner.Results(); len(results) > 0 {
  os.Exit(1)
}
```

### 超时控制

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
defer cancel()

if err := scanner.Execute(ctx); err != nil {
  if errors.Is(err, context.DeadlineExceeded) {
    log.Println("扫描超时")
  }
}
```

### 信号处理

```go
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
defer stop()

scanner.Execute(ctx)
```

### Web 服务集成

```go
func scanHandler(w http.ResponseWriter, r *http.Request) {
  scanner, err := sdk.New(r.Context(),
    sdk.WithTargets(r.URL.Query().Get("target")),
    sdk.WithPocPaths(os.Getenv("POC_PATH")),
  )
  if err != nil {
    http.Error(w, err.Error(), http.StatusBadRequest)
    return
  }
  defer scanner.Close()

  if err := scanner.Execute(r.Context()); err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }

  w.Header().Set("Content-Type", "application/json")
  _ = json.NewEncoder(w).Encode(scanner.Results())
}
```

## 常见问题

### 指定了 PoC 目录，为什么内置 PoC 没有执行

通常是因为加了 `WithPocPathsOnly()`。如果你希望与内置 PoC 合并，去掉这个选项即可。

### 为什么 `Wait` 返回 `context.Canceled`

通常表示扫描被 `Stop()` 或外部 `context` 取消了。此时仍然可以通过 `Results()` 获取已完成部分的结果。

### 大规模扫描时内存增长过快

优先组合：

```go
sdk.WithRequestResponse(false)
sdk.WithMaxStoredResults(1000)
```

并结合回调或流实时处理结果，避免完全依赖 `Results()` 持续累积。

## 相关文档

- [SDK 快速开始](./quickstart.md)
- [同步与异步](./sync-and-async.md)
- [回调与流](./handlers-and-streams.md)
- [配置参考](./config-reference.md)
