<!--
title: 配置参考
slug: /docs/sdk/config-reference
lang: zh
summary: 汇总 afrog SDK 的常用选项、默认值和配置边界。
status: published
source: docs/SDK使用指南_中文.md
last_reviewed: 2026-09-16
-->

本页汇总 `afrog` SDK 中最常用的一批配置选项，方便在集成时快速定位“该配什么”和“默认行为是什么”。

## 目标

| 选项 | 说明 |
| --- | --- |
| `WithTargets(...)` | 扫描目标列表 |
| `WithTargetsFile(path)` | 从文件读取目标，每行一个 |
| `WithCyberspace(cfg)` | 从空间测绘搜索获取目标，目前仅支持 ZoomEye |
| `WithTargetPreProbe()` | 并发预探测目标协议与存活，对应 CLI 的 `-mt` |

## PoC

| 选项 | 说明 |
| --- | --- |
| `WithPocPaths(...)` | 文件、目录或 glob，追加语义 |
| `WithPocPathsOnly()` | 只使用显式指定的 PoC |
| `WithSearch(kw)` | 按关键词过滤 |
| `WithSeverity(sev)` | 按风险等级过滤 |
| `WithExcludePocs(...)` | 排除指定 PoC |
| `WithExcludePocsFile(path)` | 从文件读取排除列表 |

## 性能

| 选项 | 默认值 |
| --- | --- |
| `WithConcurrency(n)` | `25` |
| `WithRateLimit(n)` | `150` |
| `WithTimeout(sec)` | `50` |
| `WithRetries(n)` | `1` |
| `WithMaxHostError(n)` | `3` |
| `WithMaxRespBodySize(mb)` | `2` |
| `WithRequestLimitPerTarget(n)` | `0` |
| `WithPolite()` / `WithBalanced()` / `WithAggressive()` | 无 |
| `WithAutoRequestLimit()` | 无 |
| `WithSmartConcurrency()` | 无 |
| `WithStopOnFirstMatch()` | 无 |

需要注意：

- `WithRequestLimitPerTarget`
- `WithAutoRequestLimit`
- `WithPolite`
- `WithBalanced`
- `WithAggressive`

这几类单目标限速策略互斥，同时设置多个会返回 `ErrInvalidOptions`。

## 指纹与探测

| 选项 | 默认值 |
| --- | --- |
| `WithFingerprintDisabled()` | 指纹默认开启 |
| `WithFingerprintFilterMode(mode)` | `"strict"`，可选 `"opportunistic"` |
| `WithWebProbe()` | 默认关闭 |

## 网络

| 选项 | 说明 |
| --- | --- |
| `WithProxy(p)` | HTTP 或 SOCKS5 代理 |
| `WithHeaders(...)` | 自定义请求头，格式为 `"Name: value"` |

## 输出

| 选项 | 默认值 |
| --- | --- |
| `WithRequestResponse(b)` | `true` |
| `WithMaxStoredResults(n)` | `0`，表示不限 |
| `WithStreamBuffer(n)` | `256` |
| `WithRedactedHeaders(...)` | 默认不脱敏 |
| `WithVerbose()` | 默认静默 |

### 脱敏建议

如果结果会进入日志、数据库或 API 返回，建议开启头部脱敏：

```go
sdk.WithRedactedHeaders()
sdk.WithRedactedHeaders("authorization", "x-token")
```

脱敏会同时作用于：

- 原始请求报文
- 原始响应报文
- 请求头结构
- 响应头结构

被命中的头部值会被替换成 `[REDACTED]`。

## OOB

通过 `WithOOB(cfg)` 配置带外检测：

```go
sdk.WithOOB(sdk.OOBOptions{
  Adapter: "ceyeio",
  Key:     "your-ceye-api-token",
  Domain:  "your-subdomain.ceye.io",
})
```

常见适配器与必填字段：

| Adapter | 必填字段 |
| --- | --- |
| `ceyeio` | `Key`、`Domain` |
| `dnslogcn` | `Domain` |
| `alphalog` | `Domain`、`ApiURL` |
| `xray` | `Key`、`Domain`、`ApiURL` |
| `revsuit` | `Key`、`Domain`、`ApiURL`、`HttpURL` |

如果没有显式传入，SDK 会尝试只读加载：

```text
~/.config/afrog/afrog-config.yaml
```

SDK 不会自动创建或改写这份文件。

## 端口预扫描

通过 `WithPortScan(cfg)` 配置：

```go
sdk.WithPortScan(sdk.PortScanOptions{
  Ports:         "top",
  TimeoutMs:     500,
  SkipDiscovery: true,
})
```

适合：

- 网段扫描
- 服务发现
- 把 `host:port` 动态纳入后续漏洞扫描

## 任务级超时

单请求超时和单任务超时不是一回事。后者用于限制“单目标 + 单 PoC”的整体耗时：

```go
sdk.WithTaskTimeout(sdk.TaskTimeoutOptions{
  HardSec: 120,
  Smart:   true,
})
```

说明：

- `HardSec`：固定上限
- `Smart`：按规则数量、爆破、sleep、payload 等估算超时

两者同时开启时取较大值，因此 `HardSec` 更像下限保护，而不是覆盖智能估算。

## 执行耗时监控

对应 CLI 的 `-pedm`：

```go
sdk.WithExecutionMonitor(sdk.ExecutionMonitorOptions{
  SlowThresholdSec: 20,
  SummaryTop:       10,
  SummaryBy:        sdk.MonitorSummaryByMax,
}),
sdk.WithMonitorHandler(func(line string) {
  log.Println(line)
})
```

注意：

- 监控输出只会送到 `WithMonitorHandler`
- 不注册 handler 时，监控虽然运行，但你看不到结果

## 断点续扫

对应 CLI 的 `-resume`：

```go
sdk.WithCheckpoint(sdk.CheckpointOptions{
  Path:         "scan.afg",
  SaveInterval: 10 * time.Second,
})
```

断点是按“目标 + PoC id”记录的，因此续扫时目标集和 PoC 集需要保持一致。

## 常见错误

初始化和运行时最常见的错误包括：

- `ErrNoTargets`
- `ErrNoPocs`
- `ErrPocPathNotFound`
- `ErrAlreadyRunning`
- `ErrAlreadyFinished`
- `ErrClosed`
- `ErrNotStarted`
- `ErrInvalidOptions`
- `ErrWebhookTokenRequired`

如果只是 curated PoC 源挂载失败，则属于可选错误，不会中断扫描；可以通过 `scanner.CuratedError()` 查看。

> **← 上一篇：** [回调与流](./03-handlers-and-streams.md) ｜ **本手册首页：** [SDK 快速开始](./01-quickstart.md) ｜ **下一篇 →：** [API 参考](./05-api-reference.md)
