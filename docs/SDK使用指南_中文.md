# Afrog SDK 使用指南

## 概述

Afrog SDK 是把漏洞扫描能力嵌入自己程序的 Go 接口，包路径为 `github.com/zan8in/afrog/v3/pkg/sdk`。

### 核心特性

- **结构化返回** —— 纯 Go 结构体，可直接 `json.Marshal`
- **完整数据输出** —— 每一步扫描的原始请求与响应报文都可获取
- **灵活的 PoC 输入** —— 单个文件、目录（递归）、glob 通配符
- **同步与异步** —— `Execute` 同步阻塞；`Start` + `Wait`/`Done` 异步
- **回调与流** —— 多回调注册，或按需订阅事件通道
- **默认静默** —— 不向 stdout/stderr 输出任何内容
- **类型化错误** —— 使用 `errors.Is` 判断失败原因
- **资源可控** —— `Close` 释放所有后台协程，无泄漏

### 两套 API 共存

| 包 | 入口 | 适用 |
|---|---|---|
| `github.com/zan8in/afrog/v3/pkg/sdk` | `sdk.New(ctx, opts...)` | 新代码，本文档主要介绍这套 |
| `github.com/zan8in/afrog/v3` | `afrog.NewSDKScanner(opts)` | 已有集成，保持原样即可 |

根包是旧 API 的兼容门面，内部委托给 `pkg/sdk`，因此**这次的缺陷修复和新能力对两套 API 同时生效**。旧写法无需改动：

```go
options := afrog.NewSDKOptions()
options.Targets = []string{"https://example.com"}
options.PocFile = pocPath
options.Concurrency = 10

scanner, err := afrog.NewSDKScanner(options)
if err != nil {
	log.Fatal(err)
}
defer scanner.Close()

scanner.OnResult = func(r *result.Result) {
	log.Printf("发现: %s", r.PocInfo.Id)
}
if err := scanner.Run(); err != nil {
	log.Fatal(err)
}
results := scanner.GetResults()
```

`SDKOptions` 上新增了若干可选字段，把这次的新能力开放给旧写法：`PocPaths`/`PocPathsOnly`（glob 与追加语义）、`ResumeFile`（断点续扫）、`TaskHardTimeoutSec`/`TaskSmartTimeout`、`Cyberspace`/`Query`/`QueryCount`、`MonitorTargets`、`OOBPollInterval`/`OOBHitRetention`、`MaxStoredResults`、`RedactedHeaders`、`OnFailure`、`Silent`。留空则行为与以前完全一致。

想逐步迁移的话，`scanner.Scanner()` 会返回底层的 `*sdk.Scanner`，可以直接用新 API 的流式订阅与诊断能力。

有一处旧行为被修正：同时指定 `PocFile` 与 `AppendPoc` 时，旧版会静默丢弃 `AppendPoc`，现在两者都会加载。

## 安装

```bash
go get -u github.com/zan8in/afrog/v3
```

## 快速开始

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/zan8in/afrog/v3/pkg/sdk"
)

func main() {
	ctx := context.Background()

	scanner, err := sdk.New(ctx,
		sdk.WithTargets("https://example.com"),
		sdk.WithPocPaths("./pocs/afrog-pocs"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer scanner.Close()

	if err := scanner.Execute(ctx); err != nil {
		log.Fatal(err)
	}

	for _, r := range scanner.Results() {
		fmt.Printf("[%s] %s - %s\n", r.Severity, r.FullTarget, r.PocName)
	}
}
```

## PoC 输入

`WithPocPaths` 支持三种形式，可以混用、可以传多个：

```go
sdk.WithPocPaths(
	"/path/to/single.yaml",   // 单个文件
	"/path/to/pocs",          // 目录（递归查找 .yaml/.yml）
	"/path/to/pocs/*.yaml",   // glob 通配符
)
```

### 追加还是独占

| 配置 | 行为 |
|-----|-----|
| `WithPocPaths(...)` | **追加**：与内置 PoC、curated、my、local 合并，同名时以显式路径优先 |
| `WithPocPaths(...)` + `WithPocPathsOnly()` | **独占**：只使用显式指定的 PoC |

### 检查加载结果

在发起任何网络请求之前，可以先确认加载到了什么：

```go
fmt.Printf("已加载 %d 个 PoC\n", scanner.PocCount())

for _, p := range scanner.Pocs() {
	fmt.Println(p.Id, p.Info.Name)
}

// 哪些 PoC 被跳过了，以及为什么
for _, d := range scanner.PocDiagnostics() {
	fmt.Printf("跳过 %s：%s\n", d.Path, d.Reason)
}
```

`PocLoadError.Reason` 的取值：

| 常量 | 含义 |
|-----|-----|
| `config.PocLoadNotFound` | 路径不存在或通配符没匹配到文件 |
| `config.PocLoadReadFailed` | 文件读取失败 |
| `config.PocLoadParseFailed` | YAML 解析失败 |
| `config.PocLoadLegacyOOB` | 使用了已废弃的 v2 OOB 语法 |

## 完整数据输出

`Results()` 返回 `sdk.Result`，其中 `Exchanges` 携带每一步的完整请求/响应：

```go
for _, r := range scanner.Results() {
	fmt.Printf("%s [%s] %s\n", r.PocID, r.Severity, r.FullTarget)

	for _, ex := range r.Exchanges {
		fmt.Printf("%s %s -> %d (%d ms)\n", ex.Method, ex.URL, ex.StatusCode, ex.LatencyMs)

		fmt.Println("--- 原始请求 ---")
		fmt.Println(ex.Request)

		fmt.Println("--- 原始响应 ---")
		fmt.Println(ex.Response)

		if ex.BodyTruncated {
			fmt.Println("警告：响应体在 MaxRespBodySize 上限处被截断")
		}
	}
}
```

### Result 结构

```go
type Result struct {
	PocID       string   `json:"poc_id"`
	PocName     string   `json:"poc_name,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Author      string   `json:"author,omitempty"`
	Description string   `json:"description,omitempty"`
	Reference   []string `json:"reference,omitempty"`
	Tags        []string `json:"tags,omitempty"`

	CveID       string  `json:"cve_id,omitempty"`
	CweID       string  `json:"cwe_id,omitempty"`
	CvssScore   float64 `json:"cvss_score,omitempty"`
	CvssMetrics string  `json:"cvss_metrics,omitempty"`

	Target     string `json:"target"`
	FullTarget string `json:"full_target,omitempty"`

	Extractors   map[string]string `json:"extractors,omitempty"`
	Fingerprints []Fingerprint     `json:"fingerprints,omitempty"`
	Exchanges    []Exchange        `json:"exchanges,omitempty"`

	FoundAt time.Time `json:"found_at"`
}
```

### Exchange 结构

```go
type Exchange struct {
	Request  string `json:"request,omitempty"`  // 原始请求报文
	Response string `json:"response,omitempty"` // 原始响应报文

	Method          string            `json:"method,omitempty"`
	URL             string            `json:"url,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	RequestBody     string            `json:"request_body,omitempty"`
	StatusCode      int               `json:"status_code,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
	ContentType     string            `json:"content_type,omitempty"`
	LatencyMs       int64             `json:"latency_ms,omitempty"`

	Matched        bool `json:"matched"`
	BodyTruncated  bool `json:"body_truncated,omitempty"`
	BruteTruncated bool `json:"brute_truncated,omitempty"`
	BruteRequests  int  `json:"brute_requests,omitempty"`
}
```

原始报文是字符串而不是 `[]byte`，可以直接序列化，不会变成 base64：

```go
data, err := json.MarshalIndent(scanner.Results(), "", "  ")
```

### 控制内存占用

```go
sdk.WithRequestResponse(false),   // 不保留 Exchanges
sdk.WithMaxStoredResults(1000),   // 最多累积 1000 条
```

`MaxStoredResults` 只限制内部累积，**不影响回调和流**，所有结果仍会被推送出来。

### 响应体截断

响应体读取上限由 `MaxRespBodySize` 控制（默认 2 MB）。超出部分会被丢弃，此时 `Exchange.BodyTruncated` 为 `true`，据此可以判断拿到的是不是完整响应。

```go
sdk.WithMaxRespBodySize(10) // 提高到 10 MB
```

## 同步与异步

### 同步

```go
if err := scanner.Execute(ctx); err != nil {
	log.Fatal(err)
}
results := scanner.Results()
```

### 异步

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

### 生命周期方法

| 方法 | 说明 |
|-----|-----|
| `Execute(ctx)` | 同步执行，直到扫描结束才返回 |
| `Start(ctx)` | 异步启动，立即返回 |
| `Wait(ctx)` | 阻塞等待扫描结束，返回扫描错误 |
| `Done()` | 返回扫描结束时关闭的通道 |
| `Err()` | 返回扫描错误，未结束时为 nil |
| `Stop()` | 请求停止，立即返回 |
| `Close()` | 停止扫描、等待协程退出、释放全部资源 |
| `Pause()` / `Resume()` / `IsPaused()` | 暂停控制 |
| `IsStopping()` / `IsRunning()` | 状态查询 |

扫描器是**一次性**的：

```go
scanner.Execute(ctx) // 第一次：正常
scanner.Execute(ctx) // 第二次：返回 ErrAlreadyFinished
```

需要重新扫描请新建实例。`Close()` 是幂等的，可以在 `New` 之后立即 `defer`。

## 回调与流

### 回调

```go
scanner, _ := sdk.New(ctx,
	sdk.WithResultHandler(saveToDatabase),
	sdk.WithResultHandler(sendAlert),        // 可注册多个
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

回调由扫描工作协程**并发触发**，实现方需要自行保证并发安全。

### 流

流是按需订阅的：**首次调用订阅方法之前不会产生任何数据**，因此没用到的流零开销、也绝不会阻塞扫描。

```go
results := scanner.ResultStream() // 在 Start 之前订阅

scanner.Start(ctx)

go func() {
	for r := range results {   // 扫描结束时通道关闭，range 自然退出
		fmt.Println(r.PocID, r.FullTarget)
	}
}()

scanner.Wait(ctx)
```

| 方法 | 事件类型 |
|-----|---------|
| `ResultStream()` | `Result` |
| `PortStream()` | `PortEvent` |
| `HostStream()` | `HostEvent` |
| `WebProbeStream()` | `WebProbeEvent` |
| `ProgressStream()` | `PhaseProgress` |
| `ScanInfoStream()` | `ScanInfo` |

> **重要**：一旦订阅就必须消费。为了保证漏洞不被静默丢弃，通道写满时发送会**阻塞**而不是丢弃数据。取消 context 或调用 `Stop()` 会释放被阻塞的发送。
>
> 扫描结束后再订阅会得到一个已关闭的通道，`range` 立即退出，不会死锁。

### 高级：拿到引擎原始结果

需要 `Result` 未暴露的字段（例如按引擎内部结构持久化）时：

```go
sdk.WithRawResultHandler(func(r *result.Result) {
	_ = persist(r)
})
```

`result.Result` 是内部类型，其结构不在 SDK 的稳定性保证范围内，优先使用 `WithResultHandler`。

## 错误处理

```go
scanner, err := sdk.New(ctx, opts...)
switch {
case errors.Is(err, sdk.ErrNoTargets):
	log.Fatal("未指定扫描目标")
case errors.Is(err, sdk.ErrPocPathNotFound):
	log.Fatal("PoC 路径无法解析")
case errors.Is(err, sdk.ErrInvalidOptions):
	log.Fatal("选项配置非法")
case err != nil:
	log.Fatal(err)
}
```

| 错误 | 含义 |
|-----|-----|
| `ErrNoTargets` | 未指定扫描目标 |
| `ErrNoPocs` | 没有可执行的 PoC |
| `ErrPocPathNotFound` | PoC 路径无法解析为任何文件 |
| `ErrAlreadyRunning` | 扫描已在进行中 |
| `ErrAlreadyFinished` | 扫描已结束，扫描器不可复用 |
| `ErrClosed` | 扫描器已关闭 |
| `ErrNotStarted` | 尚未启动扫描 |
| `ErrInvalidOptions` | 选项组合非法 |
| `ErrWebhookTokenRequired` | 启用了 webhook 但未配置 token |

`CuratedMountError` 表示可选的 curated PoC 源挂载失败，它**不是致命错误**，扫描会继续，可通过 `scanner.CuratedError()` 查询。

## 端口预扫描

发现的开放端口会以 `host:port` 形式追加为扫描目标：

```go
scanner, _ := sdk.New(ctx,
	sdk.WithTargets("192.168.1.0/24"),
	sdk.WithPocPaths(pocPath),
	sdk.WithPortScan(sdk.PortScanOptions{
		Ports:         "top",  // top|full|all|80,443|1-1024
		TimeoutMs:     500,
		SkipDiscovery: true,
	}),
	sdk.WithPortHandler(func(p sdk.PortEvent) {
		fmt.Printf("open: %s:%d\n", p.Host, p.Port)
	}),
)

scanner.Execute(ctx)

open := scanner.OpenPorts() // map[string][]int
```

## OOB（带外）检测

```go
scanner, _ := sdk.New(ctx,
	sdk.WithTargets(target),
	sdk.WithPocPaths(pocPath),
	sdk.WithOOB(sdk.OOBOptions{
		Adapter: "ceyeio",
		Key:     "your-ceye-api-token",
		Domain:  "your-subdomain.ceye.io",
	}),
)

// 注意：这会对 OOB 服务发起一次真实的网络探测
if enabled, status := scanner.OOBStatus(); !enabled {
	log.Printf("OOB 不可用: %s", status)
}
```

| Adapter | 必填字段 |
|---------|---------|
| `ceyeio` | `Key`、`Domain` |
| `dnslogcn` | `Domain` |
| `alphalog` | `Domain`、`ApiURL` |
| `xray` | `Key`、`Domain`、`ApiURL` |
| `revsuit` | `Key`、`Domain`、`ApiURL`、`HttpURL` |

未显式配置时，SDK 会尝试从 `~/.config/afrog/afrog-config.yaml` 读取。该文件**只读**，SDK 不会创建或改写它。

`OOBOptions` 还可以调整轮询节奏，默认值与 CLI 一致：

| 字段 | 默认 | 说明 |
|------|------|------|
| `PollInterval` | `2` | 轮询 OOB 服务的间隔（秒） |
| `HitRetention` | `10` | 命中记录的保留时长（分钟） |
| `RateLimit` | `25` | OOB 阶段的速率限制 |
| `Concurrency` | `25` | OOB 阶段的并发 |
| `FinalizeTimeout` | `-1` | 收敛等待上限（秒），`-1` 表示由 PoC 自身决定 |

### v3 的 OOB PoC 语法

```yaml
rules:
  r0:
    request:
      method: GET
      path: /?dns=ping%20{{oob.DNS}}
    expression: oobCheck(oob.ProtocolDNS, 5)
expression: r0()
```

v2 时代的 `set: oob: oob()`、`{{oobDNS}}`、`oobWait(...)`、`oobCheck(oob, ...)` 均已废弃，使用旧语法的 PoC 会被跳过并出现在 `PocDiagnostics()` 中。

## 控制台输出

SDK **默认完全静默**。需要摘要时用结构化 API：

```go
info := scanner.Info()
log.Printf("目标 %d 个，PoC %d 个，任务 %d 个",
	info.TotalTargets, info.TotalPocs, info.TotalScans)
```

或显式开启打印：`sdk.WithVerbose()`。

## 任务级超时

单次请求的超时用 `WithTimeout`，但一个规则很多的 PoC 可能远超单次请求时长地占住 worker。`WithTaskTimeout` 给「单个目标 + 单个 PoC」这一整个任务加上限：

```go
sdk.WithTaskTimeout(sdk.TaskTimeoutOptions{
	HardSec: 120,  // 固定上限（秒），0 表示不限
	Smart:   true, // 依据 PoC 内容估算上限
})
```

`Smart` 会根据规则数量、sleep、爆破、payload 等估算超时。两者同时设置时**取较大值**，也就是 `HardSec` 起下限作用而不是覆盖估算值。

估算值按协议族分别设上限，默认与 CLI 一致：`VisibleCapSec` 300（普通 HTTP）、`NetCapSec` 360（tcp/udp/ssl）、`GoCapSec` 420（go 类 PoC）。

## 执行耗时监控

对应 CLI 的 `-pedm`，用于定位跑得慢或卡住的 PoC：

```go
sdk.WithExecutionMonitor(sdk.ExecutionMonitorOptions{
	SlowThresholdSec: 20, // 超过多少秒算慢任务
	SummaryTop:       10, // 结束时列出最慢的 N 个 PoC
	SummaryBy:        sdk.MonitorSummaryByMax, // 或 MonitorSummaryByAvg
}),
sdk.WithMonitorHandler(func(line string) {
	log.Println(line)
}),
```

监控内容只会送到 `WithMonitorHandler` 注册的回调，SDK 不会打印到控制台。**不注册回调时监控照常运行但输出无处可去**，所以这两个选项应当配套使用。

## 断点续扫

对应 CLI 的 `-resume`。启动时读取检查点跳过已完成的任务，扫描过程中周期性回写：

```go
sdk.WithCheckpoint(sdk.CheckpointOptions{
	Path:         "scan.afg",
	SaveInterval: 10 * time.Second, // 0 表示使用默认的 10 秒
})
```

进度以「PoC id + 目标」为键记录，因此**续扫时目标集与 PoC 集必须与中断前一致**，否则跳过关系会错位。文件不存在时视为全新扫描，不报错。

注意与 `Scanner.Resume()` 区分：后者是解除 `Pause()` 的暂停，与断点续扫无关。

## 从空间测绘获取目标

对应 CLI 的 `-cs` / `-q` / `-qc`。目标可以完全来自搜索，不必再传 `WithTargets`：

```go
scanner, _ := sdk.New(ctx,
	sdk.WithCyberspace(sdk.CyberspaceOptions{
		Engine: sdk.CyberspaceZoomEye,
		Query:  `app:"tomcat"`,
		Count:  100,
	}),
	sdk.WithPocPaths(pocPath),
)
```

目前**只实现了 ZoomEye**，传其他引擎名会返回 `ErrInvalidOptions`。API Key 从配置文件的 `cyberspace.zoom_eyes` 读取，缺失时 `sdk.New` 返回错误。搜索命中为 0 时返回 `ErrNoTargets`。

## 目标预探测

对应 CLI 的 `-mt`。它会在扫描的同时并发探测每个目标的协议与存活情况，错误次数超过 `MaxHostError` 的主机会被拉黑：

```go
sdk.WithTargetPreProbe()
```

尽管 CLI 的参数名叫 monitor-targets，它并**不会**监视目标文件的变化。

## 配置选项完整列表

### 目标

| 选项 | 说明 |
|-----|-----|
| `WithTargets(...)` | 扫描目标列表 |
| `WithTargetsFile(path)` | 目标文件，每行一个 |
| `WithCyberspace(cfg)` | 从空间测绘搜索获取目标（目前仅 ZoomEye） |
| `WithTargetPreProbe()` | 并发预探测目标协议与存活（CLI `-mt`） |

### PoC

| 选项 | 说明 |
|-----|-----|
| `WithPocPaths(...)` | 文件/目录/glob，追加语义 |
| `WithPocPathsOnly()` | 只用显式指定的 PoC |
| `WithSearch(kw)` | 关键词过滤 |
| `WithSeverity(sev)` | 严重程度过滤 |
| `WithExcludePocs(...)` | 排除指定 PoC |
| `WithExcludePocsFile(path)` | 排除列表文件 |

### 性能

| 选项 | 默认值 |
|-----|-------|
| `WithConcurrency(n)` | `25` |
| `WithRateLimit(n)` | `150` |
| `WithTimeout(sec)` | `50` |
| `WithRetries(n)` | `1` |
| `WithMaxHostError(n)` | `3` |
| `WithMaxRespBodySize(mb)` | `2` |
| `WithRequestLimitPerTarget(n)` | `0` |
| `WithPolite()` / `WithBalanced()` / `WithAggressive()` | — |
| `WithAutoRequestLimit()` | — |
| `WithSmartConcurrency()` | — |
| `WithStopOnFirstMatch()` | — |

`WithRequestLimitPerTarget`、`WithAutoRequestLimit`、`WithPolite`、`WithBalanced`、`WithAggressive` 五者互斥，同时设置多个会返回 `ErrInvalidOptions`。

### 指纹与探测

| 选项 | 默认值 |
|-----|-------|
| `WithFingerprintDisabled()` | 指纹默认开启 |
| `WithFingerprintFilterMode(mode)` | `"strict"`（可选 `"opportunistic"`） |
| `WithWebProbe()` | 默认关闭 |

### 网络

| 选项 | 说明 |
|-----|-----|
| `WithProxy(p)` | HTTP/SOCKS5 代理 |
| `WithHeaders(...)` | 自定义请求头，格式 `"Name: value"` |

### 输出

| 选项 | 默认值 |
|-----|-------|
| `WithRequestResponse(b)` | `true` |
| `WithMaxStoredResults(n)` | `0`（不限） |
| `WithStreamBuffer(n)` | `256` |
| `WithRedactedHeaders(...)` | 默认不脱敏 |
| `WithVerbose()` | 默认静默 |

### 敏感信息脱敏

`Exchange` 默认携带完整的原始请求/响应，其中可能包含 `Authorization`、`Cookie`、`Set-Cookie` 等凭证。如果结果会写日志、落库或经 API 返回，应开启脱敏：

```go
sdk.WithRedactedHeaders()                       // 脱敏默认的凭证类头
sdk.WithRedactedHeaders("authorization", "x-token") // 自定义要脱敏的头
```

脱敏会同时作用于 `Exchange.Request`/`Response` 原始报文和 `RequestHeaders`/`ResponseHeaders`，把对应值替换为 `[REDACTED]`，只影响头部、不触碰响应体。脱敏是**可选**的，因为原始报文正是 `Exchange` 的核心价值，默认全脱敏会削弱调试能力。

### 其他

| 选项 | 说明 |
|-----|-----|
| `WithOOB(cfg)` | 带外检测 |
| `WithPortScan(cfg)` | 端口预扫描 |
| `WithCurated(cfg)` | curated PoC 源 |
| `WithTaskTimeout(cfg)` | 单个目标+PoC 任务的超时上限 |
| `WithExecutionMonitor(cfg)` | PoC 执行耗时监控（CLI `-pedm`） |
| `WithMonitorHandler(fn)` | 接收耗时监控输出 |
| `WithCheckpoint(cfg)` | 断点续扫（CLI `-resume`） |
| `WithDingtalk()` / `WithWecom()` | webhook 通知 |
| `WithOptions(o)` | 直接使用一份完整 `Options` |

## API 方法参考

### 构造

| 方法 | 返回值 |
|-----|-------|
| `New(ctx, options...)` | `*Scanner, error` |
| `NewOptions()` | `*Options` |

### 结果

| 方法 | 返回值 |
|-----|-------|
| `Results()` | `[]Result` |
| `ResultCount()` | `int` |
| `HasResults()` | `bool` |
| `OpenPorts()` | `map[string][]int` |
| `Stats()` | `Stats` |
| `Progress()` | `float64` |

### PoC 与信息

| 方法 | 返回值 |
|-----|-------|
| `Pocs()` | `[]poc.Poc` |
| `PocCount()` | `int` |
| `PocDiagnostics()` | `[]config.PocLoadError` |
| `Info()` | `ScanInfo` |
| `OOBStatus()` | `bool, string` |
| `CuratedError()` | `error` |

## 并发限制

**单个扫描器实例是并发安全的**，可以从多个协程调用它的方法。

**但同一进程内不支持多个扫描器并行运行。** HTTP 客户端、限速器和协议探测缓存都是进程级全局状态，并行的扫描器会互相覆盖代理、超时和速率配置。

```go
// 正确：串行复用
for _, group := range targetGroups {
	scanner, _ := sdk.New(ctx, sdk.WithTargets(group...), sdk.WithPocPaths(pocPath))
	if err := scanner.Execute(ctx); err != nil {
		log.Print(err)
	}
	results = append(results, scanner.Results()...)
	scanner.Close()
}
```

## 集成示例

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
	for _, v := range results {
		fmt.Printf("- [%s] %s: %s\n", v.Severity, v.FullTarget, v.PocName)
	}
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

results := scanner.Results() // 超时后仍可获取部分结果
```

### 信号处理

```go
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
defer stop()

scanner.Execute(ctx) // Ctrl+C 会停止扫描并返回 context.Canceled
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

## 示例程序

`examples/` 下的示例均可直接运行，PoC 路径会自动定位到仓库内的 `pocs/afrog-pocs`，也可用 `-pocs` 覆盖：

```bash
go run ./examples/basic_scan
go run ./examples/full_output -json
go run ./examples/async_scan
go run ./examples/progress_scan
go run ./examples/oob_scan -oob dnslogcn -oob-domain your.dnslog.cn
go run ./examples/sdk_portscan -target 127.0.0.1
go run ./examples/vuln_scan -target https://example.com
go run ./examples/port_scan -targets 127.0.0.1
```

## 常见问题

### 指定了 PoC 目录，为什么内置 PoC 没有执行？

你可能加了 `WithPocPathsOnly()`。去掉它即可与内置 PoC 合并。

### 扫描卡住不动了？

检查是否订阅了某个流却没有消费。订阅后的流写满会阻塞扫描，这是为了不丢弃漏洞。

### 为什么 `Wait` 返回 `context.Canceled`？

扫描被 `Stop()` 或外部 context 取消了。此时仍可通过 `Results()` 获取已发现的结果。

### 大规模扫描内存增长过快？

```go
sdk.WithRequestResponse(false),
sdk.WithMaxStoredResults(1000),
```

配合回调实时处理结果，不要依赖 `Results()` 累积。

## 许可证

MIT License
