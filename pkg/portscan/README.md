# PortScan 端口扫描模块

`pkg/portscan` 是 afrog 的独立端口扫描模块，专为资产探测和前置扫描设计。它具备跨平台、自适应、高性能等特点。

## ✨ 功能特点 (Features)

1.  **🛡️ 自适应扫描 (Adaptive Mode)**
    *   **智能流控**：实时监控网络错误率（如连接超时、被重置）。当连续错误超过阈值时，自动降低扫描速率并暂停，有效绕过简单的 WAF 频率限制，防止因扫描过快导致的漏报。
    *   **稳定性优先**：在网络状况不佳时自动调整策略，确保结果准确性。

2.  **🚀 高性能并发 (High Performance)**
    *   基于 `ants` 协程池实现，支持数千并发连接。
    *   资源占用低，自动管理 Goroutine 生命周期。

3.  **🔍 服务指纹识别 (Service Fingerprinting)**
    *   **数据驱动**：探针（probes）、规则（services）、端口先验（ports）三层数据分离，全部为 YAML，改指纹不需要改代码。
    *   **默认识别（被动）**：在已建立的连接上直接读取服务端主动吐出的 Banner，零额外连接、零额外往返。
    *   **主动探针（可选）**：对不主动问候的服务，开启 `ServiceProbes` 后发送应用层 payload（`GET /`、`PING`、`INFO server`、BSON 查询等）激发响应。
    *   **可信度分级**：识别结果带 `Confidence`（`port`/`probable`/`certain`），明确区分「端口惯例推测」与「Banner 实证」。
    *   **正则引擎**：规则使用 .NET 风格正则（lookahead/lookbehind/具名捕获组），带匹配超时保护，可安全承接社区贡献的复杂指纹。

4.  **💻 跨平台兼容 (Cross-Platform)**
    *   采用 TCP Connect Scan（全连接扫描），利用系统原生网络栈。
    *   **无需 Root/Admin 权限**：可在 Windows、Linux、macOS 上直接运行，无依赖。

5.  **🔢 灵活的端口/目标定义**
    *   **端口支持**：
        *   单端口：`80`
        *   列表：`80,443,8080`
        *   范围：`1000-2000`
        *   预设：`top-100` (常见 Top 100 端口), `full` (1-65535)
    *   **目标支持**：支持 IP、域名。

## 📖 使用方法 (Usage)

### 1. 基础调用

```go
package main

import (
	"context"
	"fmt"
	"time"
	"github.com/zan8in/afrog/v3/pkg/portscan"
)

func main() {
    // 1. 配置选项
    opts := portscan.DefaultOptions()
    opts.Targets = []string{"192.168.1.1", "scanme.nmap.org"}
    opts.Ports = "80,443,22,8000-8100,top-100"
    opts.RateLimit = 1000 // 并发限制
    opts.Timeout = 2 * time.Second
    opts.ServiceProbes = true // 可选：开启主动探针，识别不主动吐 Banner 的服务

    // 2. 设置结果回调函数
    opts.OnResult = func(result *portscan.ScanResult) {
        if result.State == portscan.PortStateOpen {
            fmt.Printf("[+] 发现端口: %s:%d | 服务: %s | 版本: %s\n", 
                result.Host, result.Port, result.Service, result.Version)
        }
    }

    // 3. 创建扫描器
    scanner, _ := portscan.NewScanner(opts)

    // 4. 开始扫描
    scanner.Scan(context.Background())
}
```

### 2. 核心结构说明

*   **`portscan.Options`**:
    *   `Targets`: 目标列表 ([]string)
    *   `Ports`: 端口字符串 (如 "80,443,top-100")
    *   `RateLimit`: 全局速率/并发限制
    *   `MaxHostConcurrency`: 单目标并发上限，避免全局并发集中打单台触发目标 SYN 保护
    *   `AdaptiveTimeout`: RTT 自适应连接超时，按实测往返时间收紧首次超时（重试仍用完整预算）
    *   `ServiceProbes`: 是否发送主动探针（默认 false，仅被动抓 Banner）
    *   `FingerprintDir`: 外置指纹目录，提供 `probes.yaml`/`services.yaml`/`ports.yaml` 覆盖内置指纹集
    *   `ScanMode`: 扫描模式 (目前默认为 Auto/Connect)

*   **`portscan.ScanResult`**:
    *   `Host` / `Port` / `State`: 目标主机、端口号与端口状态
    *   内嵌 `ServiceInfo`，可直接访问识别字段：
        *   `Service` / `Product` / `Version` / `Device` / `Hostname` / `OS` / `CPE` / `Info`: 识别出的服务、产品、版本等
        *   `TLS`: 该端口是否为 TLS 服务
        *   `Confidence`: 识别可信度（`port` < `probable` < `certain`）
        *   `RuleID` / `ProbeID`: 命中的规则与探针，便于排查误报
        *   `Banner`: 原始响应（已截断至 2048 字节并做安全化处理）
        *   `Extras`: 规则具名捕获组的额外字段

## 🧬 端口指纹数据与扩展

指纹集分三层，均为 YAML，内置在二进制中（`go:embed`），运行时无需外部文件：

| 文件 | 作用 |
|---|---|
| `fingerprints/probes.yaml` | 探针：一条连接上发送（或不发送）的 payload，`mode` 为 `passive`/`active` |
| `fingerprints/services.yaml` | 规则：在某个探针的响应上用什么正则、能提取出哪些字段；**顺序即优先级**（specific → generic） |
| `fingerprints/ports.yaml` | 端口先验：端口惯例服务名与 `tls` 标记，用于兜底推测与决定是否做 TLS 握手 |

### 覆盖与扩展

提供 `Options.FingerprintDir`（CLI 为 `-ps-fingerprint-dir`）指向自定义目录，目录下的同名文件会与内置集合并，**外置永远优先**：

*   `probes.yaml` 按 `id` 合并，同 id 覆盖内置，新 id 追加；
*   `services.yaml` 的外置规则**整体排在内置规则之前**，保证用户新增的 specific 规则不会被内置通用规则（如 `http`）抢先命中；
*   `ports.yaml` 按端口合并，同端口覆盖内置。

目录下缺少某个文件不是错误；只有文件存在但解析失败才会报错。

## 📂 目录结构

*   `scan.go`: 扫描器核心逻辑、并发控制、自适应流控。
*   `iterator.go`: 端口和目标的解析迭代器。
*   `fingerprint_data.go`: 指纹数据层（内置 embed、外置目录合并、YAML 结构定义与编译校验）。
*   `fingerprint.go`: 识别引擎（探针响应 → 规则命中 → `ServiceInfo`）。
*   `fingerprint_probe.go`: 运行时抓取器（在复用连接上执行被动/主动探针）。
*   `fingerprints/`: 内置指纹集（`probes.yaml`、`services.yaml`、`ports.yaml`）。
*   `types.go`: 基础数据结构定义。
