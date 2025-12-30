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
    *   **Banner Grabbing**：自动抓取端口返回的 Banner 信息。
    *   **协议识别**：内置常见服务指纹（HTTP, SSH, FTP, MySQL, Redis, SMTP, RDP 等），可识别服务类型及版本号。
    *   **通用探测**：对于未发送 Banner 的端口，主动发送通用探针（如 HTTP GET）进行激发。

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
    *   `RateLimit`: 速率/并发限制
    *   `ScanMode`: 扫描模式 (目前默认为 Auto/Connect)

*   **`portscan.ScanResult`**:
    *   `Host`: 目标主机
    *   `Port`: 端口号
    *   `Service`: 识别出的服务名称 (如 ssh, http)
    *   `Version`: 版本号 (如 7.6p1)
    *   `Banner`: 原始 Banner 信息

## 📂 目录结构

*   `scan.go`: 扫描器核心逻辑、并发控制、自适应流控。
*   `iterator.go`: 端口和目标的解析迭代器。
*   `service.go`: 服务指纹识别逻辑。
*   `types.go`: 基础数据结构定义。
