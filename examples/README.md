# afrog SDK Examples / SDK 示例

Every example is runnable as-is. The PoC directory is resolved relative to the
repository, not to your current working directory, so these commands work from
anywhere:

每个示例都可以直接运行。PoC 目录是相对仓库定位的，而不是相对当前工作目录，
所以下面的命令在任何目录下都能执行：

```sh
go run ./examples/basic_scan
go run ./examples/full_output -json
go run ./examples/async_scan
go run ./examples/progress_scan
go run ./examples/sdk_portscan -target 127.0.0.1
go run ./examples/vuln_scan -target https://example.com
go run ./examples/port_scan -targets 127.0.0.1
go run ./examples/oob_scan -oob dnslogcn -oob-domain your.dnslog.cn
```

Use `-h` on any example to see its flags. `-pocs` overrides the PoC source and
accepts a file, a directory or a glob pattern:

任何示例都可以用 `-h` 查看参数。`-pocs` 用于覆盖 PoC 来源，
支持单个文件、目录和 glob 通配符：

```sh
go run ./examples/basic_scan -pocs /path/to/poc.yaml
go run ./examples/basic_scan -pocs /path/to/pocs
go run ./examples/basic_scan -pocs '/path/to/pocs/*.yaml'
```

## What each example shows / 各示例演示内容

| Example | Shows | 演示内容 |
|---------|-------|---------|
| [basic_scan](basic_scan) | Minimal scan, PoC introspection | 最小可用程序、PoC 加载检查 |
| [full_output](full_output) | Raw request/response, JSON output, failure callback | 原始请求响应、JSON 输出、失败回调 |
| [async_scan](async_scan) | `Start`/`Wait`/`Done`, result streaming, progress | 异步执行、流式结果、进度 |
| [progress_scan](progress_scan) | Progress bar driven by `GetProgress` | 基于 `GetProgress` 的进度条 |
| [oob_scan](oob_scan) | OOB adapters, identifying OOB findings | OOB 适配器配置、OOB 漏洞识别 |
| [sdk_portscan](sdk_portscan) | Port pre-scan feeding the PoC scan | 端口预扫描并作为 PoC 扫描目标 |
| [vuln_scan](vuln_scan) | CI gate with streaming and non-zero exit | CI 门禁：流式消费 + 非零退出 |
| [port_scan](port_scan) | The `portscan` package standalone | 独立使用 `portscan` 包 |
| [mcp_agent](mcp_agent) | Minimal MCP client: findings → evidence | 最小 MCP 客户端：命中 → 证据 |

## MCP agent / MCP 客户端

[mcp_agent](mcp_agent) drives afrog over MCP Streamable HTTP: it lists findings
and then fetches the replayable evidence of the first one. Start the service
first, since the example is a client:

[mcp_agent](mcp_agent) 通过 MCP Streamable HTTP 驱动 afrog：先列命中，再取
第一条命中的可重放证据。它是客户端，需要先启动服务：

```sh
# Terminal 1 / 终端 1
afrog mcp -listen 127.0.0.1:16870

# Terminal 2 / 终端 2
go run ./examples/mcp_agent -limit 5
```

Pass `-draft <file> -target <url>` to run the draft → verify loop instead
(needs a `safe` policy, since `verify.poc` sends traffic):

传入 `-draft <file> -target <url>` 则走「草稿 → 验证」闭环
（需要 `safe` 及以上策略，因为 `verify.poc` 会发包）：

```sh
go run ./examples/mcp_agent -draft ./draft.yaml -target http://127.0.0.1:8080
```

## Targets / 扫描目标

Examples default to `https://scanme.sh`, a host that permits scanning. **Only
scan systems you are authorised to test.**

示例默认目标是 `https://scanme.sh`，这是一个允许被扫描的测试主机。
**请只扫描你有授权测试的系统。**

## Local test lab / 本地靶场

[vulnweb](vulnweb) contains static pages with matching PoCs in
`vulnweb/pocs`, useful for exercising the scanner without touching any external
host:

[vulnweb](vulnweb) 是一套静态靶场页面，配套的 PoC 在 `vulnweb/pocs`，
可以在不接触任何外部主机的情况下验证扫描器：

```sh
# Serve the lab / 启动靶场
cd examples/vulnweb && python3 -m http.server 8080

# Scan it / 扫描靶场
go run ./examples/basic_scan -target http://127.0.0.1:8080 -pocs ./examples/vulnweb/pocs
```
