<!--
title: CLI 参数总览
slug: /docs/user-guide/cli-options
lang: zh
summary: afrog 命令行参数的权威参考页。
status: published
source: docs/README_CN.md, docs/tutorial/rumen-dao-rutu/02-cli-usage.md
last_reviewed: 2026-09-16
-->

本页用于沉淀 `afrog` 当前 CLI 的主要参数分组、常用写法和关键默认值，目标是让它既能作为高频总览，也能作为站内参数字典来查。

## 最常用的起步命令

| 场景 | 推荐命令 |
| --- | --- |
| 单个 URL 扫描 | `afrog -t http://example.com` |
| 批量 URL 扫描 | `afrog -T targets.txt` |
| 只扫高危 | `afrog -T targets.txt -S high,critical` |
| 指定自定义 PoC | `afrog -t http://example.com -P ./pocs/` |
| 导出 JSON | `afrog -t http://example.com -j result.json` |
| 导出完整 JSON | `afrog -t http://example.com -ja result.json` |

## 目标输入

### `-t`

指定单个目标，适合：

- 单个 URL
- 单个主机
- 单个网段 / 段范围

示例：

```bash
afrog -t https://example.com
afrog -t 192.168.1.100
afrog -t 192.168.1.0/24 -ps
```

### `-T`

从文件中读取多个目标，一行一个。

```bash
afrog -T targets.txt
```

### `-cs`

启用空间测绘输入源，例如：

```bash
afrog -cs zoomeye
```

适合你希望先从空间测绘平台拉取资产，再继续走 afrog 扫描流程的场景。

### `-q`

为空间测绘查询提供检索语句，例如：

```bash
afrog -cs zoomeye -q "app:'tomcat'"
```

### `-qc`

控制空间测绘结果数量，默认值为 `100`。

```bash
afrog -cs zoomeye -q "app:'tomcat'" -qc 1000
```

### `-ps`

开启端口预扫描，适合 IP、网段和段范围输入。

```bash
afrog -t 192.168.1.0/24 -ps
```

### `-w`

在漏洞扫描前先做一轮 Web 资产信息收集：识别 HTTP(S) 资产，并输出 URL、状态码、标题、Server 与技术栈指纹（如 `php`、`apache`、`thinkphp`），让安全工程师先对目标资产有直观认知。

**该阶段默认开启**，想关掉用 `-w=false`：

```bash
afrog -t 192.168.1.0/24 -ps           # 默认已含 Web 探测
afrog -t 192.168.1.0/24 -ps -w=false  # 显式关闭
```

Web 探测的结果同时决定漏洞扫描阶段 HTTP PoC 打哪些目标：端口扫描配合 `-ps` 时，端口指纹已判定不是 HTTP(S) 的 `host:port`（如 `22`/`3306`/`6379`，以及 `465`/`993`/`995` 这类 TLS 但非 Web 的服务）不会进入 HTTP PoC 的目标池，TCP/SSL 类 PoC 照旧覆盖全部端口。这样 `-p all` 扫出的非 Web 端口不会再让每个 HTTP 任务都等到超时。

`-w=false` 时不做这层门控，HTTP PoC 照旧打到所有目标上。被挡掉的目标数可以通过 `-debug` 查看（`vuln-scan gated non-http-targets=N`）。

### `-w-timeout`

控制 Web 探测阶段单次请求与证书获取的超时（秒），默认 `30`。

它与全局 `-timeout` 相互独立：全局超时管 PoC 请求，`-w-timeout` 只管探测阶段。目标响应慢时可以单独调大，而不必放宽整个扫描的超时。真实的共享主机 / 中间设备常在 10s 后才吐出响应头，因此默认值不宜过紧。

```bash
afrog -t http://example.com -w -w-timeout 30
```

### `-w-favicon`

在 Web 探测阶段额外抓取 favicon 并计算 hash，用于识别同一套资产或不易从标题暴露的应用。**默认关闭**，开启后每个目标会多一次请求。

```bash
afrog -t http://example.com -w -w-favicon
```

### `-p`

控制预扫端口范围，支持：

- 关键字：`top`、`full`
- 逗号分隔端口
- 端口范围

```bash
afrog -t 192.168.1.100 -ps -p 80,443,8080
afrog -t 192.168.1.100 -ps -p 1-65535
```

### `-Pn`

跳过主机发现阶段，直接进行端口扫描。

```bash
afrog -t 192.168.1.0/24 -ps -Pn
```

## PoC 选择与过滤

### `-P`

指定单个 PoC 文件或目录。

```bash
afrog -t http://example.com -P ./pocs/test.yaml
afrog -t http://example.com -P ./pocs/
```

### `-ap`

在内置 PoC 之外追加自定义 PoC。

```bash
afrog -t http://example.com -ap ./my-pocs/
```

### `-pocmigrate`

将旧版 PoC 迁移为当前语法，支持单文件或目录。

```bash
afrog -pocmigrate ./legacy-pocs/
```

### `-s`

按关键词筛选 PoC，常匹配 `id`、`name`、`tags`。

```bash
afrog -t http://example.com -s spring,weblogic
```

### `-S`

按风险等级筛选。常见等级：

- `info`
- `low`
- `medium`
- `high`
- `critical`
- `unknown`

```bash
afrog -t http://example.com -S high,critical
```

### `-sort`

控制扫描排序方式，目前支持：

- `severity`
- `a-z`

```bash
afrog -T targets.txt -sort severity
```

### `-ep`

排除某类 PoC。

```bash
afrog -t http://example.com -ep log4j
```

### `-epf`

从文件中读取需要排除的 PoC 列表。

```bash
afrog -t http://example.com -epf ./exclude.txt
```

### `-pl`

列出匹配到的 PoC。

```bash
afrog -pl -s weaver,ecology
```

### `-pd`

查看指定 PoC 详情。

```bash
afrog -pd ssh-weak-login
```

### `-validate`

验证 PoC 语法，适合在编写或批量引入新 PoC 时使用。

```bash
afrog -validate ./pocs/
```

## 输出参数

### `-o`

指定 HTML 报告输出路径。

```bash
afrog -t http://example.com -o ./result/my_scan.html
```

### `-json` / `-j`

输出简要 JSON 结果。

```bash
afrog -t http://example.com -j result.json
```

### `-json-all` / `-ja`

输出包含请求与响应的完整 JSON 结果。

```bash
afrog -t http://example.com -ja result_full.json
```

更详细的结果说明见：

- [输出与报告](./06-output-and-report.md)

## 调试与排障

### `-debug`

输出更多调试信息。

```bash
afrog -t http://example.com -debug
```

### `-nf`

跳过指纹阶段。适合临时快速验证某些漏洞 PoC，但会影响依赖 `requires` 的门控行为。

```bash
afrog -t http://example.com -nf
```

### `-resume`

从断点续扫文件恢复任务。

```bash
afrog -resume resume.afg
```

## 网络与性能

### `-timeout` / `-retries`

控制超时和重试次数。

```bash
afrog -t http://example.com -timeout 60 -retries 2
```

### `-proxy`

通过代理发起请求。

```bash
afrog -t http://example.com -proxy http://127.0.0.1:8080
```

`-proxy` 支持：

- 逗号分隔的多个代理
- 文件输入
- HTTP / SOCKS5 代理

### `-H`

添加全局请求头。

```bash
afrog -t http://example.com -H 'X-Forwarded-For: 1.1.1.1' -H 'Cookie: a=b'
```

### `-http-default-accept`

当 PoC 本身没有显式设置 `Accept` 头时，自动补上 `Accept: */*`。当前默认值为 `true`。

### `-c`

控制并发数。

```bash
afrog -T targets.txt -c 50
```

经验上，不建议只靠把 `-c` 调得特别大来提速。更稳妥的方式是配合全局和单目标限速策略一起调整。

### `-rl`

控制全局每秒请求数，默认值为 `150`。

```bash
afrog -T targets.txt -rl 80
```

### `-rlt`

控制单目标（`host:port`）每秒请求数，`0` 表示禁用。

```bash
afrog -T targets.txt -rlt 5
```

### `-smart`

根据目标数量和运行环境自动调整并发策略。

```bash
afrog -T targets.txt -smart
```

### `-mt`

监控目标存活状态，适合公网或网络波动明显的场景。

```bash
afrog -T targets.txt -mt
```

### `-auto-req-limit`

**默认开启**。按单目标（`host:port`）动态限速：起始速率与 `-rl` 挂钩并按并发做保守收敛，运行期用双向 AIMD 依据失败率与响应时延升降——健康目标会一路加性提速（上限与 `-rl` 同量级，基本不受限），劣化目标会被乘性压低。这样“既想扫得快，又不想把单个目标打挂”无需额外配置。

```bash
# 默认即启用，无需显式指定
afrog -T targets.txt -c 50

# 显式关闭，恢复完全依赖 -rl 的旧行为
afrog -T targets.txt -auto-req-limit=false
```

### `-polite` / `-balanced` / `-aggressive`

这是三种预设的单目标限速策略：

- `-polite`：更保守
- `-balanced`：平衡型
- `-aggressive`：更激进

这几个档位与 `-rlt`、`-auto-req-limit` 互斥（最多生效一个），都更适合在批量扫描时保护单个目标不被压垮。不指定任何档位与 `-rlt` 时，默认走 `-auto-req-limit` 的自适应策略。

档位同时决定端口预扫描的连接速率上限（见 `-pcps`）：`-polite` 为 `200/20`，`-balanced`（默认）为 `1000/100`，`-aggressive` 不限速。

### `-mhe`

单个主机累计错误上限，超过后跳过该主机。默认值为 `3`。

```bash
afrog -T targets.txt -mhe 5
```

### `-mrbs`

HTTP 响应体大小上限，单位为 MB，默认值为 `2`。

```bash
afrog -t https://example.com -mrbs 4
```

### `-brute-max-requests`

控制单条 brute 规则允许发出的最大请求数，默认值为 `5000`，`0` 表示禁用限制。

```bash
afrog -t https://example.com -brute-max-requests 1000
```

## OOB

### `-oob`

指定带外平台适配器，例如：

```bash
afrog -t https://example.com -oob ceyeio
afrog -t https://example.com -oob dnslogcn
afrog -t https://example.com -oob alphalog
```

### `-orl`

带外 PoC 的每秒请求速率上限，默认值为 `25`。

### `-oc`

带外 PoC 的并发上限，默认值为 `25`。

### `-oob-poll-interval`

带外结果轮询间隔，单位为秒，默认值为 `2`。

### `-oob-hit-retention`

带外命中记录保留时间，单位为分钟，默认值为 `10`。

### `-oob-finalize-timeout`

带外最终等待时间，单位为秒。`-1` 表示沿用 pending timeout（运行时会限制在 `5-60` 秒范围内），`0` 表示不等待。

## 阶段控制

### `-prate`

端口预扫描的全局并发上限（工作池大小），不是每秒请求数。默认值为 `500`。

实际生效值还会受本机文件描述符上限约束：启动时先尝试把 `ulimit -n` 的软上限提到硬上限，再按剩余预算把池子收敛到 `min(-prate, 预算)`；收敛时打印一行 `[WRN] port-scan fd-limit ...` 说明原因。详见 [实用技巧](./07-tips.md)。

### `-pcps`

端口预扫描的全局连接速率上限，单位为「每秒新建立的连接数」。默认跟随档位：`-balanced`（默认档）为 `1000`，`-polite` 为 `200`，`-aggressive` 不限速；`-pcps 0` 表示显式不限速，`-pcps <正数>` 表示显式指定。

并发（`-prate`）与速率（`-pcps`）是两个正交的维度：并发管「同时有多少条连接在飞」，速率管「每秒新开多少条连接」。只限并发是不够的——几百个并发在低延迟的内网里意味着每秒数十万次连接尝试，会把出口设备（家用/办公路由器）的 NAT/conntrack 会话表打满；被过滤的端口不回包，表项要挂到 30~120 秒超时才释放，表满之后同一网络里所有人的新建连接都会失败。默认上限就是为了避免这种情况。

### `-pcps-host`

端口预扫描针对单个目标的连接速率上限（每秒）。默认跟随档位：`-balanced` 为 `50`，`-polite` 为 `20`，`-aggressive` 不限速；语义与 `-pcps` 一致。

### `-ps-link-probe`

是否在端口预扫描期间周期性测量到默认网关的 RTT，默认为 `true`。网关 RTT 抬升说明本机出口链路已被压满，此时扫描会自动降速并在终端打印一行 `[WRN] port-scan throttled ...`；链路恢复后再逐步提速。用 `-ps-link-probe=false` 关闭。

### `-ptimeout`

端口预扫描超时，单位为毫秒。默认值为 `1000`。

### `-ptries`

端口预扫描的单端口重试次数。默认值为 `1`：只对「超时」的端口重试，收到 RST（端口确实关闭）会立即返回，因此常规目标的耗时基本不变。首次 SYN 常因瞬时丢包、ARP 冷启动、目标或中间设备的端口扫描防护被静默丢弃，不重试就等于把一个真实开放端口永久记成 closed/filtered，所以默认保留一次机会。追求速度时可用 `-ptries 0` 关闭。

### `-ps-s4-chunk`

当 `ports=full` 时控制端口预扫描分块大小，默认值为 `1000`。

### `-fingerprint-filter-mode`

控制应用类 PoC 的指纹过滤模式，目前支持：

- `strict`
- `opportunistic`

默认值为 `strict`。

### `-vsb`

一旦发现漏洞立即停止扫描并直接报告结果。适合你只关心“是否命中”，而不关心继续扫完整批目标的场景。

## 输出控制补充

### `-doh`

禁用自动生成 HTML 报告，优先级高于 `-o`。

### `-nc`

禁用 ANSI 彩色输出。

### `-silent`

尽量只输出结果。

### `-live-stats`

以单行状态的方式实时渲染统计信息。

## PEDM 与任务超时

PEDM（PoC Execution Duration Monitor）用于观测 PoC 执行时长、慢任务和任务级超时。

### `-pedm`

启用 PEDM。

### `-pedm-log-limit`

打印前 N 条已启动任务日志，`0` 表示禁用。

### `-pedm-slow-sec`

当任务执行时间超过该秒数时输出慢任务日志，默认值为 `30`。

### `-pedm-slow-log-limit`

慢任务完成日志输出上限，默认值为 `20`。

### `-pedm-summary-top`

扫描结束时输出最慢的前 N 项汇总，默认值为 `10`。

### `-pedm-summary-by`

PEDM 汇总排序方式，目前支持：

- `max`
- `avg`

### `-task-hard-timeout-sec`

单个“目标 + PoC”任务的硬超时时间，单位为秒，`0` 表示禁用。

### `-task-smart-timeout`

根据 PoC 内容估算任务超时，并把它作为主要的硬超时策略。

### `-task-timeout-visible-cap-sec`

普通 HTTP PoC 的智能超时上限，默认值为 `300`。

### `-task-timeout-net-cap-sec`

`tcp/udp/ssl` PoC 的智能超时上限，默认值为 `360`。

### `-task-timeout-go-cap-sec`

Go PoC 的智能超时上限，默认值为 `420`。

## 调试工具补充

### `-test`

测试模式，会禁用 requires gating。适合排查 PoC 行为，但不建议把它当作常规扫描模式。

### `-v` / `-version`

显示 afrog 版本。

## 服务与集成

### `-web`

启动 Web 服务。

### `-dingtalk`

启动钉钉 webhook 服务。

### `-wecom`

启动企业微信 webhook 服务。

## 配置

### `-config`

指定 afrog 配置文件路径。

```bash
afrog -config ./afrog-config.yaml -t https://example.com
```

## Curated

### `-curated`

控制 curated pocs 模式，目前支持：

- `auto`
- `on`
- `off`

### `-curated-endpoint`

指定 curated 服务端点。

### `-curated-timeout`

控制 curated mount 超时时间，单位为秒。

### `-curated-force-update`

立即强制检查 curated pocs 更新。

## 更新

### `-un` / `-update`

将 afrog 引擎更新到最新发布版本。

### `-duc` / `-disable-update-check`

禁用自动更新检查。

## 推荐组合

### 单目标快速扫描

```bash
afrog -t https://example.com
```

### 批量高危扫描

```bash
afrog -T targets.txt -S high,critical
```

### 网段资产探测 + Web 探测 + 漏扫

```bash
afrog -t 192.168.1.0/24 -ps        # Web 探测默认已包含，关闭用 -w=false
```

### 批量稳定扫描

```bash
afrog -T targets.txt -mt -auto-req-limit
```

## 说明

本页已经按当前 `afrog -h` 的主要分组补齐了核心参数；如果你需要以运行时实际输出为准，仍然建议同时参考：

```bash
afrog -h
```

> **← 上一篇：** [第一次扫描](./03-first-scan.md) ｜ **本手册首页：** [afrog 简介](./01-overview.md) ｜ **下一篇 →：** [配置文件说明](./05-configuration.md)
