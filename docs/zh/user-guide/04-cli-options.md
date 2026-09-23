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

对目标进行 Web 探测，适合在漏洞扫描前先识别 HTTP(S) 资产。

```bash
afrog -t 192.168.1.0/24 -ps -w
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

自动按单目标动态限速，适合“既想扫得快，又不想把单个目标打挂”的场景。

```bash
afrog -T targets.txt -c 50 -auto-req-limit
```

### `-polite` / `-balanced` / `-aggressive`

这是三种预设的单目标限速策略：

- `-polite`：更保守
- `-balanced`：平衡型
- `-aggressive`：更激进

这几类单目标限速策略与 `-rlt`、`-auto-req-limit` 一样，都更适合在批量扫描时保护单个目标不被压垮。

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

端口预扫描速率限制。

### `-ptimeout`

端口预扫描超时，单位为毫秒。

### `-ptries`

端口预扫描重试次数。

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
afrog -t 192.168.1.0/24 -ps -w
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
