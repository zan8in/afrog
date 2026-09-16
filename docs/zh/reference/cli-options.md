---
title: CLI 参数总览
slug: /docs/reference/cli-options
lang: zh
summary: afrog 命令行参数的权威参考页。
status: published
source: docs/README_CN.md, docs/tutorial/rumen-dao-rutu/02-cli-usage.md
last_reviewed: 2026-09-16
---

本页用于收敛 `afrog` 最常用的一组命令行参数，并作为后续完整参数参考的入口页。当前先覆盖高频参数和推荐组合。

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

- 关键字：`top`、`full`、`all`
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

```bash
afrog -t http://example.com -S high,critical
```

### `-ep`

排除某类 PoC。

```bash
afrog -t http://example.com -ep log4j
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

- [输出与报告](../user-guide/output-and-report.md)

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

### `-H`

添加全局请求头。

```bash
afrog -t http://example.com -H 'X-Forwarded-For: 1.1.1.1' -H 'Cookie: a=b'
```

### `-c`

控制并发数。

```bash
afrog -T targets.txt -c 50
```

经验上，不建议只靠把 `-c` 调得特别大来提速。更稳妥的方式是配合全局和单目标限速策略一起调整。

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

## Webhook

### `-wecom`

命中漏洞后推送到企业微信群机器人。

```bash
afrog -T targets.txt -wecom
```

### `-dingtalk`

命中漏洞后推送到钉钉机器人。

```bash
afrog -T targets.txt -dingtalk
```

Webhook token 需要先写入配置文件，见：

- [配置文件说明](../user-guide/configuration.md)

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

当前页面先覆盖高频参数。更细的参数列表、默认值和边界行为，后续会继续扩展；如果你想先查看最完整的参数集合，可以直接运行：

```bash
afrog -h
```
