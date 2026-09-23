---
title: 实战技巧
slug: /docs/user-guide/tips
lang: zh
summary: afrog 的高频实战组合：目标输入、资产探测、性能与稳定性、OOB、输出与断点续扫。
status: published
source: new
last_reviewed: 2026-09-23
---

本页不是参数字典，而是把高频参数组合成可以直接照抄的实战用法。完整参数定义见 [CLI 参数总览](./04-cli-options.md)。

## 只关注高危漏洞

```bash
afrog -T targets.txt -S high,critical
```

配合 `-sort severity` 可以让结果按风险等级排序，适合先看重点。

## 从空间测绘直接拉资产

```bash
afrog -cs zoomeye -q "app:'tomcat'" -qc 1000
```

`-cs` 指定空间测绘平台，`-q` 传检索语句，`-qc` 控制拉取数量（默认 100）。使用前需要先在 [配置文件](./05-configuration.md) 的 `cyberspace` 段填好凭据。

## 网段场景先探活再扫描

```bash
afrog -t 192.168.1.0/24 -ps -w
```

- `-ps`：开启端口预扫描，适合 IP、网段和段范围
- `-w`：对目标做 Web 探测，先识别出 HTTP(S) 资产
- `-p`：控制端口范围，支持 `top`、`full`、`80,443,8080`、`1-65535`
- `-Pn`：跳过主机发现，直接进入端口扫描

## 只用自己关心的 PoC

```bash
afrog -t https://example.com -s spring,weblogic   # 关键词筛选（id / name / tags）
afrog -t https://example.com -P ./my-pocs/        # 指定 PoC 文件或目录
afrog -t https://example.com -ap ./extra-pocs/    # 在内置 PoC 之外追加
afrog -t https://example.com -ep log4j            # 排除某类 PoC
```

写或引入新 PoC 前，建议先校验与确认：

```bash
afrog -validate ./pocs/        # 校验 PoC 语法
afrog -pl -s weaver,ecology    # 列出匹配到的 PoC
afrog -pd ssh-weak-login       # 查看单条 PoC 详情
```

## 批量扫描时保护目标

```bash
afrog -T targets.txt -c 50 -auto-req-limit
afrog -T targets.txt -rl 80 -rlt 5
afrog -T targets.txt -mt -balanced
```

- `-c` 并发数，`-rl` 全局每秒请求数（默认 150），`-rlt` 单目标每秒请求数
- `-auto-req-limit` 或 `-polite` / `-balanced` / `-aggressive` 按单目标动态限速
- `-mt` 监控目标存活状态，适合公网或网络波动明显的场景

经验上不建议只靠把 `-c` 调大来提速，更稳妥的做法是并发与限速一起调。

## 无回显漏洞用 OOB

```bash
afrog -t https://example.com -oob ceyeio
```

可用适配器包括 `ceyeio`、`dnslogcn`、`alphalog` 等，需要先在 [配置文件](./05-configuration.md) 的 `reverse` 段填好对应平台凭据。速率与并发可用 `-orl`、`-oc` 控制。

## 输出与自动化

```bash
afrog -T targets.txt -o report.html        # HTML 报告
afrog -T targets.txt -j result.json        # 简要 JSON
afrog -T targets.txt -ja result_full.json  # 含请求与响应的完整 JSON
```

少量场景下的输出控制：

- `-silent`：尽量只输出结果
- `-live-stats`：单行实时统计
- `-nc`：关闭 ANSI 彩色输出
- `-doh`：禁用自动生成 HTML 报告

## 长任务断点续扫

```bash
afrog -T big-targets.txt -resume resume.afg
```

中断后带上同一个 `-resume` 文件即可继续，适合大批量目标的长时间扫描。

## 排障

```bash
afrog -t https://example.com -debug   # 输出更多调试信息
afrog -t https://example.com -nf      # 跳过指纹阶段，快速验证
afrog -t https://example.com -test    # 测试模式，会禁用 requires 门控
```

`-nf` 和 `-test` 都会影响依赖 `requires` 的门控行为，不建议作为常规扫描模式。

## 通知与 Web 服务

```bash
afrog -web         # 启动 Web 服务
afrog -dingtalk    # 启动钉钉 webhook 服务
afrog -wecom       # 启动企业微信 webhook 服务
```

通知的触发级别与 token 在 [配置文件](./05-configuration.md) 的 `webhook` 段配置。

> **← 上一篇：** [输出与报告](./06-output-and-report.md) ｜ **本手册首页：** [afrog 简介](./01-overview.md) ｜ **文档首页 →：** [afrog 文档](../index.md)
