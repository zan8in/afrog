---
title: 第一次扫描
slug: /docs/getting-started/first-scan
lang: zh
summary: 帮助新用户在最短路径内完成第一次 afrog 扫描。
status: published
source: docs/README_CN.md
last_reviewed: 2026-09-16
---

这一页只关注一件事：让你在最短路径内跑通一次 `afrog` 扫描，并看到结果。

## 最小可运行命令

默认情况下，`afrog` 会扫描所有内置 PoC；如果发现漏洞，会自动生成以扫描日期命名的 HTML 报告。

```bash
afrog -t https://example.com
```

这里的 `-t` 表示指定单个目标。

## 扫描多个目标

如果你已经有一批 URL，可以使用 `-T` 指定文件：

```bash
afrog -T urls.txt
```

文件中每行写一个目标即可。

## 常见的第一次使用方式

### 只跑自定义 PoC

```bash
afrog -t https://example.com -P mypocs/
```

### 按关键词筛选 PoC

例如只跑 `weblogic` 和 `jboss` 相关内容：

```bash
afrog -t https://example.com -s weblogic,jboss
```

### 按风险等级筛选

例如只关注高危和严重漏洞：

```bash
afrog -t https://example.com -S high,critical
```

支持的等级包括：`info`、`low`、`medium`、`high`、`critical`。

## 扫描完成后会看到什么

- 控制台输出扫描进度和命中结果
- 当前目录下生成 HTML 报告
- 如开启 JSON 输出，还会写出结构化结果文件

输出细节见：

- [输出与报告](../user-guide/output-and-report.md)

## 第一次使用时最常见的警告

如果你看到类似下面的报错：

```text
[ERR] ceye reverse service not set: /home/afrog/.config/afrog/afrog-config.yaml
```

说明你还没有完成 OOB / reverse 配置。某些依赖反连平台的 PoC 无法正常工作时，就会出现这个提示。

处理方式见：

- [配置文件说明](../user-guide/configuration.md)

## 指纹门控要点

弱口令、爆破、默认口令等高成本 PoC，通常只建议在目标命中对应指纹后执行。`afrog` 支持在 PoC `info` 中声明：

- `requires`
- `requires-mode`

当 `requires-mode: strict` 时，如果运行时禁用了指纹阶段，或者目标未命中所需指纹，该 PoC 会被跳过。

完整说明见：

- [PoC 编写快速开始](../poc/quickstart.md)

## 下一步

跑通第一次扫描后，建议继续阅读：

- [CLI 参数总览](../reference/cli-options.md)
- [配置文件说明](../user-guide/configuration.md)
