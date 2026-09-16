---
title: 输出与报告
slug: /docs/user-guide/output-and-report
lang: zh
summary: 介绍 afrog 的控制台输出、HTML 报告、JSON 输出和截图能力。
status: published
source: docs/README_CN.md
last_reviewed: 2026-09-16
---

`afrog` 支持控制台输出、HTML 报告、JSON 文件和更完整的 `JsonAll` 输出，既能满足人工查看，也适合自动化集成。

## 默认输出

不额外指定参数时：

- 控制台会输出扫描过程和命中结果
- 如果发现漏洞，会自动生成 HTML 报告

最常见的启动方式：

```bash
afrog -t https://example.com
```

## HTML 报告

HTML 报告适合人工查看和归档，是 `afrog` 最直观的结果展示形式之一。

适合场景：

- 单次目标验证
- 漏洞复核
- 交付给测试或运营同事查看

## JSON 输出

可选参数：

- `-json`
- `-j`

这两个参数会将扫描结果保存到 JSON 文件。默认包含的字段以结果概要为主，例如：

- `target`
- `fulltarget`
- `id`
- `info`

其中 `info` 常见包含：

- `name`
- `author`
- `severity`
- `description`
- `reference`

示例：

```bash
afrog -t https://example.com -json result.json
afrog -t https://example.com -j result.json
```

## JsonAll 输出

可选参数：

- `-json-all`
- `-ja`

与 `-json` 相比，`-json-all` 会把更完整的请求与响应内容也写入结果文件。

示例：

```bash
afrog -t https://example.com -json-all result.json
afrog -t https://example.com -ja result.json
```

如果你需要：

- 自动化平台二次处理
- 自定义告警
- 审计请求与响应证据

优先考虑 `JsonAll`。

## 关于 JSON 文件的一个注意点

扫描过程中，JSON 文件会实时写入。也就是说，在扫描尚未完成时，如果你提前解析这个文件，可能需要自己补上尾部的 `]`，否则解析器可能报错。

如果等扫描完成后再读取，就不会遇到这个问题。

## 截图

`afrog` 也支持将结果配合截图展示，适合需要更强可读性的场景。

## 选型建议

如果你主要关注：

- 人工查看：优先 HTML 报告
- 程序集成：优先 `-json` 或 `-json-all`
- 调试与证据保留：优先 `-json-all`

## 相关文档

- [第一次扫描](../getting-started/first-scan.md)
- [SDK 快速开始](../sdk/quickstart.md)
