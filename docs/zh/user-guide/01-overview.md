<!--
title: afrog 简介
slug: /docs/user-guide/overview
lang: zh
summary: 使用指南开篇：afrog 是什么、能做什么，以及这本手册的阅读路线。
status: published
source: new
last_reviewed: 2026-09-23
-->

## afrog 是什么

`afrog` 是一个高性能安全扫描工具，面向漏洞赏金、渗透测试和红队场景。它把目标探测、内置漏洞检查、自定义 PoC 编写和 SDK 自动化整合在同一套 Go 工作流里。

### afrog 能做什么

- 面向 Web 目标和网络服务做快速、聚焦的扫描
- 在漏洞验证中同时使用内置 PoC 和自定义 PoC
- 通过精确的规则设计降低误报噪音
- 灵活集成到 Go 程序、自动化流程和私有 PoC 流水线

## 这本手册覆盖什么

《使用指南》覆盖把 `afrog` 用起来所需的全部内容：安装、第一次扫描、CLI 命令、配置文件、输出与报告，以及常用实战技巧。

- 想写自己的 PoC，请转读 [PoC 编写指南](../poc/01-quickstart.md)
- 想把 `afrog` 集成进程序，请转读 [SDK 使用指南](../sdk/01-quickstart.md)

## 本书目录

1. [安装](./02-install.md)
2. [第一次扫描](./03-first-scan.md)
3. [CLI 参数总览](./04-cli-options.md)
4. [配置文件说明](./05-configuration.md)
5. [输出与报告](./06-output-and-report.md)
6. [实战技巧](./07-tips.md)

## 最短起步

装好之后，一条命令就能完成第一次扫描：

```bash
afrog -t https://example.com
```

从 [安装](./02-install.md) 开始往下读即可。

> **← 文档首页：** [afrog 文档](../index.md) ｜ **下一篇 →：** [安装](./02-install.md)
