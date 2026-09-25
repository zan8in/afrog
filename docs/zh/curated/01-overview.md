<!--
title: Curated PoC 简介
slug: /docs/curated/overview
lang: zh
summary: 了解 curated PoC（星球精选）是什么、相比内置 PoC 的优势，以及接入前需要准备什么。
status: published
source: afrog.wiki/Afrog 支持星球PoC自动更新功能.md
last_reviewed: 2026-09-23
-->

## 什么是 curated PoC

curated PoC 是 `afrog` 的可授权 PoC 分发能力，也就是常说的**「星球精选 PoC」**。

加入知识星球后你会获得一个专属 License，`afrog` 在启动时会自动挂载并更新星球最新发布的高危漏洞 PoC。**启动即最新，扫描即实战**——不需要手动下载与解压，漏洞情报库始终保持在最新状态。

它把 PoC 更新从「跟着引擎版本一起发布」变成了「按授权动态更新」。

## 与内置 PoC 的区别

| 维度 | 内置 PoC | curated PoC（星球精选） |
| --- | --- | --- |
| 来源 | 随 `afrog` 版本 / 仓库发布 | 由 curated 服务端下发 |
| 更新 | 跟随 `afrog` 版本 | 启动时自动检查更新 |
| 分发控制 | 无 | license / channel 控制可见范围与更新渠道 |
| 获取方式 | 随引擎自带 | 加入[知识星球](https://t.zsxq.com/lV66x)获取 License |

## 核心特点

- **启动即最新**：只需配置一次 License，之后每次启动都会自动挂载并更新
- **后台静默更新**：默认约每 6 小时检查一次，不占用扫描时间、不影响扫描速度
- **零学习成本**：不引入任何新命令，用法与平时完全一致
- **可临时关闭**：某次任务只想用开源 PoC 时，加一个参数即可关掉，无需改配置

## 接入需要什么

- 一个专属 **License Key**：加入[知识星球](https://t.zsxq.com/lV66x)后获取，是同步精选 PoC 的唯一凭证，请妥善保管
- 较新版本的 `afrog`：建议使用最新版（`afrog -v` 查看当前版本），v3 及之后版本已内置该客户端
- 在 `afrog-config.yaml` 的 `curated` 段中填好配置，见 [配置与使用](./02-usage.md)

> **← 文档首页：** [afrog 文档](../index.md) ｜ **下一篇 →：** [配置与使用](./02-usage.md)
