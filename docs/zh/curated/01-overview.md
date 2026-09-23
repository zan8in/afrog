---
title: Curated PoC 简介
slug: /docs/curated/overview
lang: zh
summary: 介绍 curated PoC 的定位、与内置 PoC 的区别，以及接入所需的前置条件。
status: published
source: new
last_reviewed: 2026-09-23
---

## 什么是 curated PoC

curated PoC 是 `afrog` 的可授权 PoC 分发能力：PoC 由 curated 服务端统一下发，客户端凭 license 挂载到本地目录，`afrog` 启动时自动加载并参与扫描。

它把「PoC 分发」从「跟着引擎版本一起发布」变成「按授权动态更新」，同时用 license / channel 控制可见范围与更新渠道。

## 与内置 PoC 的区别

| 维度 | 内置 PoC | curated PoC |
| --- | --- | --- |
| 来源 | 随 `afrog` 版本 / 仓库发布 | curated 服务端下发（AFCP 加密包） |
| 更新 | 跟随 `afrog` 版本 | 命中授权后自动检查更新 |
| 分发控制 | 无 | license / channel 控制 |
| 离线 | 自带 | 支持离线 AFCP 包安装 |

## 适用场景

- 需要用 license 控制 PoC 的分发与更新
- 希望本地 PoC 目录自动更新、可回滚、可离线安装
- 不希望把静态对象存储凭据下发到客户端

## 接入需要什么

- 一个 curated 服务端地址（例如 `https://pro-api.example.com`）
- 一个 `license_key`
- `afrog-curated` 可执行文件（负责登录、挂载、更新）

## 本书目录

1. [在 afrog 中使用 curated PoC](./02-usage.md)
2. [afrog-curated 命令参考](./03-tool-reference.md)

> **← 文档首页：** [afrog 文档](../index.md) ｜ **下一篇 →：** [在 afrog 中使用 curated PoC](./02-usage.md)
