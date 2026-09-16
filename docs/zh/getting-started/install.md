---
title: 安装
slug: /docs/getting-started/install
lang: zh
summary: 介绍 afrog 的安装方式、运行前提和版本确认方法。
status: draft
source: docs/README_CN.md
last_reviewed: 2026-09-15
---

`afrog` 支持二进制安装、源码构建和 `go install` 三种方式。对大多数用户来说，优先建议直接使用发布版本。

## 前置要求

- [Go](https://go.dev/) 1.19 或更高版本

如果只是使用编译好的二进制文件，可以不预先安装 Go；如果需要源码构建或 `go install`，则必须先准备好 Go 环境。

## 安装方式

### 方式一：下载发布版本

适合绝大多数使用者。

```bash
https://github.com/zan8in/afrog/releases/latest
```

从发布页下载与本机系统匹配的可执行文件后，放到 `PATH` 中可直接使用。

### 方式二：源码构建

适合需要本地调试、修改源码或参与开发的场景。

```bash
git clone https://github.com/zan8in/afrog.git
cd afrog
go build cmd/afrog/main.go
./afrog -h
```

### 方式三：使用 Go 安装

适合熟悉 Go 的开发者。

```bash
go install -v github.com/zan8in/afrog/v3/cmd/afrog@latest
```

安装完成后，确保 `$GOBIN` 或 `$GOPATH/bin` 已加入 `PATH`。

## 安装后验证

最直接的方式是查看帮助信息：

```bash
afrog -h
```

如果命令可执行并输出参数说明，说明安装已经成功。

## 常见问题

### 找不到 `afrog` 命令

通常是因为可执行文件不在 `PATH` 中。请检查：

- 二进制文件是否放到了系统可执行目录
- `go install` 的输出目录是否已加入 `PATH`

### `go build` 或 `go install` 失败

优先检查：

- Go 版本是否满足要求
- 网络环境是否能正常下载依赖
- 当前仓库是否处于可编译状态

## 下一步

安装完成后，建议继续阅读：

- [第一次扫描](./first-scan.md)
- [CLI 参数总览](../reference/cli-options.md)
