<!--
title: SDK 快速开始
slug: /docs/sdk/quickstart
lang: zh
summary: 帮助开发者以最短路径将 afrog SDK 集成到自己的程序中。
status: published
source: docs/SDK使用指南_中文.md
last_reviewed: 2026-09-16
-->

`afrog` SDK 适合把漏洞扫描能力嵌入你自己的 Go 程序。当前推荐直接使用 `pkg/sdk` 这套新接口。

## 包路径

推荐入口：

```go
github.com/zan8in/afrog/v3/pkg/sdk
```

如果你已经在用旧的根包 API，也可以继续使用；新接口更适合新项目。

## 安装

```bash
go get -u github.com/zan8in/afrog/v3
```

## 最小示例

```go
package main

import (
  "context"
  "fmt"
  "log"

  "github.com/zan8in/afrog/v3/pkg/sdk"
)

func main() {
  ctx := context.Background()

  scanner, err := sdk.New(ctx,
    sdk.WithTargets("https://example.com"),
    sdk.WithPocPaths("./pocs/afrog-pocs"),
  )
  if err != nil {
    log.Fatal(err)
  }
  defer scanner.Close()

  if err := scanner.Execute(ctx); err != nil {
    log.Fatal(err)
  }

  for _, r := range scanner.Results() {
    fmt.Printf("[%s] %s - %s\n", r.Severity, r.FullTarget, r.PocName)
  }
}
```

这段代码已经展示了最常见的最小集成路径：

1. 创建 `context`
2. 构造扫描器
3. 指定目标和 PoC 来源
4. 执行扫描
5. 读取结果

## PoC 输入

`WithPocPaths` 支持三种常见形式，而且可以混用：

```go
sdk.WithPocPaths(
  "/path/to/single.yaml",
  "/path/to/pocs",
  "/path/to/pocs/*.yaml",
)
```

含义分别是：

- 单个文件
- 目录递归加载
- glob 通配符

## 执行方式

### 同步执行

最简单的方式：

```go
if err := scanner.Execute(ctx); err != nil {
  log.Fatal(err)
}
results := scanner.Results()
```

### 异步执行

如果你需要自行管理进度、订阅状态或并发处理结果，可以使用异步方式：

```go
if err := scanner.Start(ctx); err != nil {
  log.Fatal(err)
}

if err := scanner.Wait(ctx); err != nil {
  log.Printf("扫描出错: %v", err)
}
```

## 结果读取

`Results()` 返回结构化结果，适合直接做后处理或 JSON 序列化。

```go
for _, r := range scanner.Results() {
  fmt.Printf("%s [%s] %s\n", r.PocID, r.Severity, r.FullTarget)
}
```

如果需要更完整的请求与响应信息，结果中的 `Exchanges` 也可以直接使用。

## 内存控制

如果你做大规模集成，可以优先关注这两个选项：

```go
sdk.WithRequestResponse(false)
sdk.WithMaxStoredResults(1000)
```

含义：

- 不保留完整请求响应
- 限制内部累计结果数

## 常见错误

初始化时最常见的错误包括：

- `ErrNoTargets`
- `ErrNoPocs`
- `ErrPocPathNotFound`
- `ErrInvalidOptions`

示例：

```go
scanner, err := sdk.New(ctx, opts...)
switch {
case errors.Is(err, sdk.ErrNoTargets):
  log.Fatal("未指定扫描目标")
case errors.Is(err, sdk.ErrPocPathNotFound):
  log.Fatal("PoC 路径无法解析")
case err != nil:
  log.Fatal(err)
}
```

## 本书目录

- [同步与异步](./02-sync-and-async.md)
- [回调与流](./03-handlers-and-streams.md)
- [配置参考](./04-config-reference.md)
- [API 参考](./05-api-reference.md)
- [示例程序](./06-examples.md)
- [常见问题](./07-faq.md)

> **← 文档首页：** [afrog 文档](../index.md) ｜ **下一篇 →：** [同步与异步](./02-sync-and-async.md)
