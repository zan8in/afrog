<!--
title: 输出与报告
slug: /docs/user-guide/output-and-report
lang: zh
summary: 介绍 afrog 的控制台输出、HTML 报告、JSON 输出和截图能力。
status: published
source: docs/README_CN.md
last_reviewed: 2026-09-16
-->

`afrog` 支持控制台输出、HTML 报告、JSON 文件和更完整的 `JsonAll` 输出，既能满足人工查看，也适合自动化集成。

## 输出格式字典

如果你的目标是把 `afrog` 接进平台、脚本或数据管道，最值得先区分的是这三类结果：

| 输出方式 | 参数 | 典型用途 | 粒度 |
| --- | --- | --- | --- |
| 控制台 / HTML | 默认 / `-o` | 人工查看、归档 | 可读性优先 |
| `JSON` 摘要输出 | `-json` / `-j` | 自动化处理、轻量告警 | 结果级摘要 |
| `JsonAll` 详细输出 | `-json-all` / `-ja` | 保留请求响应证据、审计 | 结果级摘要 + 请求响应 |

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

### `-json` 字段字典

`-json` / `-j` 对应源码里的 `pkg/report/json.go`。每个结果项的结构如下：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `isvul` | bool | 是否命中漏洞 |
| `target` | string | 原始目标 |
| `fulltarget` | string | 带协议、端口或归一化后的完整目标 |
| `pocinfo` | object | PoC 元信息 |
| `pocresult` | array | 请求响应数组；普通 `-json` 下通常为空 |
| `extractor` | object | extractor 提取出的命名字段 |

`pocinfo` 内部字段如下：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | PoC ID |
| `infoname` | string | PoC 名称 |
| `infoauthor` | string | 作者 |
| `infoseg` | string | 严重级别 |
| `infodescription` | string | 描述 |
| `inforeference` | string[] | 参考链接 |

这里有一个值得记住的小细节：源码里的 JSON key 目前就是 `infoseg`，不是更直观的 `infoseverity`。如果你写解析器，应该以这个实际键名为准。

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

### `-json-all` 额外字段

`JsonAll` 仍然使用上面的顶层结构，但 `pocresult` 会被填充。它的每个元素包含：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `request` | string | 原始请求报文 |
| `response` | string | 原始响应报文，已按 UTF-8 方向处理 |

也就是说：

- `-json` 更适合做结果摘要和告警
- `-json-all` 更适合做证据留存、复核、调试和二次审计

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

## 一个最小 `-json` 示例

下面是一个简化后的结果项示例：

```json
[
  {
    "isvul": true,
    "target": "https://example.com",
    "fulltarget": "https://example.com:443",
    "pocinfo": {
      "id": "spring-core-rce",
      "infoname": "Spring Core RCE",
      "infoauthor": "afrog",
      "infoseg": "critical",
      "infodescription": "Example description",
      "inforeference": ["https://example.com/advisory"]
    },
    "extractor": {
      "version": "5.3.17"
    }
  }
]
```

## 一个最小 `-json-all` 示例

```json
[
  {
    "isvul": true,
    "target": "https://example.com",
    "fulltarget": "https://example.com:443",
    "pocinfo": {
      "id": "spring-core-rce",
      "infoname": "Spring Core RCE"
    },
    "pocresult": [
      {
        "request": "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n...",
        "response": "HTTP/1.1 200 OK\\r\\nServer: nginx\\r\\n..."
      }
    ]
  }
]
```

## 旧版轻量 JSON 输出

源码里还有一套更轻量的输出结构，定义在 `pkg/output/json.go`，字段只有：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `name` | string | 漏洞名称 |
| `severity` | string | 严重级别 |
| `url` | string | 命中的 URL |

如果你在旧脚本或历史集成里只看到这 3 个字段，通常就是在消费这套轻量结构，而不是 `pkg/report/json.go` 里的新结果模型。

## 截图

`afrog` 也支持将结果配合截图展示，适合需要更强可读性的场景。

## 选型建议

如果你主要关注：

- 人工查看：优先 HTML 报告
- 程序集成：优先 `-json` 或 `-json-all`
- 调试与证据保留：优先 `-json-all`

## 给自动化集成的建议

如果你准备把 `afrog` 当成平台输入源，建议优先按下面的思路设计解析器：

1. 先按数组结果解析
2. 兼容扫描中间态的“缺少结尾 `]`”情况
3. 把 `target`、`fulltarget`、`pocinfo.id`、`pocinfo.infoseg` 当成最稳定的一组索引字段
4. 需要保留证据时再消费 `pocresult`

> **← 上一篇：** [配置文件说明](./05-configuration.md) ｜ **本手册首页：** [afrog 简介](./01-overview.md) ｜ **下一篇 →：** [实战技巧](./07-tips.md)
