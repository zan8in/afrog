<!--
title: 配置文件说明
slug: /docs/user-guide/configuration
lang: zh
summary: 介绍 afrog 配置文件的用途、字段和典型配置方式。
status: published
source: docs/README_CN.md, docs/tutorial/rumen-dao-rutu/03-configuration.md
last_reviewed: 2026-09-16
-->

`afrog` 第一次启动时，会在当前用户目录下自动创建配置文件：

```text
$HOME/.config/afrog/afrog-config.yaml
```

这份配置主要用于管理 OOB / reverse 平台、通知和其他运行期依赖。

## 配置文件字段字典

`afrog-config.yaml` 对应源码里的 `pkg/config/config.go`。顶层字段目前有 7 组：

| 顶层键 | 类型 | 作用 | 默认值 / 说明 |
| --- | --- | --- | --- |
| `server` | string | Web 服务监听地址 | 默认 `:16868` |
| `reverse` | object | OOB / reverse 平台配置 | 按不同 provider 分组 |
| `webhook` | object | 钉钉、企业微信通知 | 默认只创建空模板 |
| `cyberspace` | object | 空间测绘平台配置 | 当前内置 `zoom_eyes` |
| `curated` | object | curated pocs 相关配置 | 默认 `enabled: auto` |
| `cluster` | object | 多实例编排（Web 控制台） | 留空即单实例 |
| `ai` | object | AI 辅助的模型接入 | 留空即未接入 |

下面这部分可以当字段字典直接查。

## 示例配置

```yaml
reverse:
  ceye:
    api-key: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    domain: "xxxxxx.cey2e.io"
  dnslogcn:
    domain: dnslog.cn
  alphalog:
    domain: dnslogxx.sh
    api_url: "http://dnslogxx.sh/"
  xray:
    x_token: "xraytest"
    domain: dnslogxx.sh
    api_url: "http://x.x.0.x:8777"
  revsuit:
    token: "xx"
    dns_domain: "log.xx.com"
    http_url: "http://x.x.x.x/log/"
    api_url: "http://x.x.x.x/helplog"
```

## `reverse` 字段字典

`reverse` 用于配置反连平台，给需要 OOB 证据的 PoC 使用。

### `reverse.ceye`

| 字段 | 类型 | 作用 |
| --- | --- | --- |
| `api-key` | string | Ceye API Key |
| `domain` | string | Ceye 分配给你的域名 |

默认情况下这两个字段都为空，需要手动填写。

### `reverse.dnslogcn`

| 字段 | 类型 | 作用 | 默认值 |
| --- | --- | --- | --- |
| `domain` | string | dnslog.cn 域名 | `dnslog.cn` |

### `reverse.alphalog`

| 字段 | 类型 | 作用 |
| --- | --- | --- |
| `domain` | string | Alphalog 回连域名 |
| `api_url` | string | Alphalog API 地址 |

### `reverse.xray`

| 字段 | 类型 | 作用 | 默认值 |
| --- | --- | --- | --- |
| `x_token` | string | Xray reverse token | 空 |
| `domain` | string | Xray reverse 域名 | 空 |
| `api_url` | string | Xray API 地址 | `http://x.x.x.x:8777` |

### `reverse.revsuit`

| 字段 | 类型 | 作用 |
| --- | --- | --- |
| `token` | string | Revsuit token |
| `dns_domain` | string | DNS 回连域名 |
| `http_url` | string | HTTP 回连地址 |
| `api_url` | string | Revsuit API 地址 |

### `reverse.interactsh`

| 字段 | 类型 | 作用 | 默认值 |
| --- | --- | --- | --- |
| `server` | string | interactsh 服务端域名 | `oast.pro` |
| `token` | string | 私有 interactsh token | 空 |

### `reverse.eye`

| 字段 | 类型 | 作用 |
| --- | --- | --- |
| `host` | string | eye 平台主机 |
| `token` | string | eye token |
| `domain` | string | eye 域名 |

### `reverse.jndi`

| 字段 | 类型 | 作用 |
| --- | --- | --- |
| `jndi_address` | string | JNDI 服务地址 |
| `ldap_port` | string | LDAP 端口 |
| `api_port` | string | API 端口 |

## `webhook` 字段字典

`webhook` 目前支持 `dingtalk` 和 `wecom` 两组配置。

### `webhook.dingtalk`

| 字段 | 类型 | 作用 | 默认值 |
| --- | --- | --- | --- |
| `tokens` | string[] | 钉钉机器人 token 列表 | `[""]` |
| `at_mobiles` | string[] | 需要 @ 的手机号列表 | `[""]` |
| `at_all` | bool | 是否 @ 所有人 | `false` |
| `range` | string | 触发通知的严重级别范围 | `high,critical` |

### `webhook.wecom`

| 字段 | 类型 | 作用 | 默认值 |
| --- | --- | --- | --- |
| `tokens` | string[] | 企业微信机器人 token 列表 | `[""]` |
| `at_mobiles` | string[] | 需要 @ 的手机号列表 | `[""]` |
| `at_all` | bool | 是否 @ 所有人 | `false` |
| `range` | string | 触发通知的严重级别范围 | `high,critical` |
| `markdown` | bool | 是否以 Markdown 消息格式发送 | `true` |

## `cyberspace` 字段字典

### `cyberspace.zoom_eyes`

| 字段 | 类型 | 作用 | 默认值 |
| --- | --- | --- | --- |
| `zoom_eyes` | string[] | ZoomEye 认证信息列表 | `[""]` |

如果你计划使用 `-cs zoomeye`、`-q`、`-qc` 这一类命令行参数，通常就要先把这里配好。

## `curated` 字段字典

| 字段 | 类型 | 作用 | 默认值 |
| --- | --- | --- | --- |
| `enabled` | string | curated 模式，支持 `auto` / `on` / `off` | `auto` |
| `auto_update` | bool | 是否自动更新 curated pocs | `true` |
| `endpoint` | string | curated 服务端点 | 空 |
| `bin` | string | 自定义 curated 二进制路径 | 空 |
| `timeout_sec` | int | curated mount / 调用超时秒数 | `10` |
| `channel` | string | curated 渠道 | `stable` |
| `license_key` | string | 授权 key | 空 |

## `cluster` 字段字典

`cluster` 用于多实例编排：让一个 Web 控制台的「概览」页同时看到多个 `afrog` 实例的运行状态。留空即单实例，控制台照常工作。

| 字段 | 类型 | 作用 | 默认值 |
| --- | --- | --- | --- |
| `name` | string | 本节点的显示名 | 空（界面显示为「本机」） |
| `token` | string | 集群共享密钥：实例之间互访的凭证 | 空（为空时不对外提供实例信息） |
| `peers` | object[] | 同伴实例列表 | 空 |
| `peers[].name` | string | 同伴显示名 | 空（回退为地址） |
| `peers[].url` | string | 同伴的 Web 控制台地址 | — |

```yaml
cluster:
  name: "总部"
  token: "集群共享密钥"
  peers:
    - name: "节点A"
      url: "http://10.0.0.11:16868"
    - name: "节点B"
      url: "http://10.0.0.12:16868"
```

要点：

- 同一集群的节点要配置**相同的 token**；地址不写协议时按 `http://` 处理
- 本实例每 30 秒读取一次同伴的 `/api/cluster/self`，同伴不可达时界面上如实显示原因
- 未配置 `token` 的实例不会对外暴露自身状态，这是默认关闭的安全设计
- 聚合视图是只读的：这一阶段只做状态汇总，不远程派发扫描

## `ai` 字段字典

`ai` 用于「AI 辅助」——让模型结合原始请求与响应复核命中结果（详见 [Web 控制台](./08-web-console.md#ai-研判)）。留空即未接入，界面上会引导你去补齐。只实现 OpenAI 兼容的 `POST {base_url}/chat/completions`，所以换供应商只需改 `base_url` 与 `model`。

| 字段 | 类型 | 作用 | 默认值 |
| --- | --- | --- | --- |
| `base_url` | string | 接口地址，通常以 `/v1` 结尾 | 空 |
| `model` | string | 模型名，例如 `deepseek-chat` | 空 |
| `api_key` | string | 调用凭证 | 空 |
| `timeout_sec` | int | 单次研判的超时秒数 | `60` |
| `max_tokens` | int | 单次输出的 token 上限 | `1200` |

```yaml
ai:
  base_url: "https://api.deepseek.com/v1"
  model: "deepseek-chat"
  api_key: "sk-..."
  timeout_sec: 60
  max_tokens: 1200
```

要点：

- `base_url` / `model` / `api_key` **三项都填齐才算接入**；填完整路径（`.../v1/chat/completions`）也能识别
- 也可以直接在 Web 控制台的「设置 → AI 辅助」里填写，保存后写回本文件并立即生效，无需重启
- 研判是**按次点击才调用**，不会后台自动跑；同一条命中重复查看走本地缓存，不再重复请求
- 发送前会隐藏 `Cookie`、`Authorization`、`Set-Cookie` 等敏感头并截断超长内容，但仍会把这条命中的请求/响应发给你配置的模型服务，请自行评估

## reverse 是什么

`reverse` 用于配置反连平台，主要服务于无法直接回显的漏洞验证场景，比如命令执行、XXE、SSRF 等需要通过 DNS 或 HTTP 外带回证据的 PoC。

当前文档里最常见的配置方式如下。

## Ceye

这是最常见也最容易跑通的配置方式。

### 获取方式

1. 打开 [ceye.io](http://ceye.io/)
2. 注册并登录
3. 在个人设置页复制 `domain` 和 `api-key`
4. 填入 `afrog-config.yaml`

## Dnslog.cn

- 无需复杂配置
- 使用门槛低
- 稳定性相对一般

官网：

- [dnslog.cn](http://dnslog.cn/)

## Alphalog

适合有自建需求的场景。

- 需要自行部署服务
- 项目地址：[alphalog](https://github.com/AlphabugX/Alphalog)

## Xray

如果你已有 Xray 反连环境，也可以接入：

- 文档地址：[xray](https://docs.xray.cool/tools/xray/advanced/reverse)

## Revsuit

同样属于自建型方案：

- 项目地址：[Revsuit](https://github.com/Li4n0/revsuit)
- 参考教程：[教程](https://mp.weixin.qq.com/s/hGwcMz8sh7BImBjI3wHqnQ)

## 常见问题

### 为什么会提示 reverse service not set

如果你在扫描时看到类似下面的报错：

```text
[ERR] ceye reverse service not set: /home/afrog/.config/afrog/afrog-config.yaml
```

通常说明：

- 配置文件还没有创建
- `reverse` 段未填写完整
- 当前 PoC 依赖 OOB，但你没有配置对应平台

### 我能把配置文件放到别的位置吗

可以。CLI 提供了 `-config` 参数，可以显式指定配置文件路径：

```bash
afrog -config ./afrog-config.yaml -t https://example.com
```

如果没有显式传 `-config`，则默认走：

```text
$HOME/.config/afrog/afrog-config.yaml
```

### 配置文件会自动补齐哪些默认项

第一次启动时，`afrog` 会自动写入一份带默认值的模板配置，比较关键的默认值包括：

- `server: ":16868"`
- `reverse.dnslogcn.domain: "dnslog.cn"`
- `reverse.interactsh.server: "oast.pro"`
- `webhook.dingtalk.range: "high,critical"`
- `webhook.wecom.range: "high,critical"`
- `webhook.wecom.markdown: true`
- `curated.enabled: "auto"`
- `curated.auto_update: true`
- `curated.timeout_sec: 10`
- `curated.channel: "stable"`

### 所有 PoC 都必须配置 reverse 吗

不是。只有依赖 OOB / reverse 验证的 PoC 才需要这类配置；普通回显型检测不一定依赖它。

> **← 上一篇：** [CLI 参数总览](./04-cli-options.md) ｜ **本手册首页：** [afrog 简介](./01-overview.md) ｜ **下一篇 →：** [输出与报告](./06-output-and-report.md)
