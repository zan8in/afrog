<!--
title: 在 afrog 中使用 curated PoC
slug: /docs/curated/usage
lang: zh
summary: 通过 CLI 参数与配置文件在 afrog 中启用、关闭和更新 curated PoC。
status: published
source: new
last_reviewed: 2026-09-23
-->

`afrog` 侧只做一件事：启动时调用 `afrog-curated mount`，把返回的目录通过环境变量 `AFROG_POCS_CURATED_DIR` 交给引擎加载。所以「让 afrog 用上 curated PoC」本质上就是配好 endpoint 与授权。

## 最短路径

1. 准备好 curated 服务端地址与 `license_key`
2. 在 `afrog-config.yaml` 的 `curated` 段填入 `endpoint` 与 `license_key`
3. 正常扫描即可：

```bash
afrog -t https://example.com
```

## CLI 参数

| 参数 | 作用 |
| --- | --- |
| `-curated` | curated 模式：`auto` / `on` / `off` |
| `-curated-endpoint` | 指定 curated 服务端点 |
| `-curated-timeout` | curated mount 超时秒数 |
| `-curated-force-update` | 立即强制检查 curated PoC 更新 |

示例：

```bash
afrog -t https://example.com -curated on -curated-endpoint https://pro-api.example.com
afrog -t https://example.com -curated-force-update
afrog -t https://example.com -curated off
```

## 配置文件

`afrog-config.yaml` 的 `curated` 段：

| 字段 | 类型 | 作用 | 默认值 |
| --- | --- | --- | --- |
| `enabled` | string | 模式：`auto` / `on` / `off` | `auto` |
| `endpoint` | string | curated 服务端点 | 空 |
| `license_key` | string | 授权 key | 空 |
| `channel` | string | 更新渠道 | `stable` |
| `auto_update` | bool | 是否自动检查更新 | `true` |
| `timeout_sec` | int | mount / 调用超时秒数 | `10` |
| `bin` | string | 自定义 `afrog-curated` 二进制路径 | 空 |

更完整的字段说明见 [配置文件说明](../user-guide/05-configuration.md)。

## 启用与关闭的判定规则

- `enabled` 为 `off` / `false` / `0`，**或** `endpoint` 为空 → curated 关闭，并清理本地 `pocs-curated` 目录
- 否则 `afrog` 会在启动时执行 mount，并把挂载目录通过 `AFROG_POCS_CURATED_DIR` 传给引擎

也就是说：`auto` 的实际含义是「只要配了 endpoint 就启用」。

## 环境变量

| 变量 | 作用 |
| --- | --- |
| `AFROG_CURATED_LICENSE_KEY` | 默认 license key，可避免把它写进配置文件 |
| `AFROG_POCS_CURATED_DIR` | 由 `afrog` 在 mount 后设置，引擎据此加载 curated PoC |

## 更新与节流

- 默认每 6 小时最多检查一次更新
- `auto_update: false` 会跳过自动检查（除非显式使用 `-curated-force-update`）
- 需要立刻更新时执行：

```bash
afrog -curated-force-update
```

## 排障

- 启动时出现 `curated mount failed`：先确认 endpoint、license 与网络连通性
- 想让 `afrog` 完全不接触 curated：使用 `-curated off`，或把 `endpoint` 留空
- 更细的命令与本地文件说明见 [afrog-curated 命令参考](./03-tool-reference.md)

> **← 上一篇：** [Curated PoC 简介](./01-overview.md) ｜ **下一篇 →：** [afrog-curated 命令参考](./03-tool-reference.md)
