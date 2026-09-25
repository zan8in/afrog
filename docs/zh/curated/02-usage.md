<!--
title: 配置与使用
slug: /docs/curated/usage
lang: zh
summary: 两步完成 curated PoC（星球精选）配置，然后像平时一样使用 afrog 即可。
status: published
source: afrog.wiki/Afrog 支持星球PoC自动更新功能.md
last_reviewed: 2026-09-23
-->

配置只需两步，之后就可以完全按平时的习惯使用 `afrog`。

## 第一步：准备 License

1. **获取 License**：加入[知识星球](https://t.zsxq.com/lV66x)，获取你的专属 **License Key**（同步精选 PoC 的唯一凭证，请妥善保管）
2. **确认版本**：建议使用最新版 `afrog`，用 `afrog -v` 查看当前版本；v3 及之后版本已内置该客户端

## 第二步：修改配置文件

打开主配置文件：

```text
~/.config/afrog/afrog-config.yaml
```

找到或新增 `curated:` 段，按注释填写必填项：

```yaml
curated:
  # [必填] 功能总开关（建议设为 auto）
  # auto: 自动检测，只要配置正确即开启
  # on:   强制开启
  # off:  关闭此功能
  enabled: "auto"

  # [可选] 自动更新开关（默认 true）
  # 开启后后台会静默检测更新（默认间隔约 6 小时），不影响扫描速度
  auto_update: true

  # [必填] curated PoC 服务端地址（由作者提供）
  # 如无特殊指引，保持作者给出的值即可
  endpoint: "https://your-curated-endpoint"

  # [必填] 你的专属 License Key
  # 直接粘贴，注意不要有多余空格
  license_key: "LIC_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

  # [可选] 通道选择，例如 stable / beta
  channel: "stable"

  # [可选] 加载超时时间（默认 10）
  # 网络环境较差时建议改为 20 或 30
  timeout_sec: 10
```

### 配置项速查

| 配置项 | 必填 | 作用 |
| --- | --- | --- |
| `enabled` | 是 | 控制是否加载 curated PoC。`auto` 最省心，推荐使用 |
| `license_key` | 是 | **鉴权核心**。只有填入正确的 Key 才能拉取到精选 PoC |
| `endpoint` | 是 | curated 服务端地址，一般由作者统一给出，无需频繁修改 |
| `auto_update` | 否 | 设为 `true` 即可享受「无感更新」 |
| `channel` | 否 | 指定更新通道（如 `stable`、`beta`），控制拉取哪一类 PoC 版本 |
| `timeout_sec` | 否 | 与服务端通讯的超时时间，防止网络波动卡住扫描 |

更完整的字段说明（含 `bin` 等进阶字段）见 [配置文件说明](../user-guide/05-configuration.md)。

## 如何使用

### 1. 无感日常使用

配置完成后不需要学习新命令，像往常一样使用即可：

```bash
afrog -t http://example.com
```

你会发现：

- `afrog` 启动时会自动挂载 curated PoC 目录（`~/.config/afrog/pocs-curated`）
- 扫描任务会自动包含最新的精选 PoC
- 一切都在后台完成，无需人工干预

### 2. 强制立即更新

默认每约 6 小时检测一次更新。如果刚看到发布了紧急 0day PoC、不想等待，可以强制更新：

```bash
# 强制检查更新并开始扫描
afrog -t http://example.com -curated-force-update

# 仅做更新检查（不扫描）
afrog -curated-force-update
```

### 3. 临时关闭

某次任务只想用开源 PoC 时，不必改配置文件，加一个参数即可：

```bash
afrog -t http://example.com -curated off
```

## 排障

- 启动时出现 `curated mount failed`：先确认 `endpoint`、`license_key` 是否填写正确，以及网络是否连通
- 长时间没有新 PoC：确认 License 未过期、`channel` 是否为期望的渠道，也可以在配置文件里把 `timeout_sec` 调大
- 想让 `afrog` 完全不接触 curated：使用 `-curated off`，或把 `endpoint` 留空

> **← 上一篇：** [Curated PoC 简介](./01-overview.md) ｜ **文档首页 →：** [afrog 文档](../index.md)
