<!--
title: afrog-curated 命令参考
slug: /docs/curated/tool-reference
lang: zh
summary: afrog-curated 的 login / mount / update / status 等命令、环境变量与本地文件。
status: published
source: new
last_reviewed: 2026-09-23
-->

`afrog-curated` 是 curated PoC 的客户端管理器：负责与服务端交互、下载加密 PoC 包（AFCP）、解密安装到本地目录，并向 `afrog` 输出已挂载的目录路径。

## 命令

### login

向服务端注册设备并获取 token。如果未传 `--endpoint`，只会写入本地状态，不会发起网络登录。

```bash
afrog-curated login --endpoint https://pro-api.example.com --license LIC_xxx
```

### mount

确保本地 curated PoC 目录存在，必要时触发更新检查，最后输出该目录路径。

```bash
afrog-curated mount --endpoint https://pro-api.example.com --channel stable
```

`afrog` 启动时调用的就是这个命令。

### update

两种模式：从服务端拉取更新，或离线安装本地 AFCP 包。

```bash
afrog-curated update --endpoint https://pro-api.example.com --channel stable

afrog-curated update --afcp /path/to/full.afcp \
  --content-key-b64 "<base64_32bytes_key>" \
  --manifest-id "m-xxxx"
```

### status

打印本地状态：license、当前目录、manifest id、最后一次检查 / 更新时间与最后错误。

```bash
afrog-curated status
```

### logout

清理本地登录与运行状态（不会删除已安装的 PoC 目录内容）。

### self-update

通过给定下载 URL 自更新二进制，可选校验 sha256。

```bash
afrog-curated self-update --url "<download_url>" --sha256 "<sha256_hex>"
```

## 常用 Flags

- `--endpoint`：curated 服务端地址
- `--license`：license key（默认读取 `AFROG_CURATED_LICENSE_KEY`）
- `--channel`：渠道，默认 `stable`
- `--curated-dir`：自定义本地安装目录，默认 `~/.config/afrog/pocs-curated`
- `--no-update`：禁用远程更新检查，仅输出目录
- `--force-update`：忽略节流，强制立刻检查更新
- `--timeout`：超时秒数，默认 `10`
- `--afcp` / `--content-key-b64` / `--manifest-id`：离线安装 AFCP 包时使用

## 环境变量

- `AFROG_CURATED_LICENSE_KEY`：默认 license key
- `AFROG_CURATED_DEVICE_FINGERPRINT`：手动指定设备指纹（一般不需要，默认本地生成并缓存）
- `AFROG_CURATED_MANIFEST_PUBKEY_B64`：manifest 签名校验公钥（base64，ed25519）；设置后客户端会校验服务端下发 manifest 的签名

## 本地文件

默认根目录为 `~/.config/afrog/`：

- `pocs-curated/`：解密后的 curated PoC 安装目录
- `curated-auth.json`：登录态（token / 设备信息）
- `curated-device.json`：设备指纹缓存
- `curated-state.json`：运行态（manifest id、最后检查 / 更新时间、最后错误）
- `curated-cache/`：下载缓存（AFCP 临时文件）

> **← 上一篇：** [在 afrog 中使用 curated PoC](./02-usage.md) ｜ **本手册首页：** [Curated PoC 简介](./01-overview.md) ｜ **文档首页 →：** [afrog 文档](../index.md)
