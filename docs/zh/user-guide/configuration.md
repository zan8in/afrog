---
title: 配置文件说明
slug: /docs/user-guide/configuration
lang: zh
summary: 介绍 afrog 配置文件的用途、字段和典型配置方式。
status: published
source: docs/README_CN.md, docs/tutorial/rumen-dao-rutu/03-configuration.md
last_reviewed: 2026-09-16
---

`afrog` 第一次启动时，会在当前用户目录下自动创建配置文件：

```text
$HOME/.config/afrog/afrog-config.yaml
```

这份配置主要用于管理 OOB / reverse 平台、通知和其他运行期依赖。

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

### 所有 PoC 都必须配置 reverse 吗

不是。只有依赖 OOB / reverse 验证的 PoC 才需要这类配置；普通回显型检测不一定依赖它。

## 相关文档

- [第一次扫描](../getting-started/first-scan.md)
- [输出与报告](./output-and-report.md)
