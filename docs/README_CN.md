# afrog

<p align="center">
  <a href="http://afrogx.com"><img src="../images/afrog-logo.svg" width="60px" alt="afrog"></a>
</p>

<h4 align="center">用于漏洞赏金、测试和红队的安全工具</h4>

<p align="center">
  <a href="../README.md">English</a> •
  <a href="README_CN.md">中文</a>
</p>

<p align="center">
  <img src="https://img.shields.io/github/go-mod/go-version/zan8in/afrog?filename=go.mod" alt="Go version">
  <a href="https://github.com/zan8in/afrog/releases"><img src="https://img.shields.io/github/downloads/zan8in/afrog/total" alt="Downloads"></a>
  <a href="https://github.com/zan8in/afrog/graphs/contributors"><img src="https://img.shields.io/github/contributors-anon/zan8in/afrog" alt="Contributors"></a>
  <a href="https://github.com/zan8in/afrog/releases/"><img src="https://img.shields.io/github/release/zan8in/afrog" alt="Release"></a>
  <a href="https://github.com/zan8in/afrog/issues"><img src="https://img.shields.io/github/issues-raw/zan8in/afrog" alt="Issues"></a>
</p>

`afrog` 是一个高性能漏洞扫描器，支持内置与自定义 PoC，适合漏洞验证、批量扫描、PoC 编写和 SDK 集成等场景。

## 安装

### 二进制安装

下载最新发布版本：

- <https://github.com/zan8in/afrog/releases/latest>

### 源码构建

```bash
git clone https://github.com/zan8in/afrog.git
cd afrog
go mod tidy
go build -o afrog cmd/afrog/main.go
./afrog -h
```

### Go 安装

```bash
go install -v github.com/zan8in/afrog/v3/cmd/afrog@latest
```

## 快速开始

扫描单个目标：

```bash
afrog -t https://example.com
```

从文件读取多个目标：

```bash
afrog -T targets.txt
```

只扫描高危和严重漏洞：

```bash
afrog -T targets.txt -S high,critical
```

## 文档入口

仓库文档正在重构为统一的中英文结构。当前中文版最完整，英文版已预留镜像路径并会逐步补齐。

- 中文文档首页：[docs/zh/index.md](./zh/index.md)
- 英文文档首页：[docs/en/index.md](./en/index.md)
- PoC 快速开始：[docs/zh/poc/quickstart.md](./zh/poc/quickstart.md)
- SDK 快速开始：[docs/zh/sdk/quickstart.md](./zh/sdk/quickstart.md)
- CLI 参数总览：[docs/zh/reference/cli-options.md](./zh/reference/cli-options.md)
- PoC 贡献者荣誉墙：[docs/zh/community/contributors.md](./zh/community/contributors.md)

## PoC 贡献者

PoC 贡献者的公开致谢已经恢复为长期入口，不再随着 README 精简而消失。

- 仓库 README 荣誉墙：[`README.md#poc-contributors`](../README.md#poc-contributors)
- 文档站内稳定入口：[docs/zh/community/contributors.md](./zh/community/contributors.md)
- 贡献教程：[开源贡献 - 成为 Contributor](./tutorial/rumen-dao-rutu/06-contribution.md)

## 示例

- [基础扫描器](../examples/basic_scan/main.go)
- [异步扫描器](../examples/async_scan/main.go)
- [OOB 扫描器](../examples/oob_scan/main.go)
- [进度扫描器](../examples/progress_scan/main.go)
- [完整输出示例](../examples/full_output/main.go)
- [SDK 端口扫描示例](../examples/sdk_portscan/main.go)
- [漏洞扫描示例](../examples/vuln_scan/main.go)
- [端口扫描示例](../examples/port_scan/main.go)

## 项目链接

- Releases：<https://github.com/zan8in/afrog/releases>
- 官网：<http://afrogx.com>
- Wiki 历史入口：<https://github.com/zan8in/afrog/wiki>

## 讨论群

如果你想加入 afrog 微信交流群，请先添加 afrog 个人账号并备注 `afrog`。

<img src="https://github.com/zan8in/afrog/blob/main/images/discussion.jpg" width="33%" alt="discussion group">

## 404Starlink

afrog 已加入 [404Starlink](https://github.com/knownsec/404StarLink)。

## 免责声明

此工具仅用于合法授权的安全工作，请勿扫描未授权目标。任何非法使用及其后果均由使用者自行承担。
