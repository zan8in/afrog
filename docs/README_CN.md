<p align="center">
  <a href="#"><img src="../images/afrog-logo.svg" width="60px" alt="afrog"></a>
</p>

<h4 align="center">用于漏洞赏金、渗透测试和红队的安全工具</h4>

<p align="center">
  <a href="../README.md">English</a> •
  <a href="README_CN.md">中文</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.27%2B-00ADD8?logo=go" alt="Go version">
  <a href="https://github.com/zan8in/afrog/releases/latest"><img src="https://img.shields.io/github/v/release/zan8in/afrog?include_prereleases&sort=semver" alt="Latest release"></a>
  <a href="https://github.com/zan8in/afrog/stargazers"><img src="https://img.shields.io/github/stars/zan8in/afrog?style=flat-square" alt="GitHub stars"></a>
  <a href="https://github.com/zan8in/afrog/blob/main/LICENSE"><img src="https://img.shields.io/github/license/zan8in/afrog" alt="License"></a>
  <a href="https://github.com/zan8in/afrog/issues"><img src="https://img.shields.io/github/issues-raw/zan8in/afrog" alt="Issues"></a>
</p>

## afrog 是什么

`afrog` 是一个高性能安全扫描工具箱，面向漏洞赏金、渗透测试和红队工作流。它把快速的目标探测、内置漏洞检查、自定义 PoC 编写和 SDK 自动化整合在同一套 Go 工作流里。

### afrog 能做什么

- 面向 Web 目标和网络服务做快速、聚焦的扫描
- 支持内置与自定义 PoC，服务于实际的安全验证
- 通过精确的规则设计与检查降低误报噪音
- 灵活集成到 Go 应用、自动化流程和私有 PoC 流水线

## 安装

### 依赖

- Go 1.27 或更高版本

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

文档按四本手册组织：

| 手册 | 从这里开始 |
| --- | --- |
| 使用指南 | [afrog 是什么、如何使用](./zh/user-guide/01-overview.md) |
| PoC 编写指南 | [写出你的第一条 PoC](./zh/poc/01-quickstart.md) |
| SDK 使用指南 | [把 afrog 集成进 Go 程序](./zh/sdk/01-quickstart.md) |
| Curated PoC | [启用授权 curated PoC](./zh/curated/01-overview.md) |

## PoC 贡献者

<div><table frame=void>
        <tr>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/1.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://blog.csdn.net/U_U520"><sub>不动明王</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/2.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://www.linuxlz.com/"><sub>雪山</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/3.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/White-hua"><sub>White-hua</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/5.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0)"><sub>123456</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/6.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/ifofor"><sub>ifofor</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/7.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/SkinAir"><sub>Air</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/8.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/zhizhuoshuma"><sub>执着</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/4.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/purple-WL"><sub>purple-WL</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/9.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>throat</sub></a>
        </td>
        </tr>
    <tr>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/10.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="http://secx.store:4000/archives/"><sub>Secx</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/11.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/yueyu0740"><sub>冰河</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/12.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>Sheen</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/13.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>a16</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/14.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>A1</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/15.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/rainbow2972"><sub>rainbow2972</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/16.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/wuha0926"><sub>wuha0926</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/17.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>茄子</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/18.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>lei_sec</sub></a>
        </td>
        </tr>
    <tr>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/19.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/G-H-Z"><sub>G-H-Z</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/20.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/LDDP"><sub>wh1te</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/21.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>清月</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/22.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>york</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/23.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>7eleven.eth</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/24.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/Double-q1015"><sub>Double...</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/25.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/iceyjchen"><sub>ICEY_</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/26.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/Ablackcatlazy"><sub>lazy</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/55.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>free2e</sub></a>
        </td>
    </tr>
    <tr>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/28.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>m4sk</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/29.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://www.yuque.com/chenmoshuren/qyxg2k"><sub>沉默树人</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/30.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>陈麻子</sub></a>
        </td>
         <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/31.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/leonardo-o1"><sub>leonardo-o1</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/32.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>江湖人称魏...</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/33.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>若兮风</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/34.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>-sudo</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/35.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/Cuerz"><sub>Cuerz</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/36.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>laohuan12138</sub></a>
        </td>
    </tr>
    <tr>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/37.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/exp0l0zzz"><sub>exp0l0zzz</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/38.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/1derian"><sub>1derian</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/39.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/CMDB-M"><sub>CMDB-M</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/40.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:(0);"><sub>li1u</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/41.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/s0nd9r"><sub>oxsonder</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/42.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>Zhiliao</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/43.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>段</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/44.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/HuiTaiL6"><sub>HuiTaiL</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/45.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/Miracles666"><sub>Miracles666</sub></a>
        </td>
    </tr>
    <tr>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/46.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>Observer</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/47.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>黑熊</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/48.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>TryA9ain</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/49.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/fgz00"><sub>fgz00</sub></a>
        </td>
         <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/50.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/Y3y1ng"><sub>Y3y1ng</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/51.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>二大爷</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/52.png&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/wanswu"><sub>Wans</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/53.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://github.com/hbdxmz"><sub>海边的小米粥</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/54.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>Wen</sub></a>
        </td>
        </tr>
        <tr>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/56.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>SULAB</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/57.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0);"><sub>ZacharyZcR</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/58.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="https://superhero.blog.csdn.net/"><sub>Superhero</sub></a>
        </td>
        <td align="center">
            <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/zan8in/afrog/main/images/contributors/59.jpg&mask=circle&w=60&h=60"
                   alt="Contributor avatar"
                 />
            <br>
            <a href="javascript:void(0)"><sub>k5rC85Lma</sub></a>
        </td>
        </tr>

</table></div>


## 讨论群

如果你想加入 afrog 微信交流群，请先添加 afrog 个人账号并备注 `afrog`。

<img src="../images/discussion.jpg" width="33%" alt="discussion group">

## 404Starlink

afrog 已加入 [404Starlink](https://github.com/knownsec/404StarLink)。

## 免责声明

此工具仅用于合法授权的安全工作，请勿扫描未授权目标。任何非法使用及其后果均由使用者自行承担。
