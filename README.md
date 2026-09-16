<p align="center">
  <a href="#"><img src="images/afrog-logo.svg" width="60px" alt="afrog"></a>
</p>

<h4 align="center">A Security Tool for Bug Bounty, Pentest and Red Teaming</h4>

<p align="center">
  <a href="README.md">English</a> •
  <a href="docs/README_CN.md">中文</a>
</p>

<p align="center">
  <img src="https://img.shields.io/github/go-mod/go-version/zan8in/afrog?filename=go.mod" alt="Go version">
  <a href="https://github.com/zan8in/afrog/releases"><img src="https://img.shields.io/github/downloads/zan8in/afrog/total" alt="Downloads"></a>
  <a href="https://github.com/zan8in/afrog/graphs/contributors"><img src="https://img.shields.io/github/contributors-anon/zan8in/afrog" alt="Contributors"></a>
  <a href="https://github.com/zan8in/afrog/releases/"><img src="https://img.shields.io/github/release/zan8in/afrog" alt="Release"></a>
  <a href="https://github.com/zan8in/afrog/issues"><img src="https://img.shields.io/github/issues-raw/zan8in/afrog" alt="Issues"></a>
</p>

## What is afrog

`afrog` is a high-performance vulnerability scanner with support for built-in and custom PoCs. It is designed for fast verification, low false positives, and practical workflows across web targets, network services, PoC authoring, and SDK-based integration.

## Install

For source builds or `go install`, use Go 1.27 or later.

### Binary release

Download the latest release from:

- <https://github.com/zan8in/afrog/releases/latest>

### Build from source

```bash
git clone https://github.com/zan8in/afrog.git
cd afrog
go mod tidy
go build -o afrog cmd/afrog/main.go
./afrog -h
```

### Go install

```bash
go install -v github.com/zan8in/afrog/v3/cmd/afrog@latest
```

## Quick start

Scan a single target:

```bash
afrog -t https://example.com
```

Scan multiple targets from a file:

```bash
afrog -T targets.txt
```

Run only high and critical checks:

```bash
afrog -T targets.txt -S high,critical
```

## Documentation

The documentation is being reorganized into a structured bilingual tree. Chinese content is currently the most complete; English paths are already reserved and will be filled incrementally.

- Chinese docs index: [docs/zh/index.md](docs/zh/index.md)
- English docs index: [docs/en/index.md](docs/en/index.md)
- PoC quickstart: [docs/zh/poc/quickstart.md](docs/zh/poc/quickstart.md)
- SDK quickstart: [docs/zh/sdk/quickstart.md](docs/zh/sdk/quickstart.md)
- Contributors: [docs/zh/community/contributors.md](docs/zh/community/contributors.md)

## PoC Contributors

PoC contributors are a core part of the afrog community. This section stays in the repository README on purpose so contributor recognition remains visible in the first place people land.

For contribution guidance, see [the Chinese contributor guide](docs/tutorial/rumen-dao-rutu/06-contribution.md). For a stable docs entry, see [docs/zh/community/contributors.md](docs/zh/community/contributors.md).

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

## Examples

- [Basic scanner](examples/basic_scan/main.go)
- [Async scanner](examples/async_scan/main.go)
- [OOB scanner](examples/oob_scan/main.go)
- [Progress scanner](examples/progress_scan/main.go)
- [Full output](examples/full_output/main.go)
- [SDK portscan](examples/sdk_portscan/main.go)
- [Vulnerability scan](examples/vuln_scan/main.go)
- [Port scan](examples/port_scan/main.go)

## Project links

- Releases: <https://github.com/zan8in/afrog/releases>
- Wiki archive: <https://github.com/zan8in/afrog/wiki>

## Community

To join the afrog WeChat discussion group, add the afrog account and mark it as `afrog`.

<img src="https://github.com/zan8in/afrog/blob/main/images/discussion.jpg" width="33%" alt="discussion group">

## 404Starlink

afrog is part of [404Starlink](https://github.com/knownsec/404StarLink).

## Disclaimer

This tool is intended only for legally authorized security work. Do not scan unauthorized targets. The user is solely responsible for any misuse or illegal activity.
