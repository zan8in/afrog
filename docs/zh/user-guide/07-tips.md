<!--
title: 实战技巧
slug: /docs/user-guide/tips
lang: zh
summary: afrog 的高频实战组合：目标输入、资产探测、性能与稳定性、OOB、输出与断点续扫。
status: published
source: new
last_reviewed: 2026-09-23
-->

本页不是参数字典，而是把高频参数组合成可以直接照抄的实战用法。完整参数定义见 [CLI 参数总览](./04-cli-options.md)。

## 只关注高危漏洞

```bash
afrog -T targets.txt -S high,critical
```

配合 `-sort severity` 可以让结果按风险等级排序，适合先看重点。

## 从空间测绘直接拉资产

```bash
afrog -cs zoomeye -q "app:'tomcat'" -qc 1000
```

`-cs` 指定空间测绘平台，`-q` 传检索语句，`-qc` 控制拉取数量（默认 100）。使用前需要先在 [配置文件](./05-configuration.md) 的 `cyberspace` 段填好凭据。

## 网段场景先探活再扫描

```bash
afrog -t 192.168.1.0/24 -ps
```

- `-ps`：开启端口预扫描，适合 IP、网段和段范围
- `-w`：Web 资产信息收集（URL / 状态码 / 标题 / Server / 技术栈指纹），**默认开启**，不需要时可加 `-w=false` 关闭
- `-p`：控制端口范围，支持 `top`、`full`、`80,443,8080`、`1-65535`
  - `top` 约 640 个常见端口，秒级出结果；`full` / `all` 是全 65535 端口，按需使用
  - 全端口的耗时取决于目标对探测的响应：能回 `RST` 的目标很快，大量丢包的目标则由「单端口超时 × 65535 ÷ 单目标并发」决定
- `-Pn`：跳过主机发现，直接进入端口扫描

## 只用自己关心的 PoC

```bash
afrog -t https://example.com -s spring,weblogic   # 关键词筛选（id / name / tags）
afrog -t https://example.com -P ./my-pocs/        # 指定 PoC 文件或目录
afrog -t https://example.com -ap ./extra-pocs/    # 在内置 PoC 之外追加
afrog -t https://example.com -ep log4j            # 排除某类 PoC
```

写或引入新 PoC 前，建议先校验与确认：

```bash
afrog -validate ./pocs/        # 校验 PoC 语法
afrog -pl -s weaver,ecology    # 列出匹配到的 PoC
afrog -pd ssh-weak-login       # 查看单条 PoC 详情
```

## 批量扫描时保护目标

```bash
afrog -T targets.txt -c 50            # 单目标自适应限速已默认开启
afrog -T targets.txt -rl 80 -rlt 5    # 或改用固定单目标速率
afrog -T targets.txt -mt -balanced
```

- `-c` 并发数，`-rl` 全局每秒请求数（默认 150），`-rlt` 单目标每秒请求数
- 单目标限速默认走 `-auto-req-limit` 自适应；`-rlt` 固定速率，`-polite` / `-balanced` / `-aggressive` 为预设档位，三者互斥
- `-mt` 监控目标存活状态，适合公网或网络波动明显的场景

经验上不建议只靠把 `-c` 调大来提速，更稳妥的做法是并发与限速一起调。

## 低配机器与服务端的并发上限

端口预扫描的并发上限同时受本机文件描述符（fd）数量约束。默认工作池 `-prate 500` 在高配机器上没压力，但 Linux 服务器常见的 systemd 默认 `ulimit -n 1024` 已经踩线，容器里可能只有 `256`。fd 一旦吃满，报告、日志、Web 监听这些扫描之外的连接也会跟着失败。

afrog 按三步兜底：

1. 启动时先把软上限提到硬上限（与 nmap 相同的做法），提不动就静默跳过。
2. 按剩余预算把全局池收敛到 `min(-prate, 预算)`，收敛时打印一行说明：

```
[WRN] port-scan fd-limit probes=128 concurrency=500->128 lowered to fit open-file limit
```

3. 万一下探过程中真的耗尽（Windows 无法预读句柄上限，只能依赖运行时信号），失败探测会与目标侧信号分开计数、只告警一次，并临时把在飞并发减半：

```
[WRN] port-scan fd-exhausted failed=3 raise ulimit -n or lower -prate
```

需要手动调优时：

```bash
ulimit -n 65535                    # 会话内抬高 fd 上限
afrog -t 10.0.0.1 -ps -prate 200   # 主动降并发
```

容器场景给 `--ulimit nofile=65535:65535`。Windows 没有可设置的 fd 上限，只在看到上面的告警时降低 `-prate` 即可。

## 不要把自己的网络打挂

上一节讲的是本机资源，这一节讲的是「本机所在的网络」。端口扫描真正的风险不是带宽（一次 TCP 探测往返不到 200 字节，1000 次/秒也才 1~2 Mbps），而是出口设备的 NAT/conntrack 会话表：关闭的端口立刻回 RST，表项快速释放；**被过滤的端口不回包，表项要挂到 30~120 秒超时才释放**。表被打满后，同一网络里所有人的新建连接都会失败。

关键在于：**并发不约束速率**。`-prate 500` 扫外网（RTT 几百毫秒）大约每秒 1000 次连接，扫内网（RTT 1 毫秒）理论上限却是每秒 50 万次——差两个数量级。所以 afrog 默认给端口预扫描加了一层连接速率上限：

```bash
afrog -t 10.0.0.0/24 -ps              # 默认：全局 1000/s、单目标 50/s
afrog -t 10.0.0.0/24 -ps -polite      # 更保守：全局 200/s、单目标 20/s
afrog -t 10.0.0.0/24 -ps -pcps 200    # 只调全局速率
afrog -t 10.0.0.0/24 -ps -aggressive  # 不限速（-pcps 0 等价）
```

全端口 `65535` 在默认档位下约 65 秒扫完一个目标，日常够用；确实需要打满时再显式放开。

扫描期间 afrog 还会周期性测量到默认网关的 RTT（`-ps-link-probe`，默认开启）。网关就在本机这一跳，它的 RTT 只可能因为本机出口链路或网关被压满而抬升，是干净的本地信号：一旦网关 RTT 明显高于扫描前的空载基线，或过半探测都没有回音，就乘性降速并告警；链路恢复后再逐步加回来。

```
[WRN] port-scan throttled rate=1000->700 no-reply=100% gw-rtt=42ms baseline=3ms probes unanswered, easing off to protect the local network -pcps 0 disables
```

看到这行说明扫描已经自动收敛了，不需要干预；如果你确认这条链路足够健壮，也可以用 `-pcps 0` 关掉这层保护。

## 无回显漏洞用 OOB

```bash
afrog -t https://example.com -oob ceyeio
```

可用适配器包括 `ceyeio`、`dnslogcn`、`alphalog` 等，需要先在 [配置文件](./05-configuration.md) 的 `reverse` 段填好对应平台凭据。速率与并发可用 `-orl`、`-oc` 控制。

## 输出与自动化

```bash
afrog -T targets.txt -o report.html        # HTML 报告
afrog -T targets.txt -j result.json        # 简要 JSON
afrog -T targets.txt -ja result_full.json  # 含请求与响应的完整 JSON
```

少量场景下的输出控制：

- `-silent`：尽量只输出结果
- `-live-stats`：单行实时统计
- `-nc`：关闭 ANSI 彩色输出
- `-doh`：禁用自动生成 HTML 报告

## 长任务断点续扫

```bash
afrog -T big-targets.txt -resume resume.afg
```

中断后带上同一个 `-resume` 文件即可继续，适合大批量目标的长时间扫描。

## 排障

```bash
afrog -t https://example.com -debug   # 输出更多调试信息
afrog -t https://example.com -nf      # 跳过指纹阶段，快速验证
afrog -t https://example.com -test    # 测试模式，会禁用 requires 门控
```

`-nf` 和 `-test` 都会影响依赖 `requires` 的门控行为，不建议作为常规扫描模式。

### 端口结果每次不一样

同一个目标多次扫描，开放端口列表不一样，通常是**目标侧在限速或封禁**，不是扫描器丢结果：

- 关闭端口会回 `RST`，被丢弃的探测不会响应。目标（或其前置设备）在压力下会丢弃一部分 `SYN`，于是每次都少几个端口。
- 并发越高越明显：单目标并发默认 50，拉高到数百时很容易触发目标的连接数限制，缺失的端口反而更多。
- 如果目标丢弃了绝大多数探测，加 `-debug` 时会打印一行 `[WRN] port-scan filtered host=… drop-rate=… probes=… results may be incomplete` 警告，提示结果可能不完整（常规输出不显示，避免打断进度条）。
- 收尾汇总行恒定带 `closed=` / `filtered=`：前者是被 `RST` 明确拒绝的端口，后者是完全没回包的端口。`filtered` 占比高说明目标（或其前置设备）在丢探测，而不是端口真的关闭。

```bash
afrog -t 192.0.2.10 -ps -p full -ps-host-concurrency 20   # 把单目标并发再压低（默认 50）
afrog -t 192.0.2.10 -ps -ptries 2                          # 目标丢包严重时再加一次重试（默认 1）
afrog -t 192.0.2.10 -ps -ptimeout 2000                      # 放宽单次连接超时
```

`-ptries` 默认是 1，且只对「超时」的端口重试（收到 `RST` 立即返回，不影响常规目标）。首次 `SYN` 常因瞬时丢包、ARP 冷启动、目标或中间设备的端口扫描防护被静默丢弃，不重试就会把一个真实开放端口永久记成 `closed`/`filtered`。觉得慢可以用 `-ptries 0` 关掉。

判断依据：换一台网络位置不同的机器、或换个时间窗再扫，如果结果恢复一致，就说明是目标侧的限速而非本机问题。

## 通知与 Web 服务

```bash
afrog -web         # 启动 Web 服务
afrog -dingtalk    # 启动钉钉 webhook 服务
afrog -wecom       # 启动企业微信 webhook 服务
```

通知的触发级别与 token 在 [配置文件](./05-configuration.md) 的 `webhook` 段配置。

> **← 上一篇：** [输出与报告](./06-output-and-report.md) ｜ **本手册首页：** [afrog 简介](./01-overview.md) ｜ **下一篇 →：** [Web 扫描工作台](./08-web-console.md)
