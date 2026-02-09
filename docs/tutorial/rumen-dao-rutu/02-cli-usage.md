# Afrog 官方教程(2)：拒绝“平A”！解锁命令行参数的“组合拳”

> “只会平 A 是打不过 BOSS 的。” —— 掌握参数组合拳，让漏洞无处遁形。

大家好，这里是 **Afrog 官方**。

在上一期中，我们学会了如何安装并运行 Afrog 进行最简单的单目标扫描。但在实际的红队行动或 SRC 挖掘中，我们面对的往往是成百上千的目标，或者是需要精准打击的特定场景。

今天，我们将深入 Afrog 的武器库，解锁那些强大的**命令行参数**。

## 🧭 参数速查表（先收藏）

如果你只想快速开跑，直接抄下面的组合就够用：

| 你要做的事 | 推荐命令 |
| :--- | :--- |
| 单个 URL 扫漏洞 | `afrog -t http://example.com` |
| 批量 URL 扫漏洞 | `afrog -T targets.txt` |
| 网段资产探测（端口 → Web → 漏洞） | `afrog -t 192.168.1.0/24 -ps -w` |
| 全端口扫描（绝对全量） | `afrog -t 1.2.3.4 -ps -p 1-65535 -Pn` |
| 快速只扫高危 | `afrog -T targets.txt -S high,critical` |
| 只跑某类 PoC（关键词） | `afrog -t http://example.com -s spring,weblogic` |
| 输出完整证据链（便于复现） | `afrog -t http://example.com -ja result_full.json` |
| 扫到洞立刻群里告警 | `afrog -T targets.txt -S high,critical -wecom` |
| **公网防抖动（强烈推荐）** | `afrog -T targets.txt -mt` |

## 🎯 目标指定：指哪打哪

### 1. 批量打击：文件导入
如果你有一堆 URL 需要扫描，别一个个复制粘贴。把它们保存在一个 `txt` 文件里（一行一个），然后使用 `-T` 参数：

```bash
afrog -T targets.txt
```

### 2. 资产探测：CIDR/段探测 + 端口扫描（`-ps`）+ Web 探测（`-w`）
当你的输入不是“URL”，而是 “IP / 网段 / 段范围”时，最佳姿势通常是：

1) 用 `-ps` 做端口预扫，把 `host:port` 资产捞出来  
2) 用 `-w` 做 Web 存活探测，把可访问的 Web URL（含标题等信息）捞出来  
3) Afrog 再基于这些资产跑指纹与漏洞 PoC

#### 2.1 CIDR / 段范围作为目标
```bash
# CIDR 目标（会进入预扫/扫描流程）
afrog -t 192.168.1.0/24 -ps

# IP 段范围目标（会进入预扫/扫描流程）
afrog -t 192.168.1.1-192.168.1.254 -ps
```

#### 2.2 端口预扫：`-ps` + `-p`
```bash
# 默认端口策略：-p top（常见端口优先，-ps 不写 -p 也会用 top）
afrog -t 192.168.1.100 -ps

# 自定义端口：单个 / 逗号分隔 / 范围
afrog -t 192.168.1.100 -ps -p 80,443,8080,8000-9000
```

`-p` 支持关键字（更适合“资产探测”的语义）：
- `top`：常见端口优先（默认）
- `full` / `all`：内置高覆盖端口序列（分层扫描），适合更全面的探测
- `s1`/`s2`/`s3`/`s4`：分层端口集合（更偏调参玩法）

如果你想要“真正意义的 1-65535 全端口”，使用范围更直观：
```bash
afrog -t 192.168.1.100 -ps -p 1-65535
```

#### 2.3 端口预扫调参：`-Pn` / `-prate` / `-ptimeout` / `-ptries`
```bash
# 跳过主机发现阶段，直接对输入目标做端口扫描
afrog -t 192.168.1.0/24 -ps -Pn

# 控制端口扫描速率/超时/重试（单位：ms）
afrog -t 192.168.1.0/24 -ps -p all -prate 2000 -ptimeout 800 -ptries 1
```

`-p all/full` 时，内部会把大端口集合切块扫描；可以用 `-ps-s4-chunk` 控制块大小（更稳但更慢，或更快但更吃资源）。

#### 2.4 Web 存活探测：`-w`
`-w` 会对目标集合做 Web 探测，自动补全/识别可访问的 HTTP(S) URL，并输出常见元信息（如标题、Server 等）。它适合你在跑漏洞前快速摸清 Web 面。

```bash
# 端口预扫 + Web 探测 + 漏洞扫描
afrog -t 192.168.1.0/24 -ps -w
```

#### 2.5 常见服务探测 → 弱口令/默认口令探测
端口预扫得到的是 `host:port`，随后 Afrog 会进行指纹识别；当服务类型能被识别时，对应的弱口令/默认口令 PoC（位于 `pocs/afrog-pocs/default-pwd/`）就可以自动跑起来（例如 `ssh-weak-login` 的 `requires: [ssh]`）。

实战示例：
```bash
# 网段资产探测 + Web 探测
afrog -t 192.168.1.0/24 -ps -w

# 只盯一个服务（示例：SSH 弱口令）
afrog -t 192.168.1.0/24 -ps -p 22 -s ssh

# 先把弱口令 PoC 列出来看看（用于了解支持范围）
afrog -pl -s weak-login,default-pwd,default-login
```

常见覆盖的服务/组件（以内置 PoC 为准，随版本迭代）：
- 网络服务：SSH、FTP、Telnet、SMB、WinRM、SMTP/POP3/IMAP、VNC、Redis、MongoDB、MySQL、PostgreSQL、MSSQL、Oracle、Memcached、Zookeeper
- 常见后台/中间件：Tomcat、Jenkins、Grafana、Zabbix、RabbitMQ、phpMyAdmin、Nexus、MinIO、ActiveMQ 等

---

## 🔍 过滤的艺术：精准制导

Afrog 内置了数千个 PoC，全量扫描虽然覆盖全，但有时太慢或动静太大。这时候你需要“过滤器”。

### 1. 按关键词搜索：`-s` (Search)
假设你只关心 **Spring Boot** 相关的漏洞：

```bash
afrog -t http://example.com -s springboot
```
这样，Afrog 只会加载名字里带有 `springboot` 的 PoC。

### 2. 按危害等级：`-S` (Severity)
不想看那些 `Info` 或 `Low` 级别的低危漏洞？只看高危和严重？

```bash
afrog -t http://example.com -S high,critical
```

### 3. 排除法：`-ep` (Exclude PoC)
有时候某个 PoC 可能会导致业务异常，或者你不想扫描某个特定类型的漏洞（比如不想扫 `Log4j`）：

```bash
afrog -t http://example.com -ep log4j
```

---

## 🧰 PoC 管理：如何“只跑我想跑的”

### 1. 指定 PoC 文件/目录：`-P`
```bash
# 指定单个 PoC 文件
afrog -t http://example.com -P ./pocs/test.yaml

# 指定一个 PoC 目录
afrog -t http://example.com -P ./pocs/
```

### 2. 追加 PoC：`-ap`
当你既想跑内置 PoC，又想顺手跑你自己的几个 PoC：
```bash
afrog -t http://example.com -ap ./my-pocs/
```

### 3. 列出/查看 PoC：`-pl` / `-pd`
```bash
# 按关键词列出 PoC（注意：-s 只匹配 PoC 的 id/name/tags）
afrog -pl -s weaver,ecology

# 查看某个 PoC 的详情
afrog -pd ssh-weak-login
```

### 4. 校验 PoC 语法：`-validate`
写 PoC 写到怀疑人生时，先用这个把 YAML 语法问题揪出来：
```bash
afrog -validate ./pocs/
```

---

## 📊 输出管理：数据落地

### 1. 保存 HTML 报告
虽然默认会生成报告，但你可以用 `-o` 指定报告的文件名和位置：

```bash
afrog -t http://example.com -o ./result/my_scan.html
```

### 2. 自动化集成：JSON 输出
如果你想把 Afrog 集成到自己的扫描平台，或者用 Python 脚本处理结果，JSON 是最好的选择。

```bash
# -j 只输出简要信息
afrog -t http://example.com -j result.json

# -ja 输出包含 Request/Response 的完整信息 (Json All)
afrog -t http://example.com -ja result_full.json
```

---

## 🧪 排障与常用调优：让你跑得更稳

这些参数不一定“每天都用”，但一旦出问题，基本都靠它们救命：

### 1. 抗抖动神器：`-mt` (Monitor Targets) 🌟
**强烈推荐在公网扫描时开启！**
如果网络环境较差（丢包、波动），Afrog 的第一次探活可能会失败，导致目标被直接丢弃。
加上 `-mt`，Afrog 会对目标进行持续、带重试的监控。只要它“活过来”一次，就不会漏扫。

```bash
afrog -T targets.txt -mt
```

### 2. 超时与重试：`-timeout` / `-retries`
```bash
# 网络不稳时，适当加大超时与重试
afrog -t http://example.com -timeout 60 -retries 2
```

### 3. 代理与自定义请求头：`-proxy` / `-H`
```bash
# 走代理
afrog -t http://example.com -proxy http://127.0.0.1:8080

# 全局加请求头/Cookie
afrog -t http://example.com -H 'X-Forwarded-For: 1.1.1.1' -H 'Cookie: a=b'
```

### 4. 输出更多调试信息：`-debug`
```bash
afrog -t http://example.com -debug
```

### 5. 临时跳过指纹阶段：`-nf`
当你只想快速验证漏洞 PoC，不想做指纹门控时：
```bash
afrog -t http://example.com -nf
```

### 6. 断点续扫：`-resume`
```bash
afrog -resume resume.afg
```

---

## 🔔 Webhook 告警：钉钉 / 企业微信

当你跑批量任务时，最怕的是“扫完才发现有洞”。Webhook 告警可以让 Afrog 在命中漏洞时直接把消息推送到群里。

要点：
- 先在 `~/.config/afrog/afrog-config.yaml` 里配置 token
- 扫描时再加 `-dingtalk` 或 `-wecom` 才会推送

示例：
```bash
# 企业微信推送
afrog -T targets.txt -wecom

# 钉钉推送
afrog -T targets.txt -dingtalk
```

字段说明与配置样例请看下一篇教程《配置文件深度解析》中的 Webhook 章节。

---

## ⚡ 进阶技巧：智能并发

默认情况下，Afrog 的并发已经调教得很好了。但如果你想更激进，或者目标很脆弱，可以手动调整并发数 `-c` (Concurrency)：

```bash
# 默认是 25，调大速度快，但可能封 IP
afrog -t targets.txt -c 50
```

还有一个黑科技参数 `-smart`：
```bash
afrog -t targets.txt -smart
```
开启后，Afrog 会根据目标的数量和终端的并发能力自动调整并发策略，让你省心省力。

---

## 📚 附录：哪里看完整参数？

Afrog 的参数非常丰富，为了不让这篇文章变成“字典”，我们只列出了最常用的核心参数。
如果你想查看所有支持的参数（包括一些冷门但有趣的隐藏功能），有以下两种方式：

1.  **命令行查看**：
    ```bash
    afrog -h
    ```
2.  **GitHub 官方 Wiki**：
    访问 [https://github.com/zan8in/afrog/wiki](https://github.com/zan8in/afrog/wiki) 查看最新、最全的文档。

---

## 下期预告

有了扫描能力，但遇到**没有回显**的漏洞（比如盲注、Log4j）怎么办？
下一期**《配置文件深度解析》**，我们将教你配置 **反连平台 (OOB)**，让那些隐蔽的漏洞也无处藏身！

---

### 🌟 进阶玩法：加入 Afrog 官方星球

**“启动即最新，扫描即实战”**

觉得开源版 PoC 更新不够快？想要第一时间获取 **高危漏洞 / 0day** 情报？
Afrog v3.3.7 已内置 **“星球精选 PoC”自动更新客户端**。

加入 **「Afrog 官方圈」** 知识星球，你将获得：
1.  🔑 **专属 License Key**：一键配置。
2.  ⚡️ **独家高危 PoC**：快人一步，通过自动更新通道直达你的扫描器。
3.  🛠️ **硬核技术交流**：与作者和众多安全从业者共同探讨。

👉 **如何开启自动更新？**
查看详细文档：[Afrog 支持星球 PoC 自动更新功能](https://github.com/zan8in/afrog/wiki/Afrog-%E6%94%AF%E6%8C%81%E6%98%9F%E7%90%83PoC%E8%87%AA%E5%8A%A8%E6%9B%B4%E6%96%B0%E5%8A%9F%E8%83%BD)

*(此处建议插入知识星球二维码)*

---
*本文由 Afrog 官方原创，欢迎转发分享。*
