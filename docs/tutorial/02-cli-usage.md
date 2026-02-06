# Afrog 官方教程(2)：不仅是扫描 - 命令行参数全解

> “只会平 A 是打不过 BOSS 的。” —— 掌握参数组合拳，让漏洞无处遁形。

大家好，这里是 **Afrog 官方**。
在上一期中，我们学会了如何安装并运行 Afrog 进行最简单的单目标扫描。但在实际的红队行动或 SRC 挖掘中，我们面对的往往是成百上千的目标，或者是需要精准打击的特定场景。

今天，我们将深入 Afrog 的武器库，解锁那些强大的**命令行参数**。

## 🎯 目标指定：指哪打哪

### 1. 批量打击：文件导入
如果你有一堆 URL 需要扫描，别一个个复制粘贴。把它们保存在一个 `txt` 文件里（一行一个），然后使用 `-T` 参数：

```bash
afrog -T targets.txt
```

### 2. 联动端口扫描：`-ps` (Port Scan)
Afrog 不仅仅是个 Web 漏扫。当你面对一个 IP 时，不知道它开放了哪些 Web 端口？
加上 `-ps` 参数，Afrog 会先进行端口扫描，发现开放的 Web 服务后，自动进行漏洞扫描。

```bash
# 扫描 ip 的常见端口，发现服务后自动扫漏洞
afrog -t 192.168.1.100 -ps
```

你甚至可以指定端口范围：
```bash
# 扫描全端口
afrog -t 192.168.1.100 -ps -p 1-65535
```

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
开启后，Afrog 会根据目标的数量自动调整并发策略，让你省心省力。

---

## 📝 总结一下

| 场景 | 参数组合 |
| :--- | :--- |
| **批量扫描** | `afrog -T urls.txt` |
| **IP 资产探测** | `afrog -t 1.2.3.4 -ps` |
| **只扫某组件** | `afrog -t example.com -s weblogic` |
| **只看高危** | `afrog -t example.com -S high,critical` |
| **自动化对接** | `afrog -t example.com -ja result.json` |

熟练掌握这些参数，你就不再是一个只会运行工具的“脚本小子”，而是一名能够根据战场环境灵活调整战术的**安全研究员**。

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
