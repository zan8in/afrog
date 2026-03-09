# Afrog 官方教程(3)：配置文件详解 - OOB 与通知

> “工欲善其事，必先利其器。” —— 配好这两个核心模块，解锁 Afrog 的完全体形态。

大家好，这里是 **Afrog 官方**。
前两期我们讲了安装和命令行使用。今天我们要进入 Afrog 的**核心配置** —— `afrog-config.yaml`。
很多同学只用命令行参数，却忽略了配置文件，导致无法检测**无回显漏洞 (OOB)**，也收不到**实时通知**。
本篇教程将带你逐一解析配置文件中的两大核心模块：**Reverse (反连平台)** 与 **Webhook (通知)**。

## 📂 配置文件在哪里？

Afrog 的配置文件名为 `afrog-config.yaml`。
- **默认位置**：`~/.config/afrog/afrog-config.yaml` (用户主目录下的 .config 文件夹)
- **自动生成**：如果找不到，运行一次 `afrog`，它会自动生成默认文件。

你可以用记事本或 VS Code 打开它。

---

## 👁️ 核心一：Reverse (反连平台)

### 为什么必须配置它？
很多高危漏洞（如 Log4j2、Fastjson、Blind SSRF、Blind SQLi）触发后，服务器**不会返回任何错误信息**，而是默默执行命令。
这时候，我们需要让服务器去访问我们控制的一台机器（反连平台）。如果我们的机器收到了请求，就证明漏洞存在。
**如果不配置 Reverse 模块，Afrog 将无法检测这类高危漏洞！**

### 1. 配置 Ceye.io (推荐稳定)
去 [ceye.io](http://ceye.io) 注册个账号，拿到 `Identifier` (Domain) 和 `API Key`。

修改 `afrog-config.yaml`：
```yaml
reverse:
  ceye:
    api-key: "你的API_KEY"
    domain: "你的Identifier.ceye.io"
```
配置好后，扫描时无需额外参数，Afrog 会自动使用它来检测无回显漏洞。

### 2. 配置 Dnslog.cn (免费快捷)
如果你只是临时用用，可以用 Dnslog.cn。
```yaml
reverse:
  dnslogcn:
    domain: "dnslog.cn"
```

### 3. 自建平台 (进阶玩家)
如果你有团队自建的反连平台（如 Xray、Revsuit、Alphalog），也可以在这里配置：

**Xray 自建平台：**
```yaml
reverse:
  xray:
    x_token: "你的xray token"
    domain: "你的反连域名"
    api_url: "http://x.x.x.x:8777"
```

> **想学习如何编写 OOB PoC？**
> 本文只讲配置。如果你想学习如何编写 OOB 漏洞脚本，或者了解新版 OOB 的去重原理，请阅读：
> [Afrog Wiki: OOB 体系大升级与 PoC 编写指南](https://github.com/zan8in/afrog/wiki/OOB-%E4%BD%93%E7%B3%BB%E5%A4%A7%E5%8D%87%E7%BA%A7%EF%BC%9A%E6%96%B0%E7%89%88%E5%86%99%E6%B3%95%E4%B8%8E%E8%AF%81%E6%8D%AE%E6%95%99%E7%A8%8B%EF%BC%88v3.3.9%EF%BC%89)

---

## 🔔 核心二：Webhook (实时通知)

扫描任务一跑就是几个小时，难道要一直盯着屏幕？
当然不！配置 Webhook，发现漏洞直接推送到你的手机。

**注意**：Webhook 是“配置 + 启用参数”两件事：在配置文件填好 Token 后，还需要在命令行加 `-dingtalk` 或 `-wecom` 才会生效。

### 1. 钉钉机器人 (DingTalk)
在钉钉群添加自定义机器人，安全设置选“关键词”（填 `afrog`），复制 Webhook URL 中的 `access_token`。

```yaml
webhook:
  dingtalk:
    tokens: 
      - "这里填access_token后面的字符"
    range: "high,critical" # 只推送高危和严重漏洞
```

**启用命令**：
```bash
afrog -T targets.txt -dingtalk
```

### 2. 企业微信机器人 (WeCom)
在企业微信群添加机器人，复制 Webhook URL 中的 `key`。

```yaml
webhook:
  wecom:
    tokens:
      - "这里填key后面的字符"
    range: "high,critical"
    markdown: true
```

**启用命令**：
```bash
afrog -T targets.txt -wecom
```

---

## ⚙️ 其他配置

### Server (Web UI 端口)
Afrog 自带一个简单的 Web 报告界面（使用 `-web` 启动）。你可以在这里修改默认端口：
```yaml
server: ":16868"
```

### Cyberspace (测绘配置)
目前支持 ZoomEye 的 Key 配置，用于后续版本对接测绘数据：
```yaml
cyberspace:
  zoom_eyes:
    - "你的ZoomEye Key"
```

---

## 📝 总结

配置文件 `afrog-config.yaml` 虽然平时看不见，但它决定了 Afrog 的上限：
1.  **Reverse**：决定了能不能扫出无回显的高危漏洞。
2.  **Webhook**：决定了你能不能第一时间收到漏洞情报。

把这两项配好，你的 Afrog 才算真正完成了“初始化”。

## 下期预告

工具配好了，接下来就是实战中最具创造性的部分 —— **编写 PoC**。
下一期**《PoC 编写入门》**，我们将手把手教你写出你的第一个 YAML 漏洞脚本！

---
*本文由 Afrog 官方原创，欢迎转发分享。*
