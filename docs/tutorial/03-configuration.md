# Afrog 官方教程(3)：武装到牙齿 - 配置文件深度解析

> “看不见的威胁才是最致命的。” —— 开启 OOB 之眼，让盲注漏洞无所遁形。

大家好，这里是 **Afrog 官方**。
前两期我们讲了安装和命令行使用。今天我们要进入 Afrog 的**核心腹地** —— 配置文件。
在这里，你将解锁 Afrog 的完全体形态：**反连检测 (OOB)** 和 **实时通知**。

## 📂 配置文件在哪里？

Afrog 的配置文件名为 `afrog-config.yaml`。
- 默认位置：`~/.config/afrog/afrog-config.yaml` (用户主目录下的 .config 文件夹)
- 如果找不到，运行一次 `afrog`，它会自动生成。

你可以用记事本或 VS Code 打开它。

---

## 👁️ 开启“天眼”：反连平台 (Reverse/OOB)

### 什么是 OOB？
很多高危漏洞（如 Log4j2、Fastjson、Blind SSRF、Blind SQLi）触发后，服务器**不会返回任何错误信息**，而是默默执行命令。
这时候，我们需要让服务器去访问我们控制的一台机器（反连平台）。如果我们的机器收到了请求，就证明漏洞存在。

### 配置方法
Afrog 支持多种反连平台，最常用的是 **Ceye.io** 和 **Dnslog.cn**。

#### 1. 配置 Ceye.io (推荐稳定)
去 [ceye.io](http://ceye.io) 注册个账号，拿到 `Identifier` (Domain) 和 `API Key`。

修改 `afrog-config.yaml`：
```yaml
reverse:
  ceye:
    api-key: "你的API_KEY"
    domain: "你的Identifier.ceye.io"
```
配置好后，扫描时无需额外参数，Afrog 会自动使用它来检测无回显漏洞。

#### 2. 配置 Dnslog.cn (免费快捷)
如果你只是临时用用，可以用 Dnslog.cn。
```yaml
reverse:
  dnslogcn:
    domain: "dnslog.cn"
```

#### 3. 自建平台 (进阶)
如果你是红队大佬，可以使用 [Revsuit](https://github.com/revsuit/revsuit) 或 [Xray](https://docs.xray.cool/#/config/reverse) 的反连端。
```yaml
reverse:
  revsuit:
    token: "你的Token"
    dns_domain: "dns.yourdomain.com"
    http_url: "http://yourdomain.com"
    api_url: "http://yourdomain.com/revsuit/api"
```

---

## 🔔 躺着收洞：Webhook 通知

扫描任务一跑就是几个小时，难道要一直盯着屏幕？
当然不！配置 Webhook，发现漏洞直接推送到你的手机。

### 钉钉/企业微信机器人
以钉钉为例：
1.  在钉钉群里添加“自定义机器人”。
2.  安全设置选择“加签”或“关键词”（关键词填 `afrog`）。
3.  复制 Webhook 地址。

修改 `afrog-config.yaml`：
```yaml
webhook:
  dingtalk:
    tokens: 
      - "这里填access_token后面的那串字符"
    at_mobiles: [] # 需要@的人手机号
    range: "high,critical" # 只推送高危和严重漏洞
```
这样，一旦扫出高危漏洞，你的手机就会“叮”一声，报告直接送到手边。

---

## 🌐 自动寻敌：空间测绘联动

Afrog 支持联动 **ZoomEye** 自动寻找目标。
你需要去 ZoomEye 申请 API Key。

```yaml
cyberspace:
  zoom_eyes:
    - "你的ZoomEye_API_KEY"
```

使用方法：
```bash
# 搜索 100 个使用了 tomcat 的目标并自动扫描
afrog -cs zoomeye -q "app:tomcat" -qc 100
```
这简直是刷洞神器！

---

## 📝 总结一下

配置文件 `afrog-config.yaml` 是 Afrog 的灵魂。
1.  **OOB 配置**：让你能检测 Log4j2 等无回显漏洞（必配！）。
2.  **Webhook**：让你实现无人值守扫描。
3.  **Cyberspace**：让你拥有源源不断的扫描目标。

把这些配置好，你的 Afrog 就从“步枪”进化成了“自动制导导弹”。

## 下期预告

工具再好，也得有弹药。Afrog 内置的 PoC 虽然多，但面对新出的 0day 怎么办？
下一期**《PoC 编写入门》**，我们将手把手教你写出你的第一个 YAML 漏洞脚本！

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
