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

本课的目标很明确：把 OOB **配好、跑通、看懂证据**。
如果你想系统学习“新版 OOB 体系大升级”的完整细节（旧写法对照、更多模板、排错清单、证据解释），建议配合阅读这篇：
[OOB 体系大升级：新版写法与证据教程（v3.3.9）](https://github.com/zan8in/afrog/wiki/OOB-%E4%BD%93%E7%B3%BB%E5%A4%A7%E5%8D%87%E7%BA%A7%EF%BC%9A%E6%96%B0%E7%89%88%E5%86%99%E6%B3%95%E4%B8%8E%E8%AF%81%E6%8D%AE%E6%95%99%E7%A8%8B%EF%BC%88v3.3.9%EF%BC%89)

### 先说“最新版 OOB”到底升级了什么？
如果你用过旧版 OOB，你可能见过一种“经典套路”：**触发 -> 等几秒 -> 去平台查一下有没有命中**。
它能用，但也有两个痛点：
- 证据不够清晰：只能说“命中/没命中”，很难解释“命中发生在何时、出现了几次、是不是重复记录”。
- 平台返回不稳定：有的返回窗口有限、有的会重复、有的只给 subdomain，不给完整 URL，导致你用 token/路径去验证时很难做得很严谨。

最新版 OOB 做了一次“底层升级”，但 **PoC 写法完全不需要变复杂**：
- **PoC 仍然只写 `{{oob.DNS}}/{{oob.HTTP}} + oobCheck(...) + oobEvidence()`**
- 但 Afrog 内部把 OOB 从“一坨 body 文本 contains”升级成了“记录条目 -> 去重 -> 事件缓存 -> 证据摘要”

你可以把它理解为：**扫描器自带一个轻量的“事件仓库（EventStore）”**：
- 同一个 filter 的命中会被缓存、去重、保留一段时间
- `oobEvidence()` 不再是“随便截一段平台 body”，而是更像“可复核的证据摘要 + 最近几条命中记录”

### 这一升级带来哪些优点？
用人话讲就是四个字：**更稳、更快**。
- **更稳**：平台重复返回、窗口滚动、记录格式差异时，误判/漏判风险更低
- **更快**：同一个 OOB filter 命中过一次，后续 `oobCheck()` 更容易做到“秒回”
- **证据更友好**：`oobEvidence()` 给出 `protocol/count/last_at` 以及“最近 N 条命中摘要”，复核更舒服
- **对老 PoC 更友好**：老用户只需要把旧函数/旧占位符迁到新写法即可（下面给你迁移清单）

### 配置方法（先把反连平台装上）
Afrog 支持多种反连平台，新手最常用的是 **Ceye.io**（稳定）和 **Dnslog.cn**（免费快捷）。
配置完成后，OOB PoC 才能真正工作：否则 `oobCheck(...)` 会一直返回 false（因为根本没有可用的反连平台）。

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

#### 3. Alphalog / Xray / Revsuit (进阶玩家)
如果你已经有团队平台/自建平台，可以按对应字段配置（字段名以最新版配置结构为准）：

**Alphalog：**
```yaml
reverse:
  alphalog:
    domain: "你的反连域名"
    api_url: "http(s)://你的alphalog-api"
```

**Xray：**
```yaml
reverse:
  xray:
    x_token: "你的xray token"
    domain: "你的反连域名"
    api_url: "http://x.x.x.x:8777"
```

**Revsuit：**
```yaml
reverse:
  revsuit:
    token: "你的Token"
    dns_domain: "dns.yourdomain.com"
    http_url: "http://yourdomain.com"
    api_url: "http://yourdomain.com/revsuit/api"
```

### 🔰 3 分钟跑通 OOB（新手必做）

很多人第一次写 OOB PoC 失败，不是 PoC 写错，而是 **平台没配好 / 不知道证据在哪里看**。
你按下面三步走，先把“最小闭环”跑通，再去写更复杂的 PoC。

#### 第一步：确认反连平台配置 OK
- 你至少要配好一个平台（推荐 Ceye，临时用可以 dnslog.cn）。
- 没配平台时：`oobCheck(...)` 基本都会一直返回 false。

#### 第二步：用一个最小 OOB PoC 测通
把下面 PoC 保存成一个文件（例如 `demo-oob-dns.yaml`），然后对一个你有权限测试的目标运行：

```yaml
id: demo-oob-dns

info:
  name: Demo OOB DNS
  author: your-name
  severity: info

rules:
  r0:
    request:
      method: GET
      path: /?dns=ping%20{{oob.DNS}}
    expression: oobCheck("dns", 5)

expression: r0()
```

运行（示例）：
```bash
afrog -t http://example.com -P /path/to/demo-oob-dns.yaml
```

> 小提醒：这个 PoC 只是“演示最小闭环”。真实漏洞 PoC 通常要把“触发条件”与 “OOB 命中等待”组合，避免误报：
> `expression: response.status == 200 && oobCheck("dns", 5)`

#### 第三步：确认你能看到 `oob_evidence` 证据
命中后，你至少应该在这些地方之一看到 OOB 证明：
- 终端输出（命中结果里包含 `oob_evidence`）
- `report.html` 报告（漏洞详情会显示 OOB Evidence）
- AfrogWeb 报告（漏洞详情里显示 `oob_evidence`，便于复核与留证）

### 新版 OOB PoC 怎么写？（最推荐写法）
先记住两条铁律：
- PoC 里默认就有 `oob` 变量，不用再 `set: oob: oob()` 初始化
- 新版只推荐用 `oobCheck(...)` 做命中判断，用 `oobEvidence()` 做证据输出

你会用到的三个东西：
- `{{oob.DNS}}`：外带 DNS 域名（通常用于 `ping {{oob.DNS}}`、`nslookup {{oob.DNS}}`、JNDI 的弱验证等）
- `{{oob.HTTP}}`：外带 HTTP URL（通常用于 `curl {{oob.HTTP}}`、SSRF/命令执行外带等）
- `oobCheck(protocol, timeout)`：等待命中（`protocol` 推荐 `"dns"` 或 `"http"`，timeout 是秒；推荐：dns=5、http=3）

### 新版与旧版 PoC 的编写区别（老用户迁移指南）
下面这份表，你照着改就行：

1）**旧函数：`oobCheck(oob, protocol, timeout)` → 新函数：`oobCheck(protocol, timeout)`**
- 旧写法（示例）：
  - `expression: oobCheck(oob, oob.ProtocolDNS, 5)`
- 新写法（示例）：
  - `expression: oobCheck(oob.ProtocolDNS, 5)`
  - 或 `expression: oobCheck("dns", 5)`

2）**旧占位符：`{{oobDNS}}/{{oobHTTP}}` → 新占位符：`{{oob.DNS}}/{{oob.HTTP}}`**

3）**旧的 set 自映射可以删掉**
- 你可能见过这种历史包袱：
  - `set: oobDNS: oob.DNS`
  - `set: oobHTTP: oob.HTTP`
- 新版不需要，直接用 `{{oob.DNS}}/{{oob.HTTP}}` 即可

4）**一键迁移（推荐）**
如果你手里有很多旧 PoC，不想手工改，可以用 `-pocmigrate` 自动迁移旧语法到新版写法。
```bash
# 迁移单个 PoC 文件
afrog -pocmigrate /path/to/poc.yaml

# 迁移一个目录下的所有 PoC
afrog -pocmigrate /path/to/pocs/
```
小提醒：迁移只是“语法转换”，迁移完建议你用真实目标/靶场跑一遍，确认 PoC 扫描可用。

### 最推荐的新版 OOB PoC 模板（直接抄）

#### 模板 1：DNS 外带（弱验证，适合“只要命中就行”的场景）
```yaml
id: demo-oob-dns

info:
  name: Demo OOB DNS
  author: your-name
  severity: info

rules:
  r0:
    request:
      method: GET
      path: /?dns=ping%20{{oob.DNS}}
    expression: oobCheck("dns", 5)

expression: r0()
```

#### 模板 2：HTTP 外带（中验证，适合 SSRF/命令执行 curl/wget）
```yaml
id: demo-oob-http

info:
  name: Demo OOB HTTP
  author: your-name
  severity: info

rules:
  r0:
    request:
      method: GET
      path: /?http=curl%20{{oob.HTTP}}
    expression: oobCheck("http", 3)

expression: r0()
```

想看更多 OOB 模板（JNDI、XXE、SSRF、命令执行外带等）以及更完整的证据/排错讲解，可以看：
[OOB 体系大升级：新版写法与证据教程（v3.3.9）](https://github.com/zan8in/afrog/wiki/OOB-%E4%BD%93%E7%B3%BB%E5%A4%A7%E5%8D%87%E7%BA%A7%EF%BC%9A%E6%96%B0%E7%89%88%E5%86%99%E6%B3%95%E4%B8%8E%E8%AF%81%E6%8D%AE%E6%95%99%E7%A8%8B%EF%BC%88v3.3.9%EF%BC%89)


---

## 🔔 躺着收洞：Webhook 通知

扫描任务一跑就是几个小时，难道要一直盯着屏幕？
当然不！配置 Webhook，发现漏洞直接推送到你的手机。

使用提示：
- Webhook 是“配置 + 启用参数”两件事：在 `afrog-config.yaml` 配好 token 后，还需要在命令行加 `-dingtalk` 或 `-wecom` 才会推送。
- 配置文件默认位置：`~/.config/afrog/afrog-config.yaml`，如果你修改了其他位置，扫描时需要用 `-config` 指定。

### 钉钉机器人
1. 在钉钉群里添加“自定义机器人”。
2. 安全设置选择“加签”或“关键词”（关键词填 `afrog`）。
3. 复制 Webhook 地址，从中取出 `access_token=...` 后面的那段作为 token。

修改 `afrog-config.yaml`：
```yaml
webhook:
  dingtalk:
    tokens: 
      - "这里填access_token后面的那串字符"
    at_mobiles: [] # 需要@的人手机号
    at_all: false # 是否@所有人
    range: "high,critical" # 只推送高危和严重漏洞
```

启用推送（示例）：
```bash
afrog -t http://example.com -s spring -dingtalk
```

### 企业微信机器人（群机器人 Webhook）
企业微信这里的 `token` 指的是群机器人 Webhook URL 里的 `key`（不是应用的 `access_token`），形如：
`https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxxxxx`，把 `key=xxxxxx` 的 `xxxxxx` 填入 tokens。

修改 `afrog-config.yaml`：
```yaml
webhook:
  wecom:
    tokens:
      - "这里填key后面的那串字符"
    at_mobiles: [] # 需要@的人手机号（仅在 markdown=false 时生效）
    at_all: false # 是否@所有人
    range: high,critical # 推送的漏洞等级（命中即推）
    markdown: true # 是否使用 markdown 消息
```

启用推送（示例）：
```bash
afrog -t http://example.com -s spring -wecom
```

字段解释（企业微信）：

| 字段名 | 含义 | 默认值 |
| --- | --- | --- |
| tokens | 企业微信群机器人 Webhook key，可配置多个 | 空 |
| at_mobiles | 需要 @ 的成员手机号（仅在 markdown=false 时生效） | 空 |
| at_all | 是否 @ 全体成员 | false |
| range | 推送的漏洞等级过滤（示例：high,critical） | high,critical |
| markdown | 是否用 markdown 格式发送 | true |

这样，一旦扫出高危漏洞，你的手机就会收到推送，报告直接送到手边。

---

## 📝 总结一下

配置文件 `afrog-config.yaml` 是 Afrog 的灵魂。
1.  **OOB 配置**：让你能检测 Log4j2 等无回显漏洞（建议优先配好！）。
2.  **Webhook**：让你实现无人值守扫描（扫到洞自动推送）。

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
