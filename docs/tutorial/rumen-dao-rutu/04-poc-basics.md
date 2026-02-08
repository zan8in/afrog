# Afrog 官方教程(4)：炼金术士 - PoC 编写入门

> “授人以鱼不如授人以渔。” —— 学会编写 PoC，任何 CVE 都能成为你手中的武器。

大家好，这里是 **Afrog 官方**。
通过前三期教程，你已经是一个合格的“驾驶员”了。但真正的安全研究员，不仅会开车，还要会造车。
今天，我们将揭开 Afrog 核心能力的神秘面纱 —— **PoC (Proof of Concept)** 编写。

Afrog 的 PoC 采用 YAML 格式，结构清晰，逻辑简单。只要你懂一点 HTTP 协议，就能轻松上手。

## 🧬 PoC 的解剖学：三大件

一个标准的 Afrog PoC 文件主要由三个部分组成：

1.  **id**: 身份证号（如 `CVE-2022-1234`）。
2.  **info**: 详细信息（名字、作者、危害等级、描述）。
3.  **rules** & **expression**: 核心逻辑（怎么发包，怎么判断）。

我们来看一个最简单的例子（假设我们要检测一个网站是否存在 `/admin/config.xml` 信息泄露）：

```yaml
id: sensitive-config-disclosure

info:
  name: 敏感配置文件泄露
  author: afrog-team
  severity: high

rules:
  r0:
    request:
      method: GET
      path: /admin/config.xml
    expression: response.status == 200 && response.body.bcontains(b"db_password")

expression: r0()
```

看懂了吗？
- `rules` 定义了一个规则 `r0`：向 `/admin/config.xml` 发送 GET 请求。
- `expression` 判断：如果状态码是 200 **并且** 响应体里包含 `db_password`，则认为漏洞存在。
- 最后的 `expression: r0()` 告诉 Afrog 执行这个规则。

---

## 🛠️ 手把手写一个 PoC

假设现在爆出了一个新漏洞：**某 CMS 的 `/api/version` 接口泄露了数据库账号**。
特征是：访问该接口，返回内容包含 `root:`。

### 第一步：定义 ID 和 Info
新建文件 `cms-info-leak.yaml`：
```yaml
id: cms-info-leak
info:
  name: CMS Database Info Leak
  author: me
  severity: critical
```

### 第二步：构造请求 (Request)
在 `rules` 下定义请求包。
```yaml
rules:
  r1:
    request:
      method: GET
      path: /api/version
      headers:
        User-Agent: Mozilla/5.0
```

### 第三步：编写判断逻辑 (Expression)
我们需要判断两点：
1.  请求成功（200）。
2.  内容里有 `root:`。

```yaml
    expression: response.status == 200 && response.body.bcontains(b"root:")
```

### 第四步：组合
别忘了最后一行：
```yaml
expression: r1()
```

### 完整代码
```yaml
id: cms-info-leak
info:
  name: CMS Database Info Leak
  author: me
  severity: critical

rules:
  r1:
    request:
      method: GET
      path: /api/version
    expression: response.status == 200 && response.body.bcontains(b"root:")

expression: r1()
```

---

## 🔬 本地调试：`-P` 的妙用

写好了怎么测？不需要发给别人，Afrog 支持加载本地文件测试。
假设你的测试靶机是 `http://127.0.0.1:8080`：

```bash
afrog -t http://127.0.0.1:8080 -P ./cms-info-leak.yaml
```

如果漏洞存在，你会看到红色的告警；如果没反应，可以使用 `-pd` 查看详细的请求响应过程来排错：

```bash
# 查看详细发包过程
afrog -t http://127.0.0.1:8080 -P ./cms-info-leak.yaml -pd cms-info-leak
```

---

## 📝 常用表达式速查

| 表达式 | 含义 | 例子 |
| :--- | :--- | :--- |
| `response.status` | 状态码 | `response.status == 200` |
| `response.body.bcontains(b"...")` | 响应体包含（字节） | `response.body.bcontains(b"success")` |
| `response.headers["Server"]` | 获取 Header | `response.headers["Server"].contains("Apache")` |
| `response.latency` | 响应时间（毫秒） | `response.latency > 3000` (用于延时注入) |

注意：`bcontains` 前面的 `b` 代表字节流处理，在处理中文或二进制数据时更稳定，推荐默认使用。

## 下期预告

学会了简单的请求和判断，但遇到需要**登录后才能利用**的漏洞怎么办？遇到需要**先获取 Token 再攻击**的复杂场景怎么办？
下一期**《PoC 进阶技巧》**，我们将学习变量提取、多步攻击链以及指纹门控，让你成为真正的 PoC 大师！

---
*本文由 Afrog 官方原创，欢迎转发分享。*
