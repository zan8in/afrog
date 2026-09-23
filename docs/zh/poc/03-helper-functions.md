<!--
title: 内置函数参考
slug: /docs/poc/helper-functions
lang: zh
summary: afrog PoC 内置函数参考，先按用途找工具，再按函数名精确速查。
status: published
source: docs/afrog-helper-function.md
last_reviewed: 2026-09-16
-->

这页不是让你把所有函数背下来，而是帮你在写 PoC 时更快找到“现在该用哪一个”。

可以把它当成两层入口：

- 外层：按用途找函数，例如“生成随机值”“做提取”“做编码”“做版本比较”
- 内层：按函数名精确速查，确认参数、返回值和常见边界

如果你还在确认 PoC 结构，先看 [PoC 语法参考](./02-syntax.md)；如果你已经知道自己需要某类处理，这页更适合直接查。

## 先按用途找函数

写 PoC 时，最常见的函数需求通常只有这几类：

| 需求 | 优先看哪些函数 |
| --- | --- |
| 生成随机变量 | `randomInt`、`randomLowercase` |
| 处理正文或头部文本 | `icontains`、`replaceAll`、`toUpper`、`toLower`、`trim` |
| 处理 bytes / 原始报文 | `bcontains`、`ibcontains`、`bstartsWith`、`toBytes` |
| 提取单值或多值 | `submatch`、`submatchall`、`bsubmatch`、`bsubmatchall` |
| 编码 / 解码 / 摘要 | `base64`、`base64Decode`、`urlencode`、`urldecode`、`hexdecode`、`md5`、`sha1` |
| 处理时间或版本 | `timestamp_second`、`timestamp_milli`、`year`、`month`、`day`、`versionCompare` |
| 处理 OOB / 反连 | `wait`、`jndi`、`oobCheck`、`oobCheckToken`、`oobEvidence` |
| 做加密或 gadget 生成 | `aesCBC`、`aesECB`、`aesECBNoPad`、`ysoserial` |

## 最常用工具箱

## 随机值生成

### `randomInt`

生成指定范围内的随机整数。

示例：

```yaml
set:
  r1: randomInt(10000, 99999)
  r2: randomInt(800000000, 1000000000)
```

适合场景：

- 构造随机账号、随机参数
- 需要动态避免缓存或重复值时
- 构造文件名、验证码、探测标识

### `randomLowercase`

生成指定长度的随机小写字符串。

示例：

```yaml
set:
  randstr: randomLowercase(6)
  randbody: randomLowercase(32)
```

适合场景：

- 随机文件名
- 随机边界串
- 动态内容填充

## 提取与匹配

这一组是最值得优先掌握的，因为 PoC 里大量逻辑都在“判断命中”和“把前一步结果传给下一步”。

## 字符串处理

### `replaceAll`

替换字符串中的全部匹配项。

```yaml
set:
  value: replaceAll("this is a test", "test", "Test")
```

### `toUpper`

转大写：

```yaml
set:
  value: toUpper("admin")
```

### `toLower`

转小写：

```yaml
set:
  value: toLower("Admin")
```

### `toUtf8`

将字符串或字节流转换为 UTF-8 文本。

```yaml
expression: toUtf8(response.body).icontains("致远")
```

当响应可能存在编码问题时，这个函数很有价值。

## 匹配函数

### 字节匹配

常见字节函数：

- `bcontains`
- `ibcontains`
- `bmatches`
- `bsubmatch`
- `bsubmatchall`

示例：

```yaml
expression: response.body.bcontains(b"ThinkPHP")
expression: response.raw_header.bcontains(b"Set-Cookie")
```

### 文本匹配

常见文本函数：

- `contains`
- `icontains`
- `rmatches`
- `submatch`
- `submatchall`

示例：

```yaml
expression: response.headers["location"].icontains("dashboard")
```

### 什么时候优先用文本函数

如果你面对的是：

- 中文页面
- 已按 charset 解码的响应
- 正则提取

优先使用 `response_text` 搭配文本函数。

### `submatch`

提取第一个命名捕获结果，返回 `map[string]string`。

```yaml
output:
  web_title: '"<title>(?P<title>.+)</title>"'.submatch(response_text)
```

适合场景：

- 提取单个 token
- 提取单个版本号
- 从页面标题、隐藏字段、JSON 字段里拿一个值

### `submatchall`

提取全部命名捕获结果，返回 `map[string][]string`。

```yaml
output:
  id_matches: '"\"id\":\"(?P<tid>[0-9]+)\""'.submatchall(response_text)
```

适合场景：

- 一次提取多条 ID
- 后续需要配合 `brute` 逐个验证

### `bsubmatch` / `bsubmatchall`

和 `submatch` / `submatchall` 作用一致，但目标是 bytes 数据。

更适合：

- `response.raw_header`
- 明确是 ASCII / 二进制数据的响应体
- 暂时不想依赖 charset 解码时

经验上：

- 文本页面优先 `submatch(response_text)`
- 原始头部、原始 bytes 优先 `bsubmatch`

## 编码与解码

### `base64`

对字符串或字节数组做 Base64 编码。

```yaml
set:
  admin: base64("admin:admin")
  user: base64(bytes("user:user"))
```

### `base64Decode`

对字符串或字节数组做 Base64 解码。

```yaml
set:
  bodystr: base64Decode("REJTVEVQIFYzLjAgICAgIDM1NSA=")
```

### `urlencode`

对字符串或字节数组进行 URL 编码。

```yaml
set:
  password: urlencode(base64("1234"))
```

### `urldecode`

对 URL 编码内容进行解码。

```yaml
set:
  url: urldecode("https%3A%2F%2Fexample%2Ecom")
```

### `hexdecode`

对十六进制字符串进行解码。

```yaml
set:
  hexbody: hexdecode("789c0bf06666e16200")
```

### `hex`

把字符串或 bytes 转成十六进制字符串。

### `toBytes`

把字符串转成 bytes，适合你需要把字符串显式送进 bytes 函数时。

```yaml
expression: response.body.bcontains(toBytes("admin"))
```

## 摘要与密码学

### `md5`

用于生成 MD5 值。

```yaml
set:
  md5str1: md5(string(randomInt(10000000, 50000000)))
  md5str2: md5(randomLowercase(16))
  md5str3: md5("123456")
```

适合场景：

- 构造签名
- 生成固定摘要
- 兼容目标系统的鉴权逻辑

### `sha1`

计算 SHA1，支持字符串和 bytes。

### `aesCBC`

执行 AES-CBC 加密，适合需要按目标协议构造密文参数的场景。

### `aesECB` / `aesECBNoPad`

执行 AES-ECB 加密，是否补齐取决于函数变体。

### `pkcs7Pad` / `zeroPad`

做分组加密前的 padding 处理。更偏进阶，一般在你已经明确知道目标算法和块大小时才会用到。

## 文本处理与转换

### `substr`

按起止位置截取字符串或 bytes。

### `trim`

去除首尾空白字符。

### `printable`

将字符串变成更适合打印或展示的形式。

### `length`

获取字符串或 bytes 长度。

### `repeat`

重复字符串若干次。

### `decimal`

按指定进制处理字符串值，适合和某些编码、长度或协议字段拼装一起使用。

### `toUintString`

将字符串按指定格式转换成无符号整数字符串，更偏协议级处理场景。

## 时间、版本与指纹

### 时间函数

当前可用：

- `year`
- `shortyear`
- `month`
- `day`
- `timestamp_second`
- `timestamp_milli`

适合场景：

- 构造时间戳参数
- 拼装文件名
- 生成与当前时间相关的验证值

### `versionCompare`

做版本比较，适合：

- 指纹提取出版本号后判断是否在漏洞区间内
- 对多版本产品做精确过滤

### `faviconHash`

对 favicon 内容做哈希，适合用来辅助识别产品或后台。

## OOB 与等待类函数

### `wait`

常用于 reverse / OOB 对象等待命中。

### `jndi`

用于 JNDI 相关反连场景。

### `oobCheck` / `oobCheckToken`

显式检查 OOB 是否命中。适合你想把 OOB 判断写得更可控的时候。

### `oobEvidence`

读取最近一次 OOB 命中的证据摘要，适合写入输出或调试。

### `sleep`

主动等待若干秒。一般只在目标状态变化确实需要等待时使用，不建议滥用。

## 进阶与专项函数索引

这部分不是大多数 PoC 每次都要用，但当你已经知道目标场景时，它们会很有价值。

### 上传清理辅助

- `jspDelete`
- `phpDelete`
- `aspxDelete`
- `aspDelete`

适合上传类漏洞验证后生成清理请求。

### 统计 / 计数

- `bcount`
- `rcount`

适合判断某个特征在正文里出现了多少次。

### gadget / 利用载荷生成

- `ysoserial`

适合 Java 反序列化相关场景。

## 使用建议

1. 变量生成优先放在 `set`
2. 中文页面、已解码正文、正则提取时，优先用 `response_text`
3. 提取单值时用 `submatch` / `bsubmatch`，提取多值时用 `submatchall` / `bsubmatchall`
4. 多值遍历验证时，优先组合 `submatchall + brute`
5. 不要一上来就用进阶加密或 gadget 函数，先把最小 PoC 跑通
6. 需要 bytes 函数时，先确认你面对的是 `response.body` / `response.raw` / `response.raw_header` 还是文本内容

## 最值得先记住的 10 个函数

如果你不想一次记很多，先熟悉这 10 个就够支撑大多数 PoC：

- `randomInt`
- `randomLowercase`
- `icontains`
- `bcontains`
- `submatch`
- `submatchall`
- `base64`
- `urlencode`
- `md5`
- `versionCompare`

> **← 上一篇：** [PoC 语法参考](./02-syntax.md) ｜ **本手册首页：** [PoC 编写快速开始](./01-quickstart.md) ｜ **下一篇 →：** [requires 指纹门控](./04-requires.md)
