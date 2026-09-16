---
title: 内置函数参考
slug: /docs/poc/helper-functions
lang: zh
summary: afrog PoC 常用内置函数与使用边界的参考页。
status: published
source: docs/afrog-helper-function.md
last_reviewed: 2026-09-16
---

本页整理 `afrog` PoC 中最常用的一批内置函数，重点放在高频函数和使用边界上。

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

## 使用建议

1. 变量生成优先放在 `set`
2. 文本匹配优先考虑 `response_text`
3. 提取单值时用 `submatch`，提取多值时用 `submatchall`
4. 多值遍历验证时，推荐结合 `brute`

## 相关文档

- [PoC 编写快速开始](./quickstart.md)
- [PoC 语法参考](./syntax.md)
