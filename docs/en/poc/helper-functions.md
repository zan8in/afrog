---
title: Helper Functions
slug: /docs/poc/helper-functions
lang: en
summary: Reference for common afrog PoC helper functions and usage boundaries.
status: published
source: docs/zh/poc/helper-functions.md
last_reviewed: 2026-09-16
---

This page collects the helper functions used most often in `afrog` PoCs, with emphasis on common scenarios and boundaries.

## Random value generation

### `randomInt`

Generates a random integer inside a range.

Example:

```yaml
set:
  r1: randomInt(10000, 99999)
  r2: randomInt(800000000, 1000000000)
```

Useful for:

- random accounts or parameters
- avoiding caching or duplicated values

### `randomLowercase`

Generates a random lowercase string of a given length.

Example:

```yaml
set:
  randstr: randomLowercase(6)
  randbody: randomLowercase(32)
```

Useful for:

- random filenames
- random boundaries
- dynamic content padding

## String processing

### `replaceAll`

Replaces all matching substrings.

```yaml
set:
  value: replaceAll("this is a test", "test", "Test")
```

### `toUpper`

Converts to uppercase:

```yaml
set:
  value: toUpper("admin")
```

### `toLower`

Converts to lowercase:

```yaml
set:
  value: toLower("Admin")
```

### `toUtf8`

Converts a string or byte sequence into UTF-8 text.

```yaml
expression: toUtf8(response.body).icontains("致远")
```

This is useful when the response encoding may be inconsistent.

## Matching helpers

### Byte matching

Common byte helpers:

- `bcontains`
- `ibcontains`
- `bmatches`
- `bsubmatch`
- `bsubmatchall`

Example:

```yaml
expression: response.body.bcontains(b"ThinkPHP")
expression: response.raw_header.bcontains(b"Set-Cookie")
```

### Text matching

Common text helpers:

- `contains`
- `icontains`
- `rmatches`
- `submatch`
- `submatchall`

Example:

```yaml
expression: response.headers["location"].icontains("dashboard")
```

### When to prefer text helpers

Prefer `response_text` with text helpers when you deal with:

- Chinese pages
- already decoded responses
- regex extraction

## Encoding and decoding

### `base64`

Base64-encodes a string or byte array.

```yaml
set:
  admin: base64("admin:admin")
  user: base64(bytes("user:user"))
```

### `base64Decode`

Base64-decodes a string or byte array.

```yaml
set:
  bodystr: base64Decode("REJTVEVQIFYzLjAgICAgIDM1NSA=")
```

### `urlencode`

URL-encodes a string or byte array.

```yaml
set:
  password: urlencode(base64("1234"))
```

### `urldecode`

Decodes URL-encoded content.

```yaml
set:
  url: urldecode("https%3A%2F%2Fexample%2Ecom")
```

### `hexdecode`

Decodes a hexadecimal string.

```yaml
set:
  hexbody: hexdecode("789c0bf06666e16200")
```

## Hashing and crypto

### `md5`

Computes an MD5 value.

```yaml
set:
  md5str1: md5(string(randomInt(10000000, 50000000)))
  md5str2: md5(randomLowercase(16))
  md5str3: md5("123456")
```

Useful for:

- signatures
- fixed digests
- target-specific authentication logic

## Usage suggestions

1. Prefer generating variables in `set`
2. Prefer `response_text` for text matching
3. Use `submatch` for single values and `submatchall` for multiple values
4. For validating multiple extracted values, combine with `brute`

## Related pages

- [PoC Quickstart](./quickstart.md)
- [PoC Syntax](./syntax.md)
