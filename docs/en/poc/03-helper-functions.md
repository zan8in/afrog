<!--
title: Helper Functions
slug: /docs/poc/helper-functions
lang: en
summary: afrog PoC helper function reference, organized by real usage patterns and precise lookup.
status: published
source: docs/zh/poc/03-helper-functions.md
last_reviewed: 2026-09-16
-->

This page is not meant to make you memorize every helper. It is meant to help you find the right one faster while writing a PoC.

You can use it in two layers:

- the outer layer groups helpers by task, such as random values, extraction, encoding, or version checks
- the inner layer lets you look up a function by name and confirm what it is for

If you are still deciding how a PoC should be structured, read [PoC Syntax](./02-syntax.md) first. If you already know what kind of transformation or matching you need, this page is the faster lookup path.

## Find helpers by task first

In practice, most PoC authors only need a few helper categories:

| Need | Start with |
| --- | --- |
| Generate random values | `randomInt`, `randomLowercase` |
| Work with text in responses | `icontains`, `replaceAll`, `toUpper`, `toLower`, `trim` |
| Work with bytes or raw packets | `bcontains`, `ibcontains`, `bstartsWith`, `toBytes` |
| Extract one or many values | `submatch`, `submatchall`, `bsubmatch`, `bsubmatchall` |
| Encode, decode, or hash values | `base64`, `base64Decode`, `urlencode`, `urldecode`, `hexdecode`, `md5`, `sha1` |
| Compare versions or use time values | `timestamp_second`, `timestamp_milli`, `year`, `month`, `day`, `versionCompare` |
| Handle OOB / reverse checks | `wait`, `jndi`, `oobCheck`, `oobCheckToken`, `oobEvidence` |
| Build encrypted or gadget payloads | `aesCBC`, `aesECB`, `aesECBNoPad`, `ysoserial` |

## Core toolbox

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
- filenames, verification markers, or probe identifiers

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

## Extraction and matching

This is the group worth learning first, because a large share of PoC logic is really about “does this match” and “how do I pass this value to the next rule”.

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

### `submatch`

Extract the first named capture and return `map[string]string`.

```yaml
output:
  web_title: '"<title>(?P<title>.+)</title>"'.submatch(response_text)
```

Useful for:

- extracting one token
- extracting one version string
- pulling one value from HTML, headers, or JSON-like content

### `submatchall`

Extract all named captures and return `map[string][]string`.

```yaml
output:
  id_matches: '"\"id\":\"(?P<tid>[0-9]+)\""'.submatchall(response_text)
```

Useful for:

- collecting many IDs at once
- feeding multiple extracted values into `brute`

### `bsubmatch` / `bsubmatchall`

These are the byte-oriented variants of `submatch` and `submatchall`.

They fit better when you work with:

- `response.raw_header`
- clearly ASCII or binary response data
- content where you do not want to rely on charset decoding

As a rule of thumb:

- text pages: prefer `submatch(response_text)`
- raw headers or raw bytes: prefer `bsubmatch`

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

### `hex`

Convert a string or bytes value into a hexadecimal string.

### `toBytes`

Convert a string to bytes. Useful when you want to pass a string into byte-oriented helpers explicitly.

```yaml
expression: response.body.bcontains(toBytes("admin"))
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

### `sha1`

Compute SHA1 from strings or bytes.

### `aesCBC`

Perform AES-CBC encryption. Useful when the target expects ciphertext in a specific request parameter.

### `aesECB` / `aesECBNoPad`

Perform AES-ECB encryption, with or without padding depending on the variant.

### `pkcs7Pad` / `zeroPad`

Padding helpers for block ciphers. These are more advanced and mainly matter when you already know the algorithm and block size expected by the target.

## Text processing and conversion

### `substr`

Slice strings or bytes by start and end positions.

### `trim`

Trim leading and trailing whitespace.

### `printable`

Normalize a string into a more display-friendly form.

### `length`

Return the length of a string or bytes value.

### `repeat`

Repeat a string a fixed number of times.

### `decimal`

Process a string in a specific numeric base. Useful in some encoding or protocol-field construction cases.

### `toUintString`

Convert a string into an unsigned-integer string representation. This is more of a protocol-level helper than a day-one helper.

## Time, version, and fingerprint helpers

### Time helpers

Currently available:

- `year`
- `shortyear`
- `month`
- `day`
- `timestamp_second`
- `timestamp_milli`

Useful for:

- building timestamp parameters
- generating filenames
- creating time-linked probe values

### `versionCompare`

Compare versions. Useful when:

- you extracted a version and want to check whether it falls inside a vulnerable range
- you want more precise filtering than simple substring matching

### `faviconHash`

Hash favicon content, usually for lightweight product identification.

## OOB and waiting helpers

### `wait`

Commonly used with reverse or OOB objects to wait for a hit.

### `jndi`

Used in JNDI-related reverse scenarios.

### `oobCheck` / `oobCheckToken`

Explicitly check whether an OOB event has hit. Useful when you want tighter control over the OOB matching logic.

### `oobEvidence`

Read back the evidence summary of the latest OOB hit. Helpful for debugging or output.

### `sleep`

Wait for a number of seconds. Use it when the target really needs time for state changes, not as a default habit.

## Advanced and niche helper index

These are not used in every PoC, but become very useful once you already know the target scenario.

### Upload cleanup helpers

- `jspDelete`
- `phpDelete`
- `aspxDelete`
- `aspDelete`

Useful for cleanup requests after upload-based verification.

### Counting helpers

- `bcount`
- `rcount`

Useful when you care about how many times a pattern appears in a body.

### Gadget and exploit payload generation

- `ysoserial`

Useful in Java deserialization scenarios.

## Usage suggestions

1. Prefer generating variables in `set`
2. For Chinese pages, decoded bodies, or regex extraction, prefer `response_text`
3. Use `submatch` / `bsubmatch` for one value and `submatchall` / `bsubmatchall` for many values
4. For validating multiple extracted values, combine `submatchall` with `brute`
5. Do not start with advanced crypto or gadget helpers before the minimal PoC works
6. Before using byte helpers, confirm whether you are dealing with `response.body`, `response.raw`, `response.raw_header`, or already-decoded text

## The 10 helpers worth memorizing first

If you do not want to load too much at once, these ten already cover a large share of day-to-day PoC work:

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

> **← Previous:** [PoC Syntax](./02-syntax.md) ｜ **Handbook home:** [PoC Quickstart](./01-quickstart.md) ｜ **Next →:** [requires](./04-requires.md)
