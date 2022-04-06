<h1 align="center">afrog-pocs</h1>
<p align="center">POC，全称 Proof of Concept，指一段漏洞证明的说明或攻击样例<br/><br/>❤️POC 欢迎投递</p>

### 文件名

后缀 `.yaml`

```azure
CVE-2022-0202.yaml
```

### id

`[公司]产品-漏洞名称|CVE/CNVD-2021-XXXX`

```yaml
id: CVE-2022-0202  // good
id: seeyon-ajax-unauth  // good
id: zhiyuan-oa-unauth   // bad
```
### info

包含 `name`、`author`、`severity`、`description`、`reference`

```yaml
id: CVE-2022-22947
info:
  name: Spring Cloud Gateway Code Injection
  author: alex
  severity: critical
  description: |
    Spring Cloud Gateway 远程代码执行漏洞（CVE-2022-22947）发生在Spring Cloud Gateway...
    影响版本：Spring Cloud Gateway 3.1.x < 3.1.1 、Spring Cloud Gateway < 3.0.7
    官方已发布安全版本，请及时下载更新，下载地址：https://github.com/spring-cloud/spring-cloud-gateway
    FOFA：app="vmware-SpringBoot-framework"
  reference:
    - https://mp.weixin.qq.com/s/qIAcycsO_L9JKisG5Bgg_w	 // 必须是列表（数组）形式
```
name：漏洞名称，尽量英文且官方用语

author：大佬名称

severity: 漏洞等级，分为`critical`、`high`、`mideum`、`low`、`info`，请参考 [[National Vulnerability Database]](https://nvd.nist.gov/vuln/detail/cve-2020-11710)

description: （可选填）包含 `漏洞描述`、`漏洞影响`、`网络测绘`、`修复建议` 等

reference: （可选填）参考链接，必须数组形式，否则 poc 无法验证

### rules

示例

``` yaml
rules:
  r0:
    request:
      method: GET
      path: /phpinfo.php
    exppression: response.status == 200 && response.body.bcontains(b'PHP Version')
    stop_if_match: true
  r1:
    request:
      method: GET
      path: /info.php
    expresssion: response.status == 200 && response.body.bcontains(b'PHP Version')
    stop_if_mismatch: true
expression: r0() || r1()
```

rules：定义规则组

r0 / r1 :  子规则，自定义名称，不能重复

request:  表示 http request 请求

method:  表示 http request method 方法

path:  表示 http request URL 请求的 PATH

expresssion：子规则的验证表达式，用于验证 r0 或 r1 是否匹配规则。比如：`response.status == 200 && response.body.bcontains(b'PHP Version')`表示 request 请求返回状态码必须是 200 且 源码必须含有 `PHP Version` 关键字

stop_if_match: 如果匹配就停止

stop_if_mismatch：如果不匹配就停止

expression: 最外面的 `expression` 是 `rules` 的验证表达式，`r0() || r1()` 表示 `r0` 和 `r1` 两个规则，匹配一个表达式就为 `true`，代表漏洞存在。

> 如果 rules 表达式都是 `||`关系，比如：r0() || r1() || r2() ... ，默认执行 `stop_if_match` 动作。同理，如果表达式都是 `&&` 关系，默认执行 `stop_if_mismatch` 动作。

