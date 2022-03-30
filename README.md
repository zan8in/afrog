<h1 align="center">afrog</h1>
<p align="center">A tool for finding vulnerabilities.<br/>❤️POC <b>[442]</b> <br/>🐸Like please tag stars🌟⭐</p>

<p align="center" dir="auto">
  <a href="https://github.com/zan8in/afrog/tree/main/afrog-pocs">POC directory</a> •
  <a href="https://github.com/zan8in/afrog/blob/main/README_zh.md">中文文档</a>
</p>
<p align="center"><img src="https://github.com/zan8in/afrog/blob/main/images/1.png"/></p>

<p align="center"><img src="https://github.com/zan8in/afrog/blob/main/images/2.png"/></p>

<p align="center"><img src="https://github.com/zan8in/afrog/blob/main/images/3.png"/></p>

### Features

* [x] Great performance, least requests, best results
* [x] Real-time display, scanning progress 
* [x] View `request` and `response` packets of scan results 
* [x] Command line version, easy to deploy and scan on `vps` 
* [x] API interface, easy access to other projects 
* [x] Long-term maintenance, update POC （./afrog-pocs ）

### [Download](https://github.com/zan8in/afrog/releases)


### Usage

```
afrog -h
```
This will display help for the tool. Here are all the switches it supports.
```
NAME:
   afrog 一个挖洞工具 -  

USAGE:
   afrog [命令]

VERSION:
   1.0.6

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --target value, -t value          指定扫描的URL/Host
   --targetFilePath value, -T value  指定需要扫描的URL/Host文件（一行一个）
   --PocsFilePath value, -P value    指定需要扫描的POC脚本的路径
   --Output value, -o value          输出扫描报告，比如：-o result.html
   --help, -h                        show help (default: false)
   --version, -v                     print the version (default: false)
```

### Running afrog

Scan a single target.
```
afrog -t http://example.com
```
Scan multiple targets.
```
afrog -T urls.txt
```
For example: `urls.txt `
```
http://example.com
http://test.com
http://github.com
```
Specify the POC script directory.
```
afrog -t http://example.com -P ./pocs
```
Output scan results to a file.
```
afrog -T urls.txt -P ./pocs -o ./result.txt
```
**🐱Recommendation: Linux users please use the sudo command or switch to root **

### API interface 

```go
package main

import (
	"fmt"

	"github.com/zan8in/afrog/internal/runner"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/core"
	"github.com/zan8in/afrog/pkg/html"
)

func main() {

	options := config.Options{
		Target:          "http://127.0.0.1", // 指定扫描的URL/Host
		TargetsFilePath: "",                 // 指定需要扫描的URL/Host文件（一行一个）
		PocsFilePath:    "./afrog-pocs",     // 指定需要扫描的POC脚本的路径（非必须，默认加载{home}/afrog-pocs）
		Output:          "./result.html",    // 输出扫描报告，比如：-o result.html
	}

	htemplate := &html.HtmlTemplate{}
	htemplate.Filename = options.Output
	if err := htemplate.New(); err != nil {
		return
	}

	err := runner.New(&options, func(result interface{}) {
		r := result.(*core.Result) // result 结构体里有你要的任何数据^^

		options.OptLock.Lock()
		defer options.OptLock.Unlock()

		options.CurrentCount++ // 扫描进度计数器（当前扫描数）

		if r.IsVul {
			r.PrintColorResultInfoConsole() // 如果存在漏洞，打印结果到 console

			if len(r.Output) > 0 {
				htemplate.Result = r
				htemplate.Append()
			}
		}

		// 扫描进度实时显示
		fmt.Printf("\r%d/%d | %d%% ", options.CurrentCount, options.Count, options.CurrentCount*100/options.Count)
	})
	if err != nil {
		fmt.Println(err)
	}
}
```


### Afrog configuration file
For more configuration, please modify  `afrog-config.yaml`，default location：`{home}/.config/afrog/afrog-config.yaml`
```
window: C:/Users/[yourname]/.config/afrog/
linux: /home/[yourname]/.config/afrog/
mac: /home/[yourname]/.config/afrog/
```
Here's everything afrog configures 
```
version: 1.0.6

poc_sizewaitgroup: 8                        # 漏洞探测的 worker 数量，可以简单理解为同时有 30 个 POC 在运行
target_sizewaitgroup: 8                     # 漏洞探测的 url 数量，可以简单理解为同时有 8 个 url 在扫描  

http:
  proxy: ""                                 # 漏洞扫描时使用的代理(仅支持sock5)，如: 127.0.0.1:8080
  dial_timeout: 10                          # 建立 tcp 连接的超时时间
  read_timeout: 10000ms                     # 服务器端超时设置
  write_timeout: 10000ms                    # 服务器端超时设置
  max_redirect: 5                           # 单个请求最大允许的跳转数
  max_idle: 1h
  concurrency: 4096                         # 最大并发总数
  max_conns_per_host: 10000
  max_responsebody_sizse: 2097152
  user_agent: ""                            # 自定义 User-Agent，默认随机选择

reverse:
  ceye:      # 目前只支持 ceye.io，请替换成自己的 api-key 和 domain，使用共享的会影响扫描结果
    api-key:       # 反连平台认证的 ApiKey, 独立部署时不能为空
    domain:                          # 反连平台的 domain
```
### POC
POC directory, default location：`{home}/afrog-pocs/`
```
window: C:/Users/[yourname]/afrog-pocs/
linux: /root/[yourname]/.config/afrog-pocs/
mac: /home/[yourname]/afrog-pocs/
```
POC script syntax reference   [xray 2.0](https://docs.xray.cool/#/guide/poc/v2)，The following is the basic structure of `CVE-2022-22947.yaml` 

```
id: CVE-2022-22947

# 信息部分
info:
  name: Spring Cloud Gateway Code Injection
  author: jweny
  severity: critical
    
# 脚本部分
transport: http

set:
  router: randomLowercase(8)
  rand1: randomInt(800000000, 1000000000)
  rand2: randomInt(800000000, 1000000000)
  
rules:
  r1:
    request:
      cache: true
      method: POST
      path: /actuator/gateway/refresh
      headers:
        Content-Type: application/json
    expression: response.status == 200

  r2:
    request:
      cache: true
      method: GET
      path: /actuator/gateway/routes/{{router}}
      headers:
        Content-Type: application/json
    expression: response.status == 200 && response.body.bcontains(bytes(string(rand1 + rand2)))
    
expression: r1() && r2()
```

### Difference between afrog and xray 2.0

|         xray          | afrog |
| :-------------------: | :---: |
|    transport: http    |   √   |
| transport: tcp  / udp |   ×   |
|          set          |   √   |
|       payloads        |   √   |
|         rules         |   √   |
|        details        |   ×   |

### Thank

[jjf012](https://github.com/jjf012) 、[jweny](https://github.com/jweny) 、[WAY29](https://github.com/WAY29)、 [xray](https://github.com/chaitin/xray)

