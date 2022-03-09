<h1 align="center">afrog</h1>
<p align="center">一款基于 YAML 语法模板的定制化快速漏洞扫描器<br/>❤️POC 投递接收进行中...<br/>[ zanbin168@qq.com ]<br/>一只快乐的青蛙！🐸</p>

### 特点

* [x] 支持 xray 2.0 核心语法

* [x] 长期维护、更新 POC（免费）

* [x] 轻松二次开发，整合到其他项目

* [x] 命令行版，方便部署在 `vps` 上扫描

* [ ] 网页版，增加用户体验

* [ ] 查看扫描结果的 `request` 和 `response` 数据包

### 用法
```
afrog -h
```
这将显示 afrog 的帮助，以下是所有支持的命令
```
NAME:
   afrog 是一款基于 YAML 语法模板的定制化快速漏洞扫描器 -  

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
   --Output value, -o value          输出扫描结果到文件
   --help, -h                        show help (default: false)
   --version, -v                     print the version (default: false)
```
### afrog 配置文件
更多配置，请修改 afrog-config.yaml，默认位置：{home}/.config/afrog/afrog-config.yaml
```
window: C:/Users/[yourname]/.config/afrog/
mac: /home/[yourname]/.config/afrog/
```
因为 linux 下必须 root 权限运行，所以 afrog-config.yaml 文件位置是
```
linux: /root/.config/afrog/
```

以下是 afrog 配置的所有内容
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
    api-key: bba3368c28118247ddc4785630b8fca0      # 反连平台认证的 ApiKey, 独立部署时不能为空
    domain: 7gn2sm.ceye.io                         # 反连平台的 domain
```
### POC 脚本
POC 目录，默认位置：{home}/afrog-pocs/
```
window: C:/Users/[yourname]/afrog-pocs/
mac: /home/[yourname]/afrog-pocs/
```
因为 linux 下必须 root 权限运行，所以 POC 目录位置是
```
linux: /root/.config/afrog-pocs/
```

POC 脚本语法参考  [xray 2.0](https://docs.xray.cool/#/guide/poc/v2)，以下是 `CVE-2022-22947.yaml` 基本结构

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

POC 语法 afrog 与 xray 2.0 区别

|         xray          | afrog |
| :-------------------: | :---: |
|    transport: http    |   √   |
| transport: tcp  / udp |   ×   |
|          set          |   √   |
|       payloads        |   √   |
|         rules         |   √   |
|        details        |   ×   |

### 运行 afrog
扫描单个目标
```
afrog -t http://example.com
```
扫描多个目标
```
afrog -T urls.txt
```
例如：urls.txt
```
http://example.com
http://test.com
http://github.com
```
指定 POC 脚本目录
```
afrog -t http://example.com -P ./pocs
```
输出扫描结果到文件
```
afrog -l urls.txt -P ./pocs -o ./result.txt
```
**🐱建议：Linux 用户请使用 sudo 命令或切换成 root**

### 感谢

[jjf012](https://github.com/jjf012) 、[jweny](https://github.com/jweny) 、[WAY29](https://github.com/WAY29)、 [xray](https://github.com/chaitin/xray)

