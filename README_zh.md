<h1 align="center">afrog</h1>
<p align="center">一个挖洞工具<br/>❤️POC 欢迎投递<br/>共 <b>[455]</b> 个<br/>🐸喜欢请点赞🌟⭐，不迷路</p>

<p align="center" dir="auto">
  <a href="https://github.com/zan8in/afrog/tree/main/afrog-pocs">POC 仓库</a> •
  <a href="https://github.com/zan8in/afrog">英文文档</a>
</p>

# 什么是 afrog

afrog 是一个挖洞工具。如果你想挖 SQL 注入、XSS、文件包含等漏洞，AWVS 做得更好，否则可以试试 afrog，免费不吃亏。

# 特点

* [x] 性能卓越，最少请求，最佳结果
* [x] 实时显示，扫描进度
* [x] 输出 html 报告，方便查看 `request` 和 `response`
* [x] 启动程序，自动更新本地 POC 库
* [x] 长期维护、更新 POC（[**afrog-pocs**](https://github.com/zan8in/afrog/tree/main/afrog-pocs)）
* [x] API 接口，轻松接入其他项目

# 下载

### [下载地址](https://github.com/zan8in/afrog/releases)

# 运行

扫描单个目标
```
afrog -t http://example.com -o result.html
```
![](https://github.com/zan8in/afrog/blob/main/images/onescan.png)

扫描多个目标

```
afrog -T urls.txt -o result.html
```
例如：`urls.txt`
```
http://example.com
http://test.com
http://github.com
```
![](https://github.com/zan8in/afrog/blob/main/images/twoscan.png)

测试单个 POC 文件

```
afrog -t http://example.com -P ./testing/poc-test.yaml -o result.html
```
![](https://github.com/zan8in/afrog/blob/main/images/threescan.png)

测试多个 POC 文件

```
afrog -t http://example.com -P ./testing/ -o result.html
```
![](https://github.com/zan8in/afrog/blob/main/images/fourscan.png)

输出 html 报告

![](https://github.com/zan8in/afrog/blob/main/images/2.png)

![](https://github.com/zan8in/afrog/blob/main/images/3.png)

# 交流群

<img src="http://binbin.run/afrog-release/images/afrog.jpg" width="33%" />
