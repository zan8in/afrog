<h1 align="center">afrog</h1>
<p align="center">一款性能卓越、快速稳定、PoC 可定制化的漏洞扫描工具<br/>❤️不以物喜，不以己悲<br/>共 <b>[681]</b> 个 PoC <br/>🐸喜欢请点赞🌟⭐，不迷路</p>

<p align="center" dir="auto">
  <a href="https://github.com/zan8in/afrog/releases">下载</a> •
  <a href="https://github.com/zan8in/afrog/blob/main/docs/GUIDE.md">指南</a> •
  <a href="https://github.com/zan8in/afrog/blob/main/docs/CONTRIBUTION.md">贡献</a> •
  <a href="https://github.com/zan8in/afrog/tree/main/pocs/afrog-pocs">PoC</a> •
  <!-- <a href="https://github.com/zan8in/afrog/blob/main/docs/POCLIST.md">列表</a> • -->
  <a href="https://github.com/zan8in/afrog/blob/main/docs/README_en.md">English Doc</a>
</p>


## 什么是 afrog

afrog 是一款性能卓越、快速稳定、PoC 可定制的漏洞扫描工具，PoC 包含 CVE、CNVD、默认口令、信息泄露、指纹识别、未授权访问、任意文件读取、命令执行等多种漏洞类型，帮助网络安全从业者快速验证并及时修复漏洞。

## 特点

* [x] 开源
* [x] 快速、稳定、误报低
* [x] 详细的 html 漏洞报告
* [x] PoC 可定制化、稳定更新
* [x] 活跃的社区 [交流群](https://github.com/zan8in/afrog#%E4%BA%A4%E6%B5%81%E7%BE%A4)
* [x] 长期维护

## 示例

基本用法
```
# 扫描一个目标
afrog -t http://127.0.0.1

# 扫描多个目标
afrog -T urls.txt

# 指定漏扫报告文件
afrog -t http://127.0.0.1 -o result.html
```

高级用法

```
# 测试 PoC 
afrog -t http://127.0.0.1 -P ./test/ 
afrog -t http://127.0.0.1 -P ./test/demo.yaml 

# 按 PoC 关键字扫描 
afrog -t http://127.0.0.1 -s tomcat,springboot,shiro 

# 按 Poc 漏洞等级扫描 
afrog -t http://127.0.0.1 -S high,critical 

# 在线更新 afrog-pocs 
afrog --up 

# 禁用指纹识别，直接漏扫 
afrog -t http://127.0.0.1 --nf
```

## 截图
控制台
![](https://github.com/zan8in/afrog/blob/main/images/scan-new.png)
html 报告
![](https://github.com/zan8in/afrog/blob/main/images/report-new.png)

## 交流群

> 微信群请先添加 afrog 个人账号，并备注「afrog」，然后会把大家拉到 afrog 交流群中。

<img src="https://github.com/zan8in/afrog/blob/main/images/afrog.png" width="33%" />

## 404星链计划
<img src="https://github.com/knownsec/404StarLink-Project/raw/master/logo.png" width="30%">

afrog 现已加入 [404星链计划](https://github.com/knownsec/404StarLink)

## 免责声明

本工具仅面向**合法授权**的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

为避免被恶意使用，本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。**请勿对非授权目标进行扫描。**

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在安装并使用本工具前，请您**务必审慎阅读、充分理解各条款内容**，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。