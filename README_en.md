<h1 align="center">afrog</h1>
<p align="center">A tool for finding vulnerabilities.<br/>❤️PoC <b>[499]</b> <br/>🐸Like please tag stars🌟⭐</p>

<p align="center" dir="auto">
  <a href="https://github.com/zan8in/afrog/tree/main/pocs/afrog-pocs">PoC directory</a> •
  <a href="https://github.com/zan8in/afrog">中文文档</a>
</p>


# What is afrog

afrog is an excellent performance, fast and stable, PoC customizable vulnerability scanning (hole digging) tool. PoC involves CVE, CNVD, default password, information leakage, fingerprint identification, unauthorized access, arbitrary file reading, command execution, etc. It helps network security practitioners quickly verify and fix vulnerabilities in a timely manner.

# Features

* [x] Based on xray kernel, not like xray ([afrog template syntax](https://github.com/zan8in/afrog/blob/main/pocs/afrog-pocs/README.md))
* [x] Great performance, least requests, best results
* [x] Real-time display, scanning progress 
* [x] View `request` and `response` packets of scan results 
* [x] Start the program to automatically update the local PoC library  
* [x] Long-term maintenance, update PoC （[**afrog-pocs**](https://github.com/zan8in/afrog/tree/main/pocs/afrog-pocs) ）
* [x] API interface, easy access to other projects 
* [x] For secondary development, refer to `cmd/afrog/main.go` or join **[communication group](https://github.com/zan8in/afrog#%E4%BA%A4%E6%B5%81%E7% BE%A4)** Consulting

# Download afrog

### [Release Download](https://github.com/zan8in/afrog/releases)

# Guide

### [Go to Guide](https://github.com/zan8in/afrog/blob/main/GUIDE_en.md)

# Example

Scan a single target.

```
afrog -t http://127.0.0.1 -o result.html
```
![](https://github.com/zan8in/afrog/blob/main/images/onescan.png)

Scan multiple targets.

```
afrog -T urls.txt -o result.html
```
For example: `urls.txt `
```
http://192.168.139.129:8080
http://127.0.0.1
```
![](https://github.com/zan8in/afrog/blob/main/images/twoscan.png)

Test a single PoC file

```
afrog -t http://127.0.0.1 -P ./testing/poc-test.yaml -o result.html
```
![](https://github.com/zan8in/afrog/blob/main/images/threescan.png)

Test multiple PoC files 

```
afrog -t http://127.0.0.1 -P ./testing/ -o result.html
```
![](https://github.com/zan8in/afrog/blob/main/images/fourscan.png)

Output html report 

![](https://github.com/zan8in/afrog/blob/main/images/2.png)

![](https://github.com/zan8in/afrog/blob/main/images/3.png)

# How to contribute to PoC?

### [View tutorial](https://github.com/zan8in/afrog/blob/main/CONTRIBUTION_en.md)

# Disclaimer

This tool is only for **legally authorized** enterprise security construction behavior. If you need to test the usability of this tool, please build a target environment by yourself.

In order to avoid malicious use, all PoCs included in this project are theoretical judgments of vulnerabilities, there is no vulnerability exploitation process, and no real attacks or exploits will be launched on the target.

When using this tool for detection, you should ensure that the behavior complies with local laws and regulations and has obtained sufficient authorization. **Do not scan unauthorized targets. **

If you have any illegal behavior in the process of using this tool, you shall bear the corresponding consequences by yourself, and we will not bear any legal and joint responsibility.

Before installing and using this tool, please **must read carefully and fully understand the contents of each clause**. Restrictions, disclaimers or other clauses involving your significant rights and interests may be bolded or underlined to remind you to pay attention . Unless you have fully read, fully understood and accepted all the terms of this agreement, please do not install and use this tool. Your use behavior or your acceptance of this agreement in any other express or implied manner shall be deemed that you have read and agreed to be bound by this agreement.

# 交流群

<img src="https://github.com/zan8in/afrog/blob/main/images/afrog.jpg" width="33%" />
