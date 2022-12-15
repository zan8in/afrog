<h1 align="center">afrog</h1>
<p align="center">A tool for finding vulnerabilities.<br/>❤️PoC <b>[759]</b> <br/>🐸Like please tag stars🌟⭐</p>

<p align="center" dir="auto">
  <a href="https://github.com/zan8in/afrog/releases">Download</a> •
  <a href="https://github.com/zan8in/afrog/blob/main/docs/GUIDE.md">Guide</a> •
  <a href="https://github.com/zan8in/afrog/blob/main/docs/CONTRIBUTION.md">Contribution</a> •
  <a href="https://github.com/zan8in/afrog/tree/main/pocs/afrog-pocs">PoC</a> •
  <!-- <a href="https://github.com/zan8in/afrog/blob/main/docs/POCLIST.md">LIST</a> • -->
  <a href="https://github.com/zan8in/afrog">中文文档</a>
</p>


## What is afrog

afrog is an excellent performance, fast and stable, PoC customizable vulnerability scanning (hole digging) tool. PoC involves CVE, CNVD, default password, information leakage, fingerprint identification, unauthorized access, arbitrary file reading, command execution, etc. It helps network security practitioners quickly verify and fix vulnerabilities in a timely manner.

## Features

* [x] open source
* [x] Fast, stable, low false positives
* [x] Detailed html bug report
* [x] PoC can be customized and updated stably 
* [x] Start the program to automatically update the local PoC library  
* [x] Active community exchange group
* [x] long-term maintenance

## Download afrog

### [Release Download](https://github.com/zan8in/afrog/releases)

## Guide

### [Go to Guide](https://github.com/zan8in/afrog/blob/main/GUIDE_en.md)

## Example

Basic usage
```
# scan a target
afrog -t http://127.0.0.1

# Scan multiple targets
afrog -T urls.txt

# Specify a scan report file
afrog -t http://127.0.0.1 -o result.html
```

Advanced usage

```
# Test PoC 
afrog -t http://127.0.0.1 -P ./test/ 
afrog -t http://127.0.0.1 -P ./test/demo.yaml 

# Scan by PoC keywords 
afrog -t http://127.0.0.1 -s tomcat,springboot,shiro 

# Scan by Poc Vulnerability Level 
afrog -t http://127.0.0.1 -S high,critical 

# Online update afrog-pocs 
afrog -up 

# Disable fingerprint recognition 
afrog -t http://127.0.0.1 -nf
```
## Screenshot
Console
![](https://github.com/zan8in/afrog/blob/main/images/scan-new.png)
Html report
![](https://github.com/zan8in/afrog/blob/main/images/report-new.png)

## 404Starlink
<img src="https://github.com/knownsec/404StarLink-Project/raw/master/logo.png" width="30%">

afrog has joined [404Starlink](https://github.com/knownsec/404StarLink)

## Disclaimer

This tool is only for **legally authorized** enterprise security construction behavior. If you need to test the usability of this tool, please build a target environment by yourself.

In order to avoid malicious use, all PoCs included in this project are theoretical judgments of vulnerabilities, there is no vulnerability exploitation process, and no real attacks or exploits will be launched on the target.

When using this tool for detection, you should ensure that the behavior complies with local laws and regulations and has obtained sufficient authorization. **Do not scan unauthorized targets. **

If you have any illegal behavior in the process of using this tool, you shall bear the corresponding consequences by yourself, and we will not bear any legal and joint responsibility.

Before installing and using this tool, please **must read carefully and fully understand the contents of each clause**. Restrictions, disclaimers or other clauses involving your significant rights and interests may be bolded or underlined to remind you to pay attention . Unless you have fully read, fully understood and accepted all the terms of this agreement, please do not install and use this tool. Your use behavior or your acceptance of this agreement in any other express or implied manner shall be deemed that you have read and agreed to be bound by this agreement.

