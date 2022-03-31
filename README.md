<h1 align="center">afrog</h1>
<p align="center">A tool for finding vulnerabilities.<br/>❤️POC <b>[442]</b> <br/>🐸Like please tag stars🌟⭐</p>

<p align="center" dir="auto">
  <a href="https://github.com/zan8in/afrog/tree/main/afrog-pocs">POC directory</a> •
  <a href="https://github.com/zan8in/afrog/blob/main/README_zh.md">中文文档</a>
</p>

# What is afrog

afrog is a tool for finding vulnerabilities. If you want to finding  vulnerabilities such as SQL injection, XSS, file inclusion, etc., AWVS does a better job. Otherwise, you can try afrog for free. 

# Features

* [x] Great performance, least requests, best results
* [x] Real-time display, scanning progress 
* [x] View `request` and `response` packets of scan results 
* [x] Start the program to automatically update the local POC library  
* [x] Long-term maintenance, update POC （[**afrog-pocs**](https://github.com/zan8in/afrog/tree/main/afrog-pocs) ）
* [x] API interface, easy access to other projects 

# Download afrog

### [Release](https://github.com/zan8in/afrog/releases)

# Running afrog

Scan a single target.

```
afrog -t http://example.com -o result.html
```
![](https://github.com/zan8in/afrog/blob/main/images/onescan.png)

Scan multiple targets.

```
afrog -T urls.txt -o result.html
```
For example: `urls.txt `
```
http://example.com
http://test.com
http://github.com
```
![](https://github.com/zan8in/afrog/blob/main/images/twoscan.png)

Test a single POC file

```
afrog -t http://example.com -P ./testing/poc-test.yaml -o result.html
```
![](https://github.com/zan8in/afrog/blob/main/images/threescan.png)

Test multiple POC files 

```
afrog -t http://example.com -P ./testing/ -o result.html
```
![](https://github.com/zan8in/afrog/blob/main/images/fourscan.png)

Output html report 

![](https://github.com/zan8in/afrog/blob/main/images/2.png)

![](https://github.com/zan8in/afrog/blob/main/images/3.png)

