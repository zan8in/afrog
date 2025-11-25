package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/zan8in/gologger"
	"github.com/zan8in/retryablehttp"
)

// test retryablehttp.rawtcpdo
func main() {
	po := &retryablehttp.DefaultPoolOptions
	// 避免上游 SDK 在处理代理列表时触发并发通道错误，先不让池初始化解析代理
	// 后续我们在拿到客户端后手动设置 http.Transport 的代理
	po.Proxy = ""
	po.Timeout = 50
	po.Retries = 3
	po.DisableRedirects = true

	var RtryNoRedirect *retryablehttp.Client
	var err error

	retryablehttp.InitClientPool(po)
	if RtryNoRedirect, err = retryablehttp.GetPool(po); err != nil {
		gologger.Error().Msgf("[retryablehttp.GetPool] error: %v", err)
		return
	}

	req, err := retryablehttp.NewRequest(http.MethodPost, "http://honey.scanme.sh", nil)
	if err != nil {
		gologger.Error().Msgf("[retryablehttp.NewRequest] error: %v", err)
		return
	}
	req.Header.Set("Accept", "text/html,application/xhtml xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "zh-CN")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := RtryNoRedirect.RawTCPDo(req.Request)
	if err != nil {
		gologger.Error().Msgf("[retryablehttp.RawTCPDo] error: %v", err)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Error().Msgf("[io.ReadAll] error: %v", err)
		return
	}
	gologger.Info().Msgf("[respBody] \n%s", string(respBody))
	time.Sleep(3)
}

func main2() {
	// for _, line := range pocs.EmbedFileList {
	// 	b, err := pocs.EmbedReadFile(line)
	// 	if err != nil {
	// 		fmt.Printf(err.Error())
	// 		return
	// 	}
	// 	fmt.Println(string(b))
	// 	return
	// }
	// 	body := `--2ac719f8e29343df94aa4ab49e456061
	// Content-Disposition: form-data; name="dbId_v"

	// .
	// --2ac719f8e29343df94aa4ab49e456061
	// Content-Disposition: form-data; name="FID"

	// 2022
	// --2ac719f8e29343df94aa4ab49e456061
	// Content-Disposition: form-data; name="FAtt"; filename="../../../../uploadfiles/test.ashx."
	// Content-Type: text/plain

	// <%@ WebHandler Language="C#" Class="TestHandler" %>
	// 		using System;
	// 		using System.Web;
	// 		public class TestHandler : IHttpHandler {
	// 			public void
	// 			ProcessRequest (HttpContext context) {
	// 				context.Response.ContentType= "text/plain";
	// 				context.Response.Write("Test");
	// 			}
	// 			public bool IsReusable {
	// 				get {return false; }
	// 			}
	// 		}
	// --2ac719f8e29343df94aa4ab49e456061--
	// 	`
	// 	body = strings.ReplaceAll(body, `"`, `\"`)
	// 	body = strings.Replace(body, "\n", "\\r\\n\\\n", -1)
	// 	fmt.Println(body)

	// 	return
	// v2 := `
	// <SCRIPT LANGUAGE="JavaScript">
	// <!--
	//     alert("附件上传成功");
	//   //alert("附件上传成功");

	//     window.opener.parent.document.all.infoPicSaveName.value+=";"+"2023042410151315678066363.jsp"+";";
	// 	window.opener.parent.document.all.infoPicName.value+=";"+"shell.jsp"+";";

	// 	window.opener.parent.document.all.infoPicName.height=parseInt(window.opener.parent.document.all.infoPicName.height)+25;
	// 	//alert(window.opener.parent.document.all..height);

	// 	//在调用页面的table列表中显示
	//     var path="information";
	//     var parentTable="infoPicTable";
	//     var fileNames="infoPicName";
	//     var saveNames="infoPicSaveName";
	//     var fileNum="0";
	//     var fileNameTemp="shell.jsp";

	//     var obj=eval("opener.window.document.all."+parentTable);

	//     obj.insertRow();
	//     var rowNum=obj.rows.length-1;
	//     var newNode=obj.rows(rowNum);
	//     newNode.bgColor="#FFFFFF";
	//     newNode.id="newInsertedTrid";
	//     for(var i=0;i<2;i++){
	//         newNode.insertCell();
	// 	`
	v2 := "uid=33(www-data) gid=33(www-data) groups=33(www-data)"

	v11 := "((u|g)id|groups)=[0-9]{1,4}\\(.+\\)"
	re2 := regexp2.MustCompile(string(v11), 0)

	isMatch, err := re2.MatchString(string([]byte(v2)))
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(isMatch)
	}

	// v1 := "Location: \\./(?P<path>.+?)/"
	// resultMap := make(map[string]string)
	// re := regexp2.MustCompile(string(v1), regexp2.RE2)
	// if m, _ := re.FindStringMatch(string([]byte(v2))); m != nil {
	// 	gps := m.Groups()
	// 	for n, gp := range gps {
	// 		if n == 0 {
	// 			continue
	// 		}
	// 		resultMap[gp.Name] = gp.String()
	// 	}
	// }
	// fmt.Println(resultMap)
}

func main3() {
	var (
		resultMap = make(map[string]string)
	)
	v2 := `
		HTTP/1.1 302 Moved Temporarily
		Server: openresty/1.19.9.1
		Date: Mon, 06 Nov 2023 00:36:40 GMT
		Content-Length: 0
		Connection: close
		Pragma: No-cache
		Cache-Control: no-cache
		Expires: Thu, 01 Jan 1970 00:00:00 GMT
		X-Frame-Options: SAMEORIGIN
		Set-Cookie: JSESSIONID=cd7e684d49994b979278a1bcfac4f844; Path=/
		Set-Cookie: JSESSIONID=8iqjL45HTL9FTy1X2PI5hPIW.undefined; Path=/
		Set-Cookie: JSESSIONID=GtyMMddxS1a8y0OpxKBIAssG.undefined; Path=/
		Set-Cookie: 3B4A770C3AF55A22884CD9C5F462DF3E=A247F8FA27110B1BE0550000000000011699230909020; Expires=Wed, 08-Nov-2023 00:35:09 GMT; Path=/
		Set-Cookie: 36139225578082userId=A247F8FA27110B1BE055000000000001; Expires=Wed, 08-Nov-2023 00:35:09 GMT; Path=/
		Access-Control-Allow-Origin: *
	`
	v1 := `Set-Cookie: (?P<cookie>.+)`
	re := regexp2.MustCompile(string(v1), regexp2.RE2)
	if m, _ := re.FindStringMatch(string(v2)); m != nil {
		gps := m.Groups()
		for _, gp := range gps {
			fmt.Println(gp.Name, string(gp.Runes()))
		}
		// for n, gp := range gps {
		// 	// if n == 0 {
		// 	// 	continue
		// 	// }
		// 	resultMap[gp.Name] += gp.String()
		// 	fmt.Println(n, gp.Name, "-----", gp.String())
		// }
	}
	fmt.Println(resultMap)
}

func main1() {
	var (
		resultMap = make(map[string]string)
	)

	v2 := `HTTP/1.1 200 OK
	Date: Mon, 06 Nov 2023 13:27:12 GMT
	Server: Apache/2.4.39 (Win64) OpenSSL/1.1.1b mod_fcgid/2.3.9a mod_log_rotate/1.02
	X-Powered-By: PHP/7.3.4
	Set-Cookie: JSESSIONID=12321asdg31ds312sda3g123
	Set-Cookie: JSESSIONID=354738942357mc148jdfkjghsadflk
	Set-Cookie: 3B4A770C3AF55A22884CD9C5F462DF3E=A247F8FA27110B1BE0550000000000011699230909020%3B+Expires%3DWed%2C+08-Nov-2023+00%3A35%3A09+GMT%3B+Path%3D%2F
	Connection: close
	Content-Type: text/html; charset=UTF-8
	Content-Length: 4
	
	test`

	v1 := `Set-Cookie: (?P<cookie>.+)`

	re := regexp2.MustCompile(v1, regexp2.RE2)

	matches, err := re.FindStringMatch(v2)
	for err == nil && matches != nil {
		gps := matches.Groups()
		for n, gp := range gps {
			if n == 0 {
				continue
			}
			// fmt.Printf("%s Value: %s\n", gp.Name, matches.GroupByName(gp.Name).String())
			resultMap[gp.Name] += matches.GroupByName(gp.Name).String() + ";"
		}
		matches, err = re.FindNextMatch(matches)
	}

	for k, v := range resultMap {
		resultMap[k] = strings.TrimSuffix(v, ";")
	}

	fmt.Println(resultMap["cookie"])
}
