package main

import (
	"fmt"
	"strings"

	"github.com/dlclark/regexp2"
)

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

	return
	v2 := `
	<SCRIPT LANGUAGE="JavaScript">
    <!--
        alert("附件上传成功");
	  //alert("附件上传成功");

	    window.opener.parent.document.all.infoPicSaveName.value+=";"+"2023042410151315678066363.jsp"+";";
		window.opener.parent.document.all.infoPicName.value+=";"+"shell.jsp"+";";

		window.opener.parent.document.all.infoPicName.height=parseInt(window.opener.parent.document.all.infoPicName.height)+25;
		//alert(window.opener.parent.document.all..height);
        

		//在调用页面的table列表中显示
        var path="information";
        var parentTable="infoPicTable";
        var fileNames="infoPicName";
        var saveNames="infoPicSaveName";
        var fileNum="0";
        var fileNameTemp="shell.jsp";

        var obj=eval("opener.window.document.all."+parentTable);

        obj.insertRow();
        var rowNum=obj.rows.length-1;
        var newNode=obj.rows(rowNum);
        newNode.bgColor="#FFFFFF";
        newNode.id="newInsertedTrid";
        for(var i=0;i<2;i++){
            newNode.insertCell();
		`

	v11 := ".*infoPicSaveName\\.value\\+=\";\"\\+\"(\\d+)\\.jsp\".*"
	re2 := regexp2.MustCompile(string(v11), 0)

	isMatch, err := re2.MatchString(string([]byte(v2)))
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(isMatch)
	}

	v1 := ".*infoPicSaveName\\.value\\+=\";\"\\+\"(?P<path>.+?)\\.jsp\".*"
	resultMap := make(map[string]string)
	re := regexp2.MustCompile(string(v1), regexp2.RE2)
	if m, _ := re.FindStringMatch(string([]byte(v2))); m != nil {
		gps := m.Groups()
		for n, gp := range gps {
			if n == 0 {
				continue
			}
			resultMap[gp.Name] = gp.String()
		}
	}
	fmt.Println(resultMap)
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

func main() {
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
