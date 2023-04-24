package main

import (
	"fmt"

	"github.com/dlclark/regexp2"
)

func main() {

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
