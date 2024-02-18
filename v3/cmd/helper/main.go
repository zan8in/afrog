package main

import (
	"encoding/base64"
	"fmt"

	fileutil "github.com/zan8in/pins/file"
)

// 读取文件并base64编码
func main() {
	files, err := fileutil.ReadFile("C:\\Users\\zanbi\\Downloads\\atfersotg.zip")
	if err != nil {
		fmt.Errorf(err.Error())
		return
	}

	result := ""
	for file := range files {
		result = fmt.Sprintf("%s%s", result, file)
	}

	base64Result := base64.StdEncoding.EncodeToString([]byte(result))
	fmt.Println(base64Result)
}
