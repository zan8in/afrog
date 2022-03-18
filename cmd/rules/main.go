package main

import (
	"fmt"

	"github.com/zan8in/afrog/pkg/catalog"
)

func main() {
	c := catalog.New("../../afrog-pocs")
	allPocsYamlSlice, err := c.GetPocPath("../../afrog-pocs")
	if err != nil && len(allPocsYamlSlice) == 0 {
		fmt.Println("未找到可执行脚本(POC)，请检查`默认脚本`或指定新の脚本(POC)")
	}
	fmt.Println(len(allPocsYamlSlice))
}
