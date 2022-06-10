package main

import (
	"fmt"

	"github.com/zan8in/afrog/pkg/catalog"
	"github.com/zan8in/afrog/pkg/poc"
)

func main() {
	c := catalog.New("./pocs/afrog-pocs")
	allPocsYamlSlice, err := c.GetPocPath("./pocs/afrog-pocs")
	if err != nil && len(allPocsYamlSlice) == 0 {
		fmt.Println("未找到可执行脚本(POC)，请检查`默认脚本`或指定新の脚本(POC)")
	}
	fmt.Println(len(allPocsYamlSlice))
	for _, v := range allPocsYamlSlice {
		poc, err := poc.ReadPocs(v)
		if err != nil {
			fmt.Println(v)
		} else {
			fmt.Println(poc.Info.Name)
		}
	}
}
