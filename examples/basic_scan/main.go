package main

import (
	"fmt"

	"github.com/zan8in/afrog/v3"
)

func main() {
	if err := afrog.NewScanner([]string{"http://example.com"}, afrog.Scanner{
		Severity:  "High",
		Search:    "hikvision",
		AppendPoc: []string{"D:\\GoWork\\github\\zan8in\\vulnerdb"},
	}); err != nil {
		fmt.Println(err.Error())
	}
}
