package main

import (
	"fmt"
	"time"

	"github.com/zan8in/afrog/pkg/core"
	"github.com/zan8in/afrog/pkg/html"
)

func main() {
	ht := html.HtmlTemplate{}
	result := &core.Result{}
	filename := "demo2.html"
	ht.Filename = filename
	ht.Result = result

	err := ht.New()
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	ht.Append()

	time.Sleep(30 * time.Second)

	ht.Append()

	time.Sleep(30 * time.Second)

	ht.Append()
}
