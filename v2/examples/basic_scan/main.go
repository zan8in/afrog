package main

import (
	"fmt"

	"github.com/zan8in/afrog"
)

func main() {
	if err := afrog.NewScanner([]string{"http://example.com"}, afrog.Scanner{}); err != nil {
		fmt.Println(err.Error())
	}
}
