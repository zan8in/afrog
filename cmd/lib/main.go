package main

import (
	"fmt"

	"github.com/zan8in/afrog"
)

func main() {
	err := afrog.NewScanner([]string{""}, afrog.Scanner{
		TargetsFile: "./nacos.txt",
		Search:      "nacos-detect",
		// PocFile:     "./pocs/temp/afrog-pocs/",
		Concurrency: 200,
		Output:      "./r.html",
	})
	fmt.Println(err)
}
