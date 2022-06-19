package _go

import "fmt"

var Test []string

func init() {
	fmt.Println("init test.go")
	Test = append(Test, "world")
	fmt.Println(Size())
}
