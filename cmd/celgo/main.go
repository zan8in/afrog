package main

import (
	"fmt"

	"github.com/zan8in/afrog/pkg/xfrog/gocel"
)

func main() {

	gocel.Run(`response.body.bcontains(b'test.php')`, map[string]interface{}{}, func(result interface{}, err error) {
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		fmt.Println(result)
	})

}
