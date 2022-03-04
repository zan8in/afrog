package main

import (
	"fmt"

	"github.com/zan8in/afrog/pkg/xfrog/gocel"
	poc "github.com/zan8in/afrog/pkg/xfrog/pocset"
)

type Runner struct {
}

func main() {

	gocel.NewCustomLib()

	resp := poc.GetRunnerPool().GocelResponse
	resp.Body = []byte("test.php")

	isvul, err := gocel.RunEval(`response.body.bcontains(b'test.php')`, map[string]interface{}{
		"response": resp,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(isvul)

}
