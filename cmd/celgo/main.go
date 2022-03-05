package main

import (
	"fmt"

	"github.com/zan8in/afrog/pkg/operators/celgo"
)

type Runner struct {
}

func main() {

	c := celgo.NewCustomLib()

	resp := make(map[string]interface{})
	resp["rand1"] = 123
	resp["rand2"] = 123

	c.WriteRuleSetOptions(resp)

	isvul, err := c.RunEval(`response.body.bcontains(bytes(string(rand1 + rand2)))`, map[string]interface{}{
		"response": resp,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(isvul)

}
