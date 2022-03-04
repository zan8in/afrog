package main

import (
	"fmt"

	"github.com/zan8in/afrog/pkg/xfrog/gocel"
	poc "github.com/zan8in/afrog/pkg/xfrog/pocset"
)

var (
	pocyml = "C:\\Users\\zanbi\\go\\src\\github.com\\zan8in\\afrog\\pocs\\demo.yml"
	err    error
)

func main() {
	gocel.NewCustomLib() // must
	runner := poc.GetRunnerPool()

	runner.Poc, err = poc.ParseYamlFile(pocyml)
	if err != nil {
		fmt.Println("==", err.Error(), runner.Poc)
		return
	}

	// ① 处理 Set（全局变量）
	gocel.AddRuleSetOptions(runner.Setkey, runner.Poc.Set)
	runner.UpdateVariableMap(runner.Setkey, runner.Poc.Set)

	// ② 处理 Payload（全局变量）
	for k, v := range runner.Poc.Payloads.Payloads {
		gocel.AddRuleSetOptions(runner.Payloadkey+"."+k, v)
		runner.UpdateVariableMap(runner.Payloadkey+"."+k, v)
	}

	// ③ 处理 Rules

	// ④ 处理 Expression
	//expression := runner.Poc.Expression

	// ⑤ 处理 Detail
	runner.UpdateDetail()

	// ③ 处理 Rules
	// rules.InitHttpRules(runner.Target, runner.Poc.Rules)

	fmt.Println("end.......")
}
