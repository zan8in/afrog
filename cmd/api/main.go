package main

import (
	"fmt"

	"github.com/zan8in/afrog/internal/runner"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/core"
)

func main() {
	options := config.Options{}
	options.Target = "127.0.0.1"
	options.PocsFilePath = "./afrog-pocs"
	options.Output = "./2.txt"

	err := runner.New(&options, func(result interface{}) {
		r := result.(*core.Result)

		options.OptLock.Lock()
		defer options.OptLock.Unlock()

		options.CurrentCount++

		if r.IsVul {
			r.PrintColorResultInfoConsole()

			if len(r.Output) > 0 {
				r.WriteOutput()
			}
		}

		fmt.Printf("\r%d/%d | %d%% ", options.CurrentCount, options.Count, options.CurrentCount*100/options.Count)
	})
	if err != nil {
		fmt.Println(err)
	}
}
