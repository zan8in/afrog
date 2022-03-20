package main

import (
	"fmt"

	"github.com/zan8in/afrog/internal/runner"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/core"
)

func main() {

	options := config.Options{
		Target:          "127.0.0.1",    // 指定扫描的URL/Host
		TargetsFilePath: "./urls.txt",   // 指定需要扫描的URL/Host文件（一行一个）
		PocsFilePath:    "./afrog-pocs", // 指定需要扫描的POC脚本的路径（非必须，默认加载{home}/afrog-pocs）
		Output:          "./result.txt", // 输出扫描结果到文件
	}

	err := runner.New(&options, func(result interface{}) {
		r := result.(*core.Result) // result 结构体里有你要的任何数据^^

		options.OptLock.Lock()
		defer options.OptLock.Unlock()

		options.CurrentCount++ // 扫描进度计数器（当前扫描数）

		if r.IsVul {
			r.PrintColorResultInfoConsole() // 如果存在漏洞，打印结果到 console

			if len(r.Output) > 0 {
				r.WriteOutput() // 扫描结果写入文件
			}
		}

		// 扫描进度实时显示
		fmt.Printf("\r%d/%d | %d%% ", options.CurrentCount, options.Count, options.CurrentCount*100/options.Count)
	})
	if err != nil {
		fmt.Println(err)
	}
}
