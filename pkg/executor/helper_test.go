package executor

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/scanstream"
)

const (
	helperEnv   = "GO_WANT_HELPER_PROCESS"
	scenarioEnv = "GO_HELPER_SCENARIO"
)

// TestMain 拦截 helper 子进程。
//
// 拦截必须发生在 m.Run() 之前：m.Run() 内部会调用 flag.Parse()，而执行器传给子进程的
// 是 afrog 的 CLI 参数（-t/-json-stream 等），标准 testing 的 flag 解析会因不认识的
// 参数直接打印 usage 并退出，所以这里在解析之前按环境变量分流。
func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		os.Exit(runHelper())
	}
	os.Exit(m.Run())
}

// runHelper 模拟 afrog 子进程：向 stdout 打印 NDJSON 事件，返回退出码。
// 场景由 GO_HELPER_SCENARIO 选择。
func runHelper() int {
	w := scanstream.NewWriter(os.Stdout, "local", "helper")
	switch os.Getenv(scenarioEnv) {
	case "events":
		w.Status("starting")
		w.Status("running")
		w.Result(&scanstream.ResultEvent{Severity: "high", PocID: "poc-1", PocName: "n", Target: "http://t"})
		w.Done("completed", &scanstream.Summary{Executed: 1, Found: 1})
	case "longline":
		// 单行 >200KB：验证执行器没有踩 bufio.Scanner 的 64KB 单行上限。
		w.Result(&scanstream.ResultEvent{
			Severity: "high",
			PocID:    "poc-long",
			PocName:  "long",
			Target:   "http://t",
			Evidence: &scanstream.Evidence{
				Exchanges: []scanstream.Exchange{{
					Request:  "GET / HTTP/1.1",
					Response: strings.Repeat("A", 250*1024),
					Matched:  true,
				}},
			},
		})
	case "noise":
		// 混入无法解析的行，验证它们不会影响后续事件。
		_, _ = os.Stdout.WriteString("this is not json\n")
		w.Log("info", "first")
		_, _ = os.Stdout.WriteString("{ broken json \n")
		w.Log("info", "second")
	case "fail":
		w.Log("info", "about to fail")
		return 3
	case "sleep":
		time.Sleep(60 * time.Second)
	case "taskid":
		// 把注入的 AFROG_TASK_ID 回传成一条事件，供测试断言。
		w.Log("info", os.Getenv(taskIDEnvVar))
	case "cwd":
		// 回传工作目录，供测试断言子进程没有继承父进程的 CWD。
		wd, _ := os.Getwd()
		w.Log("info", wd)
	}
	return 0
}
