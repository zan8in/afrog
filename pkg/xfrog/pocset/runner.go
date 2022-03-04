package poc

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/zan8in/afrog/pkg/xfrog/gocel"
)

type Runner struct {
	Target        string
	TargetRequest *http.Request
	Variablemap   map[string]interface{}
	Poc           *Poc
	Setkey        string
	Payloadkey    string
	GocelRquest   *gocel.Request
	GocelResponse *gocel.Response
	GocelReverse  *gocel.Reverse
}

var (
	pocyml = "C:\\Users\\zanbi\\go\\src\\github.com\\zan8in\\afrog\\pocs\\demo.yml"
	err    error

	runnerPool = sync.Pool{
		New: func() interface{} {
			return &Runner{
				Target:        "http://example.com/",
				TargetRequest: &http.Request{},
				Variablemap:   make(map[string]interface{}),
				Poc:           &Poc{},
				Setkey:        "set",
				Payloadkey:    "payloads",
				GocelRquest:   &gocel.Request{},
				GocelResponse: &gocel.Response{},
				GocelReverse:  &gocel.Reverse{},
			}
		},
	}
)

func GetRunnerPool() *Runner {
	return runnerPool.Get().(*Runner)
}

func SetRunnerPool(newrunner Runner) {
	runnerPool.Put(&newrunner)
}

func RunPoc() {
	gocel.NewCustomLib() // must
	runner := GetRunnerPool()

	runner.Poc, err = ParseYamlFile(pocyml)
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
	runner.TargetRequest, _ = http.NewRequest("GET", runner.Target, nil)

	//for key, rule := range runner.Poc.Rules {
	key := "r1"
	rule := runner.Poc.Rules[key]
	ruleReq := rule.Request
	runnerRule := runner.Poc.Rules[key]

	// 覆盖header变量
	for k, v := range ruleReq.Headers {
		runnerRule.Request.Headers[k] = runner.AssignVariableMap(v)
	}

	// 覆盖path,body变量
	runnerRule.Request.Path = runner.AssignVariableMap(strings.TrimSpace(ruleReq.Path))
	runnerRule.Request.Body = runner.AssignVariableMap(strings.TrimSpace(ruleReq.Body))

	// 处理 path
	fmt.Println("===", runner.TargetRequest.URL.Path)
	if strings.HasPrefix(runnerRule.Request.Path, "/") {
		// 如果 path 是以 / 开头的， 取 dir 路径拼接
		runnerRule.Request.Path = strings.TrimRight(runner.TargetRequest.URL.Path, "/") + runnerRule.Request.Path
	} else if strings.HasPrefix(ruleReq.Path, "^") {
		// 如果 path 是以 ^ 开头的， uri 直接取该路径
		runnerRule.Request.Path = "/" + runnerRule.Request.Path[1:]
	}
	// 某些poc没有区分path和query，需要处理 ？？？
	runnerRule.Request.Path = strings.ReplaceAll(runnerRule.Request.Path, " ", "%20")
	runnerRule.Request.Path = strings.ReplaceAll(runnerRule.Request.Path, "+", "%20")

	runner.Poc.Rules[key] = runnerRule

	runner.Variablemap["request"] = runnerRule.Request

	// 克隆 request
	reqUrl := fmt.Sprintf("%s://%s%s", runner.TargetRequest.URL.Scheme, runner.TargetRequest.URL.Host, runnerRule.Request.Path)
	runner.SendGetRequest(reqUrl, runnerRule)

	// isVul, err := runner.CheckRule(k, rule)
	// if err != nil {
	// 	fmt.Println("该poc脚本有误！【"+runner.Poc.Name+"】,", err.Error())
	// 	return
	// }
	// gocel.AddRuleIsVulOptions(key, isVul)
	//}

	// ④ 处理 Expression
	expression := runner.Poc.Expression

	// ⑤ 处理 Detail
	runner.UpdateDetail()

	// fmt.Println("author:", runner.Poc.Detail.Author)
	// fmt.Println("infos.id:", runner.Poc.Detail.Fingerprint.Infos[0].Id)
	// fmt.Println("r2.header:", runner.Poc.Rules["r2"].Request.Headers["Content-Type"])

	// 执行GoCel表达式
	gocel.Run(expression, runner.Variablemap, func(result interface{}, err error) {
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		fmt.Println("总结果：", result)
	})

	gocel.Run(rule.Expression, runner.Variablemap, func(result interface{}, err error) {
		if err != nil {
			fmt.Println(err.Error())
			// return
		}
		gocel.AddRuleIsVulOptions(key, result.(bool))
	})
}

// 更新 Set/Payload VariableMap
// key map["set.username"] = ...  map["payload.ping.cmd"] = ...
func (runner Runner) UpdateVariableMap(key string, args map[string]interface{}) {
	for k, v := range args {
		switch vv := v.(type) {
		case int64:
			runner.Variablemap[key+"."+k] = int(vv)
		default:
			runner.Variablemap[key+"."+k] = fmt.Sprintf("%v", vv)
		}
	}
}

// 替换变量的值
// find string 规定要查找的值
// oldstr 规定被搜索的字符串
// newstr 规定替换的值
func (runner Runner) AssignVariableMap(find string) string {
	for k, v := range runner.Variablemap {
		_, isMap := v.(map[string]string)
		if isMap {
			continue
		}
		newstr := fmt.Sprintf("%v", v)
		oldstr := "{{" + k + "}}"
		if !strings.Contains(find, oldstr) {
			continue
		}
		find = strings.ReplaceAll(find, oldstr, newstr)
		break
	}
	return find
}

// 更新Detail
func (runner Runner) UpdateDetail() {
	detail := runner.Poc.Detail
	detail.Author = runner.AssignVariableMap(detail.Author)
	for k, link := range detail.Links {
		detail.Links[k] = runner.AssignVariableMap(link)
	}
	for k, info := range detail.Fingerprint.Infos {
		detail.Fingerprint.Infos[k].Id = runner.AssignVariableMap(info.Id)
		detail.Fingerprint.Infos[k].Name = runner.AssignVariableMap(info.Name)
		detail.Fingerprint.Infos[k].Type = runner.AssignVariableMap(info.Type)
		detail.Fingerprint.Infos[k].Version = runner.AssignVariableMap(info.Version)
	}
	detail.Fingerprint.HostInfo.Hostname = runner.AssignVariableMap(detail.Fingerprint.HostInfo.Hostname)
	detail.Vulnerability.Id = runner.AssignVariableMap(detail.Vulnerability.Id)
	detail.Vulnerability.Match = runner.AssignVariableMap(detail.Vulnerability.Match)
	runner.Poc.Detail = detail
}

func (runner Runner) CheckRule(key string, rule Rule) (bool, error) {
	ruleReq := rule.Request
	runnerRule := runner.Poc.Rules[key]

	// 覆盖header变量
	for k, v := range ruleReq.Headers {
		runnerRule.Request.Headers[k] = runner.AssignVariableMap(v)
	}

	// 覆盖path,body变量
	runnerRule.Request.Path = runner.AssignVariableMap(strings.TrimSpace(ruleReq.Path))
	runnerRule.Request.Body = runner.AssignVariableMap(strings.TrimSpace(ruleReq.Body))

	// 处理 path
	fmt.Println("===", runner.TargetRequest.URL.Path)
	if strings.HasPrefix(runnerRule.Request.Path, "/") {
		// 如果 path 是以 / 开头的， 取 dir 路径拼接
		runnerRule.Request.Path = strings.TrimRight(runner.TargetRequest.URL.Path, "/") + runnerRule.Request.Path
	} else if strings.HasPrefix(ruleReq.Path, "^") {
		// 如果 path 是以 ^ 开头的， uri 直接取该路径
		runnerRule.Request.Path = "/" + runnerRule.Request.Path[1:]
	}
	// 某些poc没有区分path和query，需要处理 ？？？
	runnerRule.Request.Path = strings.ReplaceAll(runnerRule.Request.Path, " ", "%20")
	runnerRule.Request.Path = strings.ReplaceAll(runnerRule.Request.Path, "+", "%20")

	runner.Poc.Rules[key] = runnerRule

	runner.Variablemap["request"] = runnerRule.Request

	// 克隆 request
	reqUrl := fmt.Sprintf("%s://%s%s", runner.TargetRequest.URL.Scheme, runner.TargetRequest.URL.Host, runnerRule.Request.Path)
	runner.SendGetRequest(reqUrl, runnerRule)

	return gocel.RunEval(rule.Expression, runner.Variablemap)
}
