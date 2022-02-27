package poc

import (
	"fmt"
	"strings"

	"github.com/zan8in/afrog/pkg/xfrog/gocel"
)

type Runner struct {
	variablemap map[string]interface{}
	poc         *Poc
	setkey      string
	payloadkey  string
}

func InitRunner() Runner {
	return Runner{
		variablemap: make(map[string]interface{}),
		poc:         &Poc{},
		setkey:      "set",
		payloadkey:  "payload",
	}
}

var (
	pocyml = "C:\\Users\\zanbi\\go\\src\\github.com\\zan8in\\afrog\\pocs\\demo.yml"
	err    error
)

func RunPoc() {
	// step 1:
	// url := "http://example.com/"
	gocel.NewCustomLib() // must

	runner := InitRunner()

	// 读取url列表文件
	// urlsfile := "C:\\Users\\zanbi\\go\\src\\github.com\\zan8in\\afrog\\pocs\\urls.txt"
	// urllist, err := utils.ReadFileLineByLine(urlsfile)
	// if err != nil {
	// 	fmt.Println("=", err.Error())
	// 	return
	// }
	// for k, url := range urllist {
	// 	fmt.Println(k, url)
	// }

	runner.poc, err = ParseYamlFile(pocyml)
	if err != nil {
		fmt.Println("==", err.Error(), runner.poc)
		return
	}

	// ① 处理 Set（全局变量）
	gocel.AddRuleSetOptions(runner.setkey, runner.poc.Set)
	runner.UpdateVariableMap(runner.setkey, runner.poc.Set)

	// ② 处理 Payload（全局变量）
	for k, v := range runner.poc.Payloads.Payloads {
		gocel.AddRuleSetOptions(runner.payloadkey+"."+k, v)
		runner.UpdateVariableMap(runner.payloadkey+"."+k, v)
	}

	// ③ 处理 Rules

	// ④ 处理 Expression
	expression := runner.poc.Expression

	// ⑤ 处理 Detail
	runner.UpdateDetail()

	fmt.Println("author:", runner.poc.Detail.Author)
	fmt.Println("infos.id:", runner.poc.Detail.Fingerprint.Infos[0].Id)

	// expression = runner.poc.Set["username"].(string)

	// 执行GoCel表达式
	gocel.Run(expression, runner.variablemap, func(result interface{}, err error) {
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		fmt.Println(result)
	})
	// })
	// pocyml := "./pocs/demo.yml"
	// poc, err := ParseYamlFile(pocyml)
	// if err != nil {
	// 	fmt.Println("==", err.Error())
	// 	return
	// }
	// fmt.Println("name : ", poc.Name)
	// fmt.Println("Transport : ", poc.Transport)
	// fmt.Println("set : ", poc.Set)
	// fmt.Println("payloads : ", poc.Payloads)
	// fmt.Println("Rules : ", poc.Rules)
	// fmt.Println("Expression : ", poc.Expression)
	// fmt.Println("Detail : ", poc.Detail)
}

// 更新 Set/Payload VariableMap
// key map["set.username"] = ...  map["payload.ping.cmd"] = ...
func (runner Runner) UpdateVariableMap(key string, args map[string]interface{}) {
	for k, v := range args {
		switch vv := v.(type) {
		case int64:
			runner.variablemap[key+"."+k] = int(vv)
		default:
			runner.variablemap[key+"."+k] = fmt.Sprintf("%v", vv)
		}
	}
}

// 替换变量的值
// find string 规定要查找的值
// oldstr 规定被搜索的字符串
// newstr 规定替换的值
func (runner Runner) AssignVariableMap(find string) string {
	for k, v := range runner.variablemap {
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
	detail := runner.poc.Detail
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
	runner.poc.Detail = detail
}
