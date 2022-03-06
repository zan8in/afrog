package core

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/operators/celgo"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/proto"
	http2 "github.com/zan8in/afrog/pkg/protocols/http"
	"github.com/zan8in/afrog/pkg/utils"
)

type Checker struct {
	options         *config.Options
	target          string
	pocItem         *poc.Poc
	originalRequest *http.Request // 原始request
	variableMap     map[string]interface{}
	result          *Result
	pocResult       *PocResult
}

var CheckerPool = sync.Pool{
	New: func() interface{} {
		return &Checker{
			originalRequest: &http.Request{},
			variableMap:     make(map[string]interface{}),
		}
	},
}

var ResultPool = sync.Pool{
	New: func() interface{} {
		return &Result{
			PocInfo: &poc.Poc{},
		}
	},
}

var PocResultPool = sync.Pool{
	New: func() interface{} {
		return &PocResult{
			ResultRequest:  &proto.Request{},
			ResultResponse: &proto.Response{},
		}
	},
}

var VariableMapPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]interface{})
	},
}

func NewChecker(options config.Options, target string, pocItem poc.Poc) *Checker {
	c := CheckerPool.Get().(*Checker)
	c.options = &options
	c.target = target
	c.pocItem = &pocItem
	return c
}

func (c *Checker) Check() error {
	var err error
	// init variablemap from sync.pool
	c.variableMap = VariableMapPool.Get().(map[string]interface{})
	// init result
	c.result = ResultPool.Get().(*Result)
	c.result.Target = c.target
	c.result.PocInfo = c.pocItem

	//log.Log().Debug(fmt.Sprintf("Run afrog Poc [%s] for %s", c.pocItem.Id, c.target))
	customLib := celgo.NewCustomLib()

	// 处理 set
	if len(c.pocItem.Set) > 0 {
		for key, value := range c.pocItem.Set {
			if value == "newReverse()" {
				// c.variableMap[key] = reverse.NewReverse() // todo
				continue
			}
			out, err := customLib.RunEval(value.(string), c.variableMap)
			if err != nil {
				return err
			}
			switch value := out.Value().(type) {
			// set value 无论是什么类型都先转成string
			case *proto.UrlType:
				c.variableMap[key] = utils.UrlTypeToString(value)
			case int64:
				c.variableMap[key] = int(value)
			default:
				c.variableMap[key] = fmt.Sprintf("%v", out)
			}
		}
		customLib.WriteRuleSetOptions(c.pocItem.Set)
	}

	// 处理 rule
	fmt.Println(c.target)
	for _, ruleMap := range c.pocItem.Rules {
		k := ruleMap.Key
		rule := ruleMap.Value
		// translate : http
		if c.pocItem.Transport != "tcp" && c.pocItem.Transport != "udp" {
			if !strings.HasPrefix(c.target, "http://") && !strings.HasPrefix(c.target, "https://") {
				c.target = "http://" + c.target
			}
			// 原始请求
			c.originalRequest, err = http.NewRequest("GET", c.target, nil)
			if err != nil {
				return err
			}
			// 设置User-Agent
			if len(c.options.Config.ConfigHttp.UserAgent) > 0 {
				c.originalRequest.Header.Set("User-Agent", c.options.Config.ConfigHttp.UserAgent)
			} else {
				c.originalRequest.Header.Set("User-Agent", utils.RandomUA())
			}

			fastclient := http2.FastClient{}
			fastclient.MaxRedirect = c.options.Config.ConfigHttp.MaxRedirect
			fastclient.Client = http2.New(c.options)
			err = fastclient.HTTPRequest(c.originalRequest, rule, c.variableMap)
			if err != nil {
				return err
			}

			isVul, err := customLib.RunEval(rule.Expression, c.variableMap)
			if err != nil {
				return err
			}
			customLib.WriteRuleFunctionsROptions(k, isVul.Value().(bool))

			// save result of request、response、target、pocinfo eg.
			c.pocResult = PocResultPool.Get().(*PocResult)
			c.pocResult.IsVul = isVul.Value().(bool)
			c.pocResult.ResultRequest = c.variableMap["request"].(*proto.Request)
			c.pocResult.ResultResponse = c.variableMap["response"].(*proto.Response)
			// 保存每次request和response，用于调试和结果展示
			c.result.AllPocResult = append(c.result.AllPocResult, *c.pocResult)

			log.Log().Info(fmt.Sprintf("result:::::::::::::%v", isVul.Value().(bool)))
		}
	}

	isVul, err := customLib.RunEval(c.pocItem.Expression, c.variableMap)
	if err != nil {
		return err
	}
	// save final result
	c.result.IsVul = isVul.Value().(bool)

	// print result info (调试)
	log.Log().Info("----------------------------------------------------------------")
	for _, v := range c.result.AllPocResult {
		log.Log().Info("Request:\r\n")
		log.Log().Info(v.ReadFullResultRequestInfo())
		log.Log().Info("Response:\r\n")
		log.Log().Info(v.ReadFullResultResponseInfo())
	}
	// log.Log().Info(c.result.ReadPocInfo())
	log.Log().Info(fmt.Sprintf("Result: %v\r\n", c.result.IsVul))
	log.Log().Info(c.result.PrintResultInfo())
	log.Log().Info("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")

	return err
}

// 更新 Set/Payload VariableMap
// key map["set.username"] = ...  map["payload.ping.cmd"] = ...
func (c *Checker) UpdateVariableMap(args map[string]interface{}) {
	for k, v := range args {
		switch vv := v.(type) {
		case int64:
			c.variableMap[k] = int(vv)
		default:
			c.variableMap[k] = fmt.Sprintf("%v", vv)
		}
	}
}

// 替换变量的值
// find string 规定要查找的值
// oldstr 规定被搜索的字符串
// newstr 规定替换的值
func (c *Checker) AssignVariableMap(find string) string {
	for k, v := range c.variableMap {
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
