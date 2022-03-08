package core

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/cel-go/checker/decls"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/proto"
	http2 "github.com/zan8in/afrog/pkg/protocols/http"
	"github.com/zan8in/afrog/pkg/utils"
	"gopkg.in/yaml.v2"
)

type Checker struct {
	options         *config.Options
	target          string
	pocItem         *poc.Poc
	originalRequest *http.Request // 原始request
	variableMap     map[string]interface{}
	result          *Result
	pocResult       *PocResult
	customLib       *CustomLib
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

var FastClientPool = sync.Pool{
	New: func() interface{} {
		return &http2.FastClient{}
	},
}

var ReverseCeyeApiKey string
var ReverseCeyeDomain string

var lock sync.Mutex

var FastClientReverse *http2.FastClient // 用于 reverse http client

func NewChecker(options config.Options, target string, pocItem poc.Poc) *Checker {
	c := CheckerPool.Get().(*Checker)
	c.options = &options
	c.target = target
	c.pocItem = &pocItem

	ReverseCeyeApiKey = options.Config.Reverse.Ceye.ApiKey
	ReverseCeyeDomain = options.Config.Reverse.Ceye.Domain

	if len(ReverseCeyeApiKey) == 0 || len(ReverseCeyeDomain) == 0 {
		log.Log().Error("Rerverse CeyeApiKey or CeyeDomain is Empty.")
		return nil
	}

	return c
}

func (c *Checker) Check() error {
	var err error

	// init fasthttp client
	fc := FastClientPool.Get().(*http2.FastClient)
	fc.DialTimeout = c.options.Config.ConfigHttp.DialTimeout
	fc.Client = http2.New(c.options)

	// init variablemap from sync.pool
	c.variableMap = VariableMapPool.Get().(map[string]interface{})

	// init result
	c.result = ResultPool.Get().(*Result)
	c.result.Target = c.target
	c.result.PocInfo = c.pocItem

	// init cel
	c.customLib = NewCustomLib()

	// update set cel and variablemap
	if len(c.pocItem.Set) > 0 {
		// c.customLib.WriteRuleSetOptions(c.pocItem.Set)
		c.UpdateVariableMap(c.pocItem.Set)
	}

	// update payloads cel and variablemap
	if len(c.pocItem.Payloads.Payloads) > 0 {
		// c.customLib.WriteRuleSetOptions(c.pocItem.Payloads.Payloads)
		c.UpdateVariableMap(c.pocItem.Payloads.Payloads)
	}

	// rule
	for _, ruleMap := range c.pocItem.Rules {
		k := ruleMap.Key
		rule := ruleMap.Value

		// translate : http
		if c.pocItem.Transport != "tcp" && c.pocItem.Transport != "udp" {
			if !strings.HasPrefix(c.target, "http://") && !strings.HasPrefix(c.target, "https://") {
				c.target = "http://" + c.target
			}

			// original request
			c.originalRequest, err = http.NewRequest("GET", c.target, nil)
			if err != nil {
				log.Log().Error(fmt.Sprintf("rule map originalRequest err, %s", err.Error()))
				return err
			}

			// set User-Agent
			if len(c.options.Config.ConfigHttp.UserAgent) > 0 {
				c.originalRequest.Header.Set("User-Agent", c.options.Config.ConfigHttp.UserAgent)
			} else {
				c.originalRequest.Header.Set("User-Agent", utils.RandomUA())
			}

			// run fasthttp client
			fc.MaxRedirect = c.options.Config.ConfigHttp.MaxRedirect
			err = fc.HTTPRequest(c.originalRequest, rule, c.variableMap)
			if err != nil {
				log.Log().Error(fmt.Sprintf("rule map fasthttp.HTTPRequest err, %s", err.Error()))
				return err
			}

			// run cel expression
			isVul, err := c.customLib.RunEval(rule.Expression, c.variableMap)
			if err != nil {
				log.Log().Error(fmt.Sprintf("rule map RunEval err, %s", err.Error()))
				return err
			}

			// set result function eg: r1() r2()
			c.customLib.WriteRuleFunctionsROptions(k, isVul.Value().(bool))

			// update output cel and variablemap
			if len(rule.Output) > 0 {
				// c.customLib.WriteRuleSetOptions(rule.Output)
				c.UpdateVariableMap(rule.Output)
			}

			// save result eg: request、response、target、pocinfo etc.
			c.pocResult = PocResultPool.Get().(*PocResult)
			c.pocResult.IsVul = isVul.Value().(bool)
			c.pocResult.ResultRequest = c.variableMap["request"].(*proto.Request)
			c.pocResult.ResultResponse = c.variableMap["response"].(*proto.Response)
			// save to allresult slice
			c.result.AllPocResult = append(c.result.AllPocResult, *c.pocResult)

			// debug per rule result
			// log.Log().Debug(fmt.Sprintf("result:::::::::::::%v", isVul.Value().(bool)))
		}
	}

	// run final cel expression
	isVul, err := c.customLib.RunEval(c.pocItem.Expression, c.variableMap)
	if err != nil {
		log.Log().Error(fmt.Sprintf("final RunEval err, %s", err.Error()))
		return err
	}

	// save final result
	c.result.IsVul = isVul.Value().(bool)

	if c.result.IsVul {
		lock.Lock()
		rst := c.result.PrintResultInfoConsole()
		if len(c.options.Output) > 0 {
			// output save to file
			utils.BufferWriteAppend(c.options.Output, rst)
		}
		lock.Unlock()

		// print result info for debug
		c.PrintTraceInfo(rst)
	}

	return err
}

func (c *Checker) PrintTraceInfo(rst string) {
	// log.Log().Info("------------------------start----------------------------------------")
	// for i, v := range c.result.AllPocResult {
	// 	log.Log().Info(fmt.Sprintf("\r\n%s（%d）\r\n%s\r\n\r\n%s（%d）\r\n%s\r\n", "Request:", i, v.ReadFullResultRequestInfo(), "Response:", i, v.ReadFullResultResponseInfo()))
	// }
	if rst != "" {
		log.Log().Info(fmt.Sprintf("\r\nResult: %s\r\n", rst))
	}
	// log.Log().Info("^^^^^^^^^^^^^^^^^^^^^^^^end^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
}

// update set、payload、output variableMap etc.
func (c *Checker) UpdateVariableMap(args yaml.MapSlice) {
	for _, item := range args {
		key := item.Key.(string)
		value := item.Value.(string)

		if value == "newReverse()" {
			c.variableMap[key] = c.newRerverse()
			c.customLib.UpdateCompileOption(key, decls.NewObjectType("proto.Reverse"))

			// if reverse()，initilize a fasthttpclient
			FastClientReverse = FastClientPool.Get().(*http2.FastClient)
			FastClientReverse.DialTimeout = c.options.Config.ConfigHttp.DialTimeout
			FastClientReverse.Client = http2.New(c.options)
			continue
		}

		out, err := c.customLib.RunEval(value, c.variableMap)
		if err != nil {
			log.Log().Error(fmt.Sprintf("UpdateVariableMap[%s][%s] Eval err, %s", key, value, err.Error()))
			return
		}

		switch value := out.Value().(type) {
		case *proto.UrlType:
			c.variableMap[key] = utils.UrlTypeToString(value)
			c.customLib.UpdateCompileOption(key, decls.NewObjectType("proto.UrlType"))
		case int64:
			c.variableMap[key] = int(value)
			c.customLib.UpdateCompileOption(key, decls.Int)
		case map[string]string:
			c.variableMap[key] = value
			c.customLib.UpdateCompileOption(key, StrStrMapType)
		default:
			c.variableMap[key] = fmt.Sprintf("%v", out)
			c.customLib.UpdateCompileOption(key, decls.String)
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

func (c *Checker) newRerverse() *proto.Reverse {
	letters := "1234567890abcdefghijklmnopqrstuvwxyz"
	randSource := rand.New(rand.NewSource(time.Now().Unix()))
	sub := utils.RandomStr(randSource, letters, 8)
	urlStr := fmt.Sprintf("http://%s.%s", sub, ReverseCeyeDomain)
	u, _ := url.Parse(urlStr)
	return &proto.Reverse{
		Url:                utils.ParseUrl(u),
		Domain:             u.Hostname(),
		Ip:                 "",
		IsDomainNameServer: false,
	}
}
