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
	Options         *sync.Pool
	Target          *sync.Pool
	PocItem         *sync.Pool
	PocHandler      *sync.Pool
	OriginalRequest *sync.Pool
	VariableMap     *sync.Pool
	Result          *sync.Pool
	PocResult       *sync.Pool
	CustomLib       *sync.Pool
	FastClient      *sync.Pool
}

var ReverseCeyeApiKey string
var ReverseCeyeDomain string

func NewChecker(options *config.Options, target string, pocItem poc.Poc) *Checker {
	ReverseCeyeApiKey = options.Config.Reverse.Ceye.ApiKey
	ReverseCeyeDomain = options.Config.Reverse.Ceye.Domain

	if len(ReverseCeyeApiKey) == 0 || len(ReverseCeyeDomain) == 0 {
		log.Log().Error("Rerverse CeyeApiKey or CeyeDomain is Empty.")
		return nil
	}

	return &Checker{
		Options: &sync.Pool{
			New: func() interface{} {
				return options
			},
		},
		Target: &sync.Pool{
			New: func() interface{} {
				return target
			},
		},
		PocItem: &sync.Pool{
			New: func() interface{} {
				return &pocItem
			},
		},
		PocHandler: &sync.Pool{
			New: func() interface{} {
				pocHandler := ""
				if strings.Contains(pocItem.Expression, "&&") && !strings.Contains(pocItem.Expression, "||") {
					pocHandler = poc.ALLAND
				}
				if strings.Contains(pocItem.Expression, "||") && !strings.Contains(pocItem.Expression, "&&") {
					pocHandler = poc.ALLOR
				}
				return pocHandler
			},
		},
		OriginalRequest: &sync.Pool{
			New: func() interface{} {
				return &http.Request{}
			},
		},
		VariableMap: &sync.Pool{
			New: func() interface{} {
				return make(map[string]interface{})
			},
		},
		Result: &sync.Pool{
			New: func() interface{} {
				return &Result{
					Target:  target,
					PocInfo: &pocItem,
					Output:  options.Output,
				}
			},
		},
		PocResult: &sync.Pool{
			New: func() interface{} {
				return &PocResult{}
			},
		},
		CustomLib: &sync.Pool{
			New: func() interface{} {
				return NewCustomLib()
			},
		},
		FastClient: &sync.Pool{
			New: func() interface{} {
				return &http2.FastClient{}
			},
		},
	}
}

func (c *Checker) ReleaseVariableMap(vmap map[string]interface{}) {
	if vmap != nil {
		vmap = nil
		c.VariableMap.Put(vmap)
	}
}

func (c *Checker) ReleaseTarget(r string) {
	if len(r) > 0 {
		r = ""
		c.Target.Put(r)
	}
}

func (c *Checker) ReleaseHandler(h string) {
	if len(h) > 0 {
		h = ""
		c.Target.Put(h)
	}
}

func (c *Checker) ReleaseOriginalRequest(o *http.Request) {
	if o != nil {
		*o = http.Request{}
		c.OriginalRequest.Put(o)
	}
}

var FastClientReverse *http2.FastClient // 用于 reverse http client

func (c *Checker) Check() (err error) {

	options := c.Options.Get().(*config.Options)
	defer c.Options.Put(options)

	fc := c.FastClient.Get().(*http2.FastClient)
	fc.Client = http2.New(options)
	fc.DialTimeout = options.Config.ConfigHttp.DialTimeout
	defer c.FastClient.Put(fc)
	defer fc.Reset()

	variableMap := c.VariableMap.Get().(map[string]interface{})
	defer c.ReleaseVariableMap(variableMap)

	target := c.Target.Get().(string)
	defer c.ReleaseTarget(target)

	pocItem := c.PocItem.Get().(*poc.Poc)
	defer c.PocItem.Put(pocItem)
	defer pocItem.Reset()

	result := c.Result.Get().(*Result)
	defer c.Result.Put(result)
	defer result.Reset()

	customLib := c.CustomLib.Get().(*CustomLib)
	defer c.CustomLib.Put(customLib)
	defer customLib.Reset()

	originalRequest := c.OriginalRequest.Get().(*http.Request)
	defer c.ReleaseOriginalRequest(originalRequest)

	pocResult := c.PocResult.Get().(*PocResult)
	defer c.PocResult.Put(pocResult)
	defer pocResult.Reset()

	pocHandler := c.PocHandler.Get().(string)
	defer c.ReleaseHandler(pocHandler)

	// update request variablemap
	tempRequest := http2.AcquireProtoRequestPool()
	defer http2.ReleaseProtoRequestPool(tempRequest)
	if pocItem.Transport != "tcp" && pocItem.Transport != "udp" {
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "http://" + target
		}

		// original request
		originalRequest, err = http.NewRequest("GET", target, nil)
		if err != nil {
			log.Log().Error(fmt.Sprintf("rule map originalRequest err, %s", err.Error()))
			result.IsVul = false
			options.ApiCallBack(result)
			return err
		}

		tempRequest, err = http2.ParseRequest(originalRequest)
		if err != nil {
			log.Log().Error(fmt.Sprintf("ParseRequest err, %s", err.Error()))
			result.IsVul = false
			options.ApiCallBack(result)
			return err
		}

		// set User-Agent
		if len(options.Config.ConfigHttp.UserAgent) > 0 {
			originalRequest.Header.Set("User-Agent", options.Config.ConfigHttp.UserAgent)
		} else {
			originalRequest.Header.Set("User-Agent", utils.RandomUA())
		}
	}
	tempVariableMap := tempRequest
	variableMap["request"] = tempVariableMap

	// update set cel and variablemap
	if len(pocItem.Set) > 0 {
		c.UpdateVariableMap(pocItem.Set, variableMap, customLib, fc)
	}

	// update payloads cel and variablemap
	if len(pocItem.Payloads.Payloads) > 0 {
		c.UpdateVariableMap(pocItem.Payloads.Payloads, variableMap, customLib, fc)
	}

	// rule
	for _, ruleMap := range pocItem.Rules {
		k := ruleMap.Key
		rule := ruleMap.Value

		// translate : http
		if pocItem.Transport != "tcp" && pocItem.Transport != "udp" {

			// run fasthttp client
			utils.RandSleep(500) // firewall just test.

			fc.MaxRedirect = options.Config.ConfigHttp.MaxRedirect

			err = fc.HTTPRequest(originalRequest, rule, variableMap)
			if err != nil {
				log.Log().Error(fmt.Sprintf("rule map fasthttp.HTTPRequest err, %s", err.Error()))
				customLib.WriteRuleFunctionsROptions(k, false)
				continue // not return, becuase may be need test next pocitem. ？？？
			}

			// run cel expression
			isVul, err := customLib.RunEval(rule.Expression, variableMap)
			if err != nil {
				log.Log().Error(fmt.Sprintf("rule map RunEval err, %s", err.Error()))
				customLib.WriteRuleFunctionsROptions(k, false)
				continue // not return, becuase may be need test next pocitem. ？？？
			}

			// set result function eg: r1() r2()
			customLib.WriteRuleFunctionsROptions(k, isVul.Value().(bool))

			// update output cel and variablemap
			if len(rule.Output) > 0 {
				c.UpdateVariableMap(rule.Output, variableMap, customLib, fc)
			}

			// save result eg: request、response、target、pocinfo etc.
			pocResult.IsVul = isVul.Value().(bool)
			pocResult.ResultRequest = variableMap["request"].(*proto.Request)
			pocResult.ResultResponse = variableMap["response"].(*proto.Response)
			// save to allresult slice
			result.AllPocResult = append(result.AllPocResult, pocResult)

			// debug per rule result
			log.Log().Debug(fmt.Sprintf("result:::::::::::::%v,%s", isVul.Value().(bool), rule.Request.Path))

			if pocHandler == poc.ALLOR && isVul.Value().(bool) {
				result.IsVul = true
				options.ApiCallBack(result)
				return err
			}
			if pocHandler == poc.ALLAND && !isVul.Value().(bool) {
				result.IsVul = false
				options.ApiCallBack(result)
				return err
			}
		}
	}

	// run final cel expression
	isVul, err := customLib.RunEval(pocItem.Expression, variableMap)
	if err != nil {
		log.Log().Error(fmt.Sprintf("final RunEval err, %s", err.Error()))
		result.IsVul = false
		options.ApiCallBack(result)
		return err
	}

	// save final result
	result.IsVul = isVul.Value().(bool)

	options.ApiCallBack(result)

	c.PrintTraceInfo(result)

	return err
}

// print result info for debug
func (c *Checker) PrintTraceInfo(result *Result) {
	for i, v := range result.AllPocResult {
		log.Log().Info(fmt.Sprintf("\r\n%s（%d）\r\n%s\r\n\r\n%s（%d）\r\n%s\r\n", "Request:", i, v.ReadFullResultRequestInfo(), "Response:", i, v.ReadFullResultResponseInfo()))
	}
}

// update set、payload、output variableMap etc.
func (c *Checker) UpdateVariableMap(args yaml.MapSlice, variableMap map[string]interface{}, customLib *CustomLib, fc *http2.FastClient) {
	for _, item := range args {
		key := item.Key.(string)
		value := item.Value.(string)

		if value == "newReverse()" {
			variableMap[key] = c.newRerverse()
			customLib.UpdateCompileOption(key, decls.NewObjectType("proto.Reverse"))

			// if reverse()，initilize a fasthttpclient
			FastClientReverse = c.FastClient.Get().(*http2.FastClient)
			FastClientReverse.DialTimeout = c.Options.Get().(*config.Options).Config.ConfigHttp.DialTimeout
			FastClientReverse.Client = http2.New(c.Options.Get().(*config.Options))
			continue
		}

		out, err := customLib.RunEval(value, variableMap)
		if err != nil {
			log.Log().Error(fmt.Sprintf("UpdateVariableMap[%s][%s] Eval err, %s", key, value, err.Error()))
			continue
		}

		switch value := out.Value().(type) {
		case *proto.UrlType:
			variableMap[key] = utils.UrlTypeToString(value)
			customLib.UpdateCompileOption(key, decls.NewObjectType("proto.UrlType"))
		case int64:
			variableMap[key] = int(value)
			customLib.UpdateCompileOption(key, decls.Int)
		case map[string]string:
			variableMap[key] = value
			customLib.UpdateCompileOption(key, StrStrMapType)
		default:
			variableMap[key] = fmt.Sprintf("%v", out)
			customLib.UpdateCompileOption(key, decls.String)
		}
	}
}

// 替换变量的值
// find string 规定要查找的值
// oldstr 规定被搜索的字符串
// newstr 规定替换的值
func (c *Checker) AssignVariableMap(find string, variableMap map[string]interface{}) string {
	for k, v := range variableMap {
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
