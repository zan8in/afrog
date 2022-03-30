package core

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

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
	Options         *config.Options
	OriginalRequest *http.Request
	VariableMap     map[string]interface{}
	Result          *Result
	CustomLib       *CustomLib
	FastClient      *http2.FastClient
}

var ReverseCeyeApiKey string
var ReverseCeyeDomain string

var FastClientReverse *http2.FastClient // 用于 reverse http client

func (c *Checker) Check(target string, pocItem poc.Poc) (err error) {

	options := c.Options

	ReverseCeyeApiKey = options.Config.Reverse.Ceye.ApiKey
	ReverseCeyeDomain = options.Config.Reverse.Ceye.Domain

	fc := c.FastClient
	fc.Client = http2.New(options)
	fc.DialTimeout = options.Config.ConfigHttp.DialTimeout

	variableMap := c.VariableMap

	result := c.Result
	result.Target = target
	result.PocInfo = &pocItem

	customLib := c.CustomLib

	originalRequest := c.OriginalRequest

	pocHandler := ""
	if strings.Contains(pocItem.Expression, "&&") && !strings.Contains(pocItem.Expression, "||") {
		pocHandler = poc.ALLAND
	}
	if strings.Contains(pocItem.Expression, "||") && !strings.Contains(pocItem.Expression, "&&") {
		pocHandler = poc.ALLOR
	}

	// update request variablemap
	// tempRequest := http2.AcquireProtoRequestPool()
	// defer http2.ReleaseProtoRequestPool(tempRequest)
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

		tempRequest, err := http2.ParseRequest(originalRequest)
		variableMap["request"] = tempRequest

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

			result.AllPocResult = append(result.AllPocResult, &PocResult{IsVul: isVul.Value().(bool), ResultRequest: variableMap["request"].(*proto.Request), ResultResponse: variableMap["response"].(*proto.Response)})

			if rule.Request.Todo == poc.TODO_FAILURE_NOT_CONTINUE && !isVul.Value().(bool) {
				result.IsVul = false
				options.ApiCallBack(result)
				return err
			}

			if rule.Request.Todo == poc.TODO_SUCCESS_NOT_CONTINUE && isVul.Value().(bool) {
				result.IsVul = true
				options.ApiCallBack(result)
				return err
			}

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
			FastClientReverse = c.FastClient
			FastClientReverse.DialTimeout = c.Options.Config.ConfigHttp.DialTimeout
			FastClientReverse.Client = http2.New(c.Options)
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

func (c *Checker) newRerverse() *proto.Reverse {
	sub := utils.CreateRandomString(8)
	urlStr := fmt.Sprintf("http://%s.%s", sub, ReverseCeyeDomain)
	u, _ := url.Parse(urlStr)
	return &proto.Reverse{
		Url:                utils.ParseUrl(u),
		Domain:             u.Hostname(),
		Ip:                 "",
		IsDomainNameServer: false,
	}
}
