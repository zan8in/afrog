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

func (c *Checker) Check(target string, pocItem poc.Poc) (err error) {

	c.Result.Target = target
	c.Result.PocInfo = &pocItem

	c.FastClient.MaxRedirect = c.Options.Config.ConfigHttp.MaxRedirect
	c.FastClient.DialTimeout = c.Options.Config.ConfigHttp.DialTimeout

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
		c.OriginalRequest, err = http.NewRequest("GET", target, nil)
		if err != nil {
			log.Log().Error(fmt.Sprintf("rule map originalRequest err, %s", err.Error()))
			c.Result.IsVul = false
			c.Options.ApiCallBack(c.Result)
			return err
		}

		tempRequest, err := http2.ParseRequest(c.OriginalRequest)
		c.VariableMap["request"] = tempRequest

		if err != nil {
			log.Log().Error(fmt.Sprintf("ParseRequest err, %s", err.Error()))
			c.Result.IsVul = false
			c.Options.ApiCallBack(c.Result)
			return err
		}

		// set User-Agent
		if len(c.Options.Config.ConfigHttp.UserAgent) > 0 {
			c.OriginalRequest.Header.Set("User-Agent", c.Options.Config.ConfigHttp.UserAgent)
		} else {
			c.OriginalRequest.Header.Set("User-Agent", utils.RandomUA())
		}
	}

	// update set cel and variablemap
	if len(pocItem.Set) > 0 {
		c.UpdateVariableMap(pocItem.Set)
	}

	// update payloads cel and variablemap
	if len(pocItem.Payloads.Payloads) > 0 {
		c.UpdateVariableMap(pocItem.Payloads.Payloads)
	}

	// rule
	for _, ruleMap := range pocItem.Rules {
		k := ruleMap.Key
		rule := ruleMap.Value

		// translate : http
		if pocItem.Transport != "tcp" && pocItem.Transport != "udp" {

			// run fasthttp client
			utils.RandSleep(500) // firewall just test.

			err = c.FastClient.HTTPRequest(c.OriginalRequest, rule, c.VariableMap)
			if err != nil {
				log.Log().Error(fmt.Sprintf("rule map fasthttp.HTTPRequest err, %s", err.Error()))
				c.CustomLib.WriteRuleFunctionsROptions(k, false)
				continue // not return, becuase may be need test next pocitem. ？？？
			}

			// run cel expression
			isVul, err := c.CustomLib.RunEval(rule.Expression, c.VariableMap)
			if err != nil {
				log.Log().Error(fmt.Sprintf("rule map RunEval err, %s", err.Error()))
				c.CustomLib.WriteRuleFunctionsROptions(k, false)
				continue // not return, becuase may be need test next pocitem. ？？？
			}

			// set result function eg: r1() r2()
			c.CustomLib.WriteRuleFunctionsROptions(k, isVul.Value().(bool))

			// update output cel and variablemap
			if len(rule.Output) > 0 {
				c.UpdateVariableMap(rule.Output)
			}

			c.Result.AllPocResult = append(c.Result.AllPocResult, &PocResult{IsVul: isVul.Value().(bool), ResultRequest: c.VariableMap["request"].(*proto.Request), ResultResponse: c.VariableMap["response"].(*proto.Response)})

			if rule.Request.Todo == poc.TODO_FAILURE_NOT_CONTINUE && !isVul.Value().(bool) {
				c.Result.IsVul = false
				c.Options.ApiCallBack(c.Result)
				return err
			}

			if rule.Request.Todo == poc.TODO_SUCCESS_NOT_CONTINUE && isVul.Value().(bool) {
				c.Result.IsVul = true
				c.Options.ApiCallBack(c.Result)
				return err
			}

			if pocHandler == poc.ALLOR && isVul.Value().(bool) {
				c.Result.IsVul = true
				c.Options.ApiCallBack(c.Result)
				return err
			}
			if pocHandler == poc.ALLAND && !isVul.Value().(bool) {
				c.Result.IsVul = false
				c.Options.ApiCallBack(c.Result)
				return err
			}
		}
	}

	// run final cel expression
	isVul, err := c.CustomLib.RunEval(pocItem.Expression, c.VariableMap)
	if err != nil {
		log.Log().Error(fmt.Sprintf("final RunEval err, %s", err.Error()))
		c.Result.IsVul = false
		c.Options.ApiCallBack(c.Result)
		return err
	}

	// save final result
	c.Result.IsVul = isVul.Value().(bool)
	c.Options.ApiCallBack(c.Result)

	return err
}

// print result info for debug
func (c *Checker) PrintTraceInfo(result *Result) {
	for i, v := range result.AllPocResult {
		log.Log().Info(fmt.Sprintf("\r\n%s（%d）\r\n%s\r\n\r\n%s（%d）\r\n%s\r\n", "Request:", i, v.ReadFullResultRequestInfo(), "Response:", i, v.ReadFullResultResponseInfo()))
	}
}

// update set、payload、output variableMap etc.
func (c *Checker) UpdateVariableMap(args yaml.MapSlice) {
	for _, item := range args {
		key := item.Key.(string)
		value := item.Value.(string)

		if value == "newReverse()" {
			c.VariableMap[key] = c.newRerverse()
			c.CustomLib.UpdateCompileOption(key, decls.NewObjectType("proto.Reverse"))
			continue
		}

		out, err := c.CustomLib.RunEval(value, c.VariableMap)
		if err != nil {
			log.Log().Error(fmt.Sprintf("UpdateVariableMap[%s][%s] Eval err, %s", key, value, err.Error()))
			continue
		}

		switch value := out.Value().(type) {
		case *proto.UrlType:
			c.VariableMap[key] = utils.UrlTypeToString(value)
			c.CustomLib.UpdateCompileOption(key, decls.NewObjectType("proto.UrlType"))
		case int64:
			c.VariableMap[key] = int(value)
			c.CustomLib.UpdateCompileOption(key, decls.Int)
		case map[string]string:
			c.VariableMap[key] = value
			c.CustomLib.UpdateCompileOption(key, StrStrMapType)
		default:
			c.VariableMap[key] = fmt.Sprintf("%v", out)
			c.CustomLib.UpdateCompileOption(key, decls.String)
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
