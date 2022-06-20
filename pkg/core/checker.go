package core

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zan8in/afrog/pkg/gopoc"
	"github.com/zan8in/afrog/pkg/protocols/raw"

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
	defer func() {
		if r := recover(); r != nil {
			c.Result.IsVul = false
			c.Options.ApiCallBack(c.Result)
			log.Log().Error(fmt.Sprintf("goroutine recover() error from pkg/core/Check, %v\n", r))
		}
	}()

	c.Result.Target = target
	c.Result.PocInfo = &pocItem

	c.FastClient.MaxRedirect = c.Options.Config.ConfigHttp.MaxRedirect
	c.FastClient.DialTimeout = c.Options.Config.ConfigHttp.DialTimeout
	c.FastClient.UserAgent = c.Options.Config.ConfigHttp.UserAgent

	matchCondition := ""
	if strings.Contains(pocItem.Expression, "&&") && !strings.Contains(pocItem.Expression, "||") {
		matchCondition = poc.STOP_IF_FIRST_MISMATCH
	}
	if strings.Contains(pocItem.Expression, "||") && !strings.Contains(pocItem.Expression, "&&") {
		matchCondition = poc.STOP_IF_FIRST_MATCH
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	c.OriginalRequest, err = http.NewRequest("GET", target, nil)
	if err != nil {
		log.Log().Error(fmt.Sprintf("rule map originalRequest err, %s", err.Error()))
		c.Result.IsVul = false
		c.Options.ApiCallBack(c.Result)
		return err
	}

	tempRequest, err := http2.ParseRequest(c.OriginalRequest)
	if err != nil {
		log.Log().Error(fmt.Sprintf("ParseRequest err, %s", err.Error()))
		c.Result.IsVul = false
		c.Options.ApiCallBack(c.Result)
		return err
	}
	c.VariableMap["request"] = tempRequest

	if len(pocItem.Set) > 0 {
		c.UpdateVariableMap(pocItem.Set)
	}

	if len(pocItem.Payloads.Payloads) > 0 {
		c.UpdateVariableMap(pocItem.Payloads.Payloads)
	}

	for _, ruleMap := range pocItem.Rules {
		k := ruleMap.Key
		rule := ruleMap.Value

		if rule.BeforeSleep != 0 {
			time.Sleep(time.Duration(rule.BeforeSleep) * time.Second)
		}
		utils.RandSleep(500)

		isMatch := false
		if len(rule.Request.Raw) > 0 {
			rt := raw.RawHttp{RawhttpClient: raw.GetRawHTTP(int(c.Options.Config.ConfigHttp.DialTimeout))}
			err = rt.RawHttpRequest(rule.Request.Raw, target, c.VariableMap)
		} else {
			err = c.FastClient.HTTPRequest(c.OriginalRequest, rule, c.VariableMap)
		}
		if err == nil {
			evalResult, err := c.CustomLib.RunEval(rule.Expression, c.VariableMap)
			if err == nil {
				isMatch = evalResult.Value().(bool)
			}
		}
		if err != nil {
			log.Log().Error(fmt.Sprintf("RunEval %s", err.Error()))
		}

		c.CustomLib.WriteRuleFunctionsROptions(k, isMatch)

		if len(rule.Output) > 0 {
			c.UpdateVariableMap(rule.Output)
		}

		pocRstTemp := PocResult{IsVul: isMatch}
		if c.VariableMap["response"] != nil {
			pocRstTemp.ResultResponse = c.VariableMap["response"].(*proto.Response)
		}
		if c.VariableMap["request"] != nil {
			pocRstTemp.ResultRequest = c.VariableMap["request"].(*proto.Request)
		}
		c.Result.AllPocResult = append(c.Result.AllPocResult, &pocRstTemp)

		if rule.StopIfMismatch && !isMatch {
			c.Result.IsVul = false
			c.Options.ApiCallBack(c.Result)
			return err
		}

		if rule.StopIfMatch && isMatch {
			c.Result.IsVul = true
			c.Options.ApiCallBack(c.Result)
			return err
		}

		if matchCondition == poc.STOP_IF_FIRST_MISMATCH && !isMatch {
			c.Result.IsVul = false
			c.Options.ApiCallBack(c.Result)
			return err
		}

		if matchCondition == poc.STOP_IF_FIRST_MATCH && isMatch {
			c.Result.IsVul = true
			c.Options.ApiCallBack(c.Result)
			return err
		}
	}

	isVul, err := c.CustomLib.RunEval(pocItem.Expression, c.VariableMap)
	if err != nil {
		log.Log().Error(fmt.Sprintf("Final RunEval Error: %s", err.Error()))
		c.Result.IsVul = false
		c.Options.ApiCallBack(c.Result)
		return err
	}

	c.Result.IsVul = isVul.Value().(bool)
	c.Options.ApiCallBack(c.Result)

	return err
}

func (c *Checker) CheckGopoc(target, gopocName string) (err error) {
	gpa := gopoc.New(target)

	fun := gopoc.GetGoPocFunc(gopocName)
	r, err := fun(gpa)
	if err != nil {
		c.Result.IsVul = false
		c.Result.PocInfo = gpa.Poc
		c.Options.ApiCallBack(c.Result)
		return
	}

	c.Result.Target = target
	c.Result.IsVul = true
	c.Result.PocInfo = gpa.Poc
	if len(r.AllPocResult) > 0 {
		for _, v := range r.AllPocResult {
			c.Result.AllPocResult = append(c.Result.AllPocResult, &PocResult{ResultRequest: v.ResultRequest, ResultResponse: v.ResultResponse, IsVul: v.IsVul})
		}
	}
	c.Options.ApiCallBack(c.Result)

	return nil
}

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
