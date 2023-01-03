package core

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/pkg/gopoc"
	"github.com/zan8in/afrog/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/pkg/protocols/raw"
	"github.com/zan8in/afrog/pkg/targetlive"
	"golang.org/x/net/context"

	"github.com/google/cel-go/checker/decls"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/proto"
	http2 "github.com/zan8in/afrog/pkg/protocols/http"
	"github.com/zan8in/afrog/pkg/utils"
	"gopkg.in/yaml.v2"
)

var MMutex = &sync.Mutex{}

type Checker struct {
	Options         *config.Options
	OriginalRequest *http.Request
	VariableMap     map[string]any
	Result          *Result
	CustomLib       *CustomLib
	FastClient      *http2.FastClient
}

func (c *Checker) Check(ctx context.Context, target string, pocItem *poc.Poc) (err error) {
	defer func() {
		if r := recover(); r != nil {
			c.Result.IsVul = false
		}
	}()

	// check target alive.
	if targetlive.TLive.HandleTargetLive(target, -1) == -1 || len(target) == 0 {
		c.Result.IsVul = false
		return err
	}

	c.Result.Target = target
	c.Result.PocInfo = pocItem

	c.FastClient.MaxRedirect = c.Options.Config.ConfigHttp.MaxRedirect
	c.FastClient.DialTimeout = c.Options.Config.ConfigHttp.DialTimeout
	c.FastClient.UserAgent = utils.RandomUA()

	matchCondition := ""
	if strings.Contains(pocItem.Expression, "&&") && !strings.Contains(pocItem.Expression, "||") {
		matchCondition = poc.STOP_IF_FIRST_MISMATCH
	}
	if strings.Contains(pocItem.Expression, "||") && !strings.Contains(pocItem.Expression, "&&") {
		matchCondition = poc.STOP_IF_FIRST_MATCH
	}

	target, err = c.checkIsURL(target)
	if err != nil {
		c.Result.IsVul = false
		return err
	}

	c.OriginalRequest, err = http.NewRequest("GET", target, nil)
	if err != nil {
		c.Result.IsVul = false
		return err
	}

	tempRequest, err := http2.ParseRequest(c.OriginalRequest)
	if err != nil {
		c.Result.IsVul = false
		return err
	}
	c.VariableMap["request"] = tempRequest

	if len(pocItem.Set) > 0 {
		c.UpdateVariableMap(pocItem.Set)
	}

	if len(pocItem.Payloads.Payloads) > 0 {
		c.UpdateVariableMap(pocItem.Payloads.Payloads)
	}

	c.FastClient.Target = target

	for _, ruleMap := range pocItem.Rules {
		k := ruleMap.Key
		rule := ruleMap.Value

		if targetlive.TLive.HandleTargetLive(target, -1) == -1 || len(target) == 0 {
			c.Result.IsVul = false
			return err
		}

		if rule.BeforeSleep != 0 {
			time.Sleep(time.Duration(rule.BeforeSleep) * time.Second)
		}

		isMatch := false
		if len(rule.Request.Raw) > 0 {
			rt := raw.RawHttp{RawhttpClient: raw.GetRawHTTP(int(c.Options.Config.ConfigHttp.DialTimeout))}
			err = rt.RawHttpRequest(rule.Request.Raw, target, c.VariableMap)
		} else {
			// err = c.FastClient.HTTPRequest(ctx, c.OriginalRequest, rule, c.VariableMap)
			err = retryhttpclient.Request(ctx, target, rule, c.VariableMap)
		}
		if err == nil {
			if len(rule.Expressions) > 0 {
				// multiple expressions
				for _, expression := range rule.Expressions {
					evalResult, err := c.CustomLib.RunEval(expression, c.VariableMap)
					if err == nil {
						isMatch = evalResult.Value().(bool)
						if isMatch {
							if name := checkExpression(expression); len(name) > 0 {
								pocItem.Id = name
								pocItem.Info.Name = name
							}
							break
						}
					}
				}
			} else {
				// single expression
				evalResult, err := c.CustomLib.RunEval(rule.Expression, c.VariableMap)
				if err == nil {
					isMatch = evalResult.Value().(bool)
				}
			}
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
		if c.VariableMap["fulltarget"] != nil {
			pocRstTemp.FullTarget = c.VariableMap["fulltarget"].(string)
			c.Result.FullTarget = c.VariableMap["fulltarget"].(string)
		}
		c.Result.AllPocResult = append(c.Result.AllPocResult, &pocRstTemp)

		if rule.StopIfMismatch && !isMatch {
			c.Result.IsVul = false
			return err
		}

		if rule.StopIfMatch && isMatch {
			c.Result.IsVul = true
			return err
		}

		if matchCondition == poc.STOP_IF_FIRST_MISMATCH && !isMatch {
			c.Result.IsVul = false
			return err
		}

		if matchCondition == poc.STOP_IF_FIRST_MATCH && isMatch {
			c.Result.IsVul = true
			return err
		}

	}

	isVul, err := c.CustomLib.RunEval(pocItem.Expression, c.VariableMap)
	if err != nil {
		c.Result.IsVul = false
		return err
	}

	c.Result.IsVul = isVul.Value().(bool)

	return err
}

func (c *Checker) checkIsURL(target string) (string, error) {
	if !utils.IsURL(target) {

		newtarget, status := retryhttpclient.CheckHttpsAndLives(target)

		if status == -1 {

			MMutex.Lock()
			if k := c.Options.Targets.GetKey(target); k != -1 && !utils.IsURL(target) {
				c.Options.Targets[k] = "http://" + target
				target = "http://" + target
			}
			MMutex.Unlock()

			targetlive.TLive.HandleTargetLive(target, 0)

			return target, errors.New("target response failed")
		}

		MMutex.Lock()
		if k := c.Options.Targets.GetKey(target); k != -1 && !utils.IsURL(target) {
			c.Options.Targets[k] = newtarget
			target = newtarget
		}
		MMutex.Unlock()

	}
	return target, nil

}

func (c *Checker) CheckGopoc(target, gopocName string) (err error) {
	gpa := gopoc.New(target)

	// check target alive.
	if targetlive.TLive.HandleTargetLive(target, -1) == -1 || len(target) == 0 {
		c.Result.IsVul = false
		return err
	}

	targetlive.TLive.AddRequestTarget(target+gopocName, 1)
	fun := gopoc.GetGoPocFunc(gopocName)
	r, err := fun(gpa)
	if err != nil {
		targetlive.TLive.AddRequestTarget(target+gopocName, 2)
		c.Result.IsVul = false
		c.Result.PocInfo = gpa.Poc
		return err
	}
	targetlive.TLive.AddRequestTarget(target+gopocName, 2)

	c.Result.Target = target
	c.Result.FullTarget = target
	c.Result.IsVul = true
	c.Result.PocInfo = gpa.Poc
	if len(r.AllPocResult) > 0 {
		for _, v := range r.AllPocResult {
			c.Result.AllPocResult = append(c.Result.AllPocResult, &PocResult{ResultRequest: v.ResultRequest, ResultResponse: v.ResultResponse, IsVul: v.IsVul, FullTarget: target})
		}
	}

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
			// fixed set string failed bug
			c.VariableMap[key] = fmt.Sprintf("%v", value)
			c.CustomLib.UpdateCompileOption(key, decls.String)
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
	sub := utils.CreateRandomString(12)
	urlStr := fmt.Sprintf("http://%s.%s", sub, ReverseCeyeDomain)
	u, _ := url.Parse(urlStr)
	return &proto.Reverse{
		Url:                utils.ParseUrl(u),
		Domain:             u.Hostname(),
		Ip:                 "",
		IsDomainNameServer: false,
	}
}

func checkExpression(expression string) string {
	if strings.Contains(expression, "!= \"\"") {
		pos := strings.Index(expression, "!= \"\"")
		name := strings.Trim(strings.TrimSpace(expression[:pos]), "\"")
		return name
	}
	return ""

}
