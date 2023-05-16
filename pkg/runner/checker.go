package runner

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/pkg/protocols/gox"
	"github.com/zan8in/afrog/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/pkg/protocols/netxclient"
	"github.com/zan8in/afrog/pkg/protocols/raw"
	"github.com/zan8in/afrog/pkg/result"

	"github.com/google/cel-go/checker/decls"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/proto"
	"github.com/zan8in/afrog/pkg/utils"
	"gopkg.in/yaml.v2"
)

var MMutex = &sync.Mutex{}

type Checker struct {
	Options *config.Options
	// OriginalRequest *http.Request
	VariableMap map[string]any
	Result      *result.Result
	CustomLib   *CustomLib
}

func (c *Checker) Check(target string, pocItem *poc.Poc) (err error) {
	defer func() {
		if r := recover(); r != nil {
			c.Result.IsVul = false
		}
	}()

	if pocItem.IsHTTPType() {
		if target, err = c.checkURL(target); err != nil {
			c.Result.IsVul = false
			return err
		}
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	c.Result.Target = target
	c.Result.PocInfo = pocItem

	matchCondition := ""
	if strings.Contains(pocItem.Expression, "&&") && !strings.Contains(pocItem.Expression, "||") {
		matchCondition = poc.STOP_IF_FIRST_MISMATCH
	}
	if strings.Contains(pocItem.Expression, "||") && !strings.Contains(pocItem.Expression, "&&") {
		matchCondition = poc.STOP_IF_FIRST_MATCH
	}

	originReq, err := http.NewRequest("GET", target, nil)
	if err != nil {
		c.Result.IsVul = false
		return err
	}
	tempRequest, err := retryhttpclient.ParseRequest(originReq)
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

	for _, ruleMap := range pocItem.Rules {
		k := ruleMap.Key
		rule := ruleMap.Value

		if rule.BeforeSleep != 0 {
			time.Sleep(time.Duration(rule.BeforeSleep) * time.Second)
		}

		isMatch := false
		reqType := strings.ToLower(rule.Request.Type)

		if len(reqType) > 0 && reqType != string(poc.HTTP_Type) {
			if reqType == poc.TCP_Type || reqType == poc.UDP_Type {
				if nc, err := netxclient.NewNetClient(rule.Request.Host, netxclient.Config{
					Network:     rule.Request.Type,
					ReadTimeout: time.Duration(rule.Request.ReadTimeout),
					ReadSize:    rule.Request.ReadSize,
					MaxRetries:  1,
				}); err == nil {
					nc.Request(rule.Request.Data, rule.Request.DataType, c.VariableMap)
					nc.Close()
				}
			}
			if reqType == poc.GO_Type {
				err = gox.Request(target, rule.Request.Data, c.VariableMap)
			}

		} else {

			if len(rule.Request.Raw) > 0 {
				rt := raw.RawHttp{RawhttpClient: raw.GetRawHTTP(int(c.Options.Timeout))}
				err = rt.RawHttpRequest(rule.Request.Raw, target, c.VariableMap)

			} else {

				err = retryhttpclient.Request(target, rule, c.VariableMap)
			}
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

		pocRstTemp := result.PocResult{IsVul: isMatch}
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

func (c *Checker) checkURL(target string) (string, error) {

	// if target check num more than MaxCheckNum
	tcount := c.Options.Targets.Num(target)

	if tcount == ActiveTarget {
		return target, nil
	}

	if tcount > c.Options.MaxHostError {
		return "", fmt.Errorf("%s is blacklisted", target)
	}

	// if target is not url, then check again
	if !utils.IsURL(target) {
		if newtarget, err := retryhttpclient.CheckProtocol(target); err == nil {
			if k := c.Options.Targets.Key(target); k >= 0 {
				c.Options.Targets.Update(k, newtarget)
				c.Options.Targets.SetNum(newtarget, ActiveTarget)
			}
			return newtarget, nil
		}

		c.Options.Targets.UpdateNum(target, 1)
		return target, fmt.Errorf("%s check protocol falied", target)
	}

	// if target is url more than zero, then check protocol against
	if c.Options.Targets.Num(target) >= 0 {
		if newtarget, err := retryhttpclient.CheckProtocol(target); err == nil {
			c.Options.Targets.SetNum(newtarget, ActiveTarget)
			return newtarget, nil
		}

		c.Options.Targets.UpdateNum(target, 1)
		return target, fmt.Errorf("%s no response", target)
	}

	return target, nil
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
	urlStr := fmt.Sprintf("http://%s.%s", sub, config.ReverseCeyeDomain)
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
