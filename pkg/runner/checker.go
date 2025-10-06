package runner

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/protocols/gox"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/protocols/netxclient"
	"github.com/zan8in/afrog/v3/pkg/protocols/raw"
	"github.com/zan8in/afrog/v3/pkg/result"

	"github.com/google/cel-go/checker/decls"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/utils"
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

		if len(reqType) > 0 && reqType != string(poc.HTTP_Type) && reqType != string(poc.HTTPS_Type) {
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
				rt := raw.RawHttp{
					RawhttpClient:   raw.GetRawHTTP(c.Options.Proxy, int(c.Options.Timeout)),
					MaxRespBodySize: c.Options.MaxRespBodySize,
					// 新增最大响应体限制
					// @editor 2024/02/06
				}
				err = rt.RawHttpRequest(rule.Request.Raw, target, c.Options.Header, c.VariableMap)

			} else {
				// 自定义type类型：http、https
				// @editor 2024/08/07
				targetTmp := target
				if len(reqType) > 0 {
					if reqType == poc.HTTPS_Type {
						if strings.HasPrefix(targetTmp, "http://") {
							targetTmp = strings.Replace(targetTmp, "http://", "https://", 1)
						}
					}
					if reqType == poc.HTTP_Type {
						if strings.HasPrefix(targetTmp, "https://") {
							targetTmp = strings.Replace(targetTmp, "https://", "http://", 1)
						}
					}
				}
				err = retryhttpclient.Request(targetTmp, c.Options.Header, rule, c.VariableMap)
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

		if len(rule.Output) > 0 && isMatch {
			c.UpdateVariableMap(rule.Output)
		}

		if len(rule.Extractors) > 0 && isMatch {
			c.UpdateVariableMapExtractor(rule.Extractors)
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
		if c.VariableMap["target"] != nil {
			c.Result.Target = c.VariableMap["target"].(string)
		}
		c.Result.AllPocResult = append(c.Result.AllPocResult, &pocRstTemp)

		if rule.StopIfMismatch && !isMatch {
			c.Result.IsVul = false
			return err
		}

		if rule.StopIfMatch && isMatch {
			if len(pocItem.Extractors) > 0 {
				c.UpdateVariableMapExtractor(pocItem.Extractors)
			}
			c.Result.IsVul = true
			return err
		}

		if matchCondition == poc.STOP_IF_FIRST_MISMATCH && !isMatch {
			c.Result.IsVul = false
			return err
		}

		if matchCondition == poc.STOP_IF_FIRST_MATCH && isMatch {
			if len(pocItem.Extractors) > 0 {
				c.UpdateVariableMapExtractor(pocItem.Extractors)
			}
			c.Result.IsVul = true
			return err
		}

	}

	if len(pocItem.Extractors) > 0 {
		c.UpdateVariableMapExtractor(pocItem.Extractors)
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

		// if value == "newReverse()" {
		// 	c.VariableMap[key] = c.newRerverse()
		// 	c.CustomLib.UpdateCompileOption(key, decls.NewObjectType("proto.Reverse"))
		// 	continue
		// }

		if value == "oob()" {
			c.VariableMap[key] = c.oob()
			c.CustomLib.UpdateCompileOption(key, decls.NewObjectType("proto.OOB"))
			continue
		}

		// if value == "newJNDI()" {
		// 	c.VariableMap[key] = c.newJNDI()
		// 	c.CustomLib.UpdateCompileOption(key, decls.NewObjectType("proto.Reverse"))
		// 	continue
		// }

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

func (c *Checker) UpdateVariableMapExtractor(extractors []poc.Extractors) {
	for _, v := range extractors {
		tpe := v.Type
		extMap := v.Extractor
		if len(extMap) == 0 {
			continue
		}
		for _, item := range extMap {
			key := item.Key.(string)
			value := item.Value.(string)

			if tpe == "word" {
				new := setVariableMap(value, c.VariableMap)
				c.VariableMap[key] = new
				c.CustomLib.UpdateCompileOption(key, decls.String)
				c.Result.Extractor = append(c.Result.Extractor, yaml.MapItem{Key: key, Value: new})
				continue
			}

			out, err := c.CustomLib.RunEval(value, c.VariableMap)
			if err != nil {
				continue
			}

			switch value := out.Value().(type) {
			case map[string]string:
				c.VariableMap[key] = value
				c.CustomLib.UpdateCompileOption(key, StrStrMapType)
				c.Result.Extractor = append(c.Result.Extractor, yaml.MapItem{Key: key, Value: value})
			case string:
				c.VariableMap[key] = fmt.Sprintf("%v", out)
				c.CustomLib.UpdateCompileOption(key, decls.String)
				c.Result.Extractor = append(c.Result.Extractor, yaml.MapItem{Key: key, Value: value})
			}

		}
	}

}

func (c *Checker) oob() *proto.OOB {
	if OOB == nil {
		return &proto.OOB{}
	}

	vdomains := OOB.GetValidationDomain()

	return &proto.OOB{
		Filter:       vdomains.Filter,
		HTTP:         vdomains.HTTP,
		DNS:          vdomains.DNS,
		ProtocolHTTP: "http",
		ProtocolDNS:  "dns",
	}
}

// func (c *Checker) newRerverse() *proto.Reverse {

// 	urlStr := ""
// 	// sub := utils.CreateRandomString(20)

// 	// 使用反连平台优先权逻辑如下：
// 	// 自建eye反连平台 > ceye反连平台 > eyes.sh反连平台
// 	// @edit 2021.11.29 21:50
// 	// 关联代码 celprogram.go line-596
// 	// if config.ReverseEyeShLive && config.ReverseEyeHost != "eyes.sh" {
// 	// 	urlStr = fmt.Sprintf("http://%s.%s", sub, config.ReverseEyeDomain)
// 	// } else if config.ReverseCeyeLive {
// 	// 	urlStr = fmt.Sprintf("http://%s.%s", sub, config.ReverseCeyeDomain)
// 	// } else if config.ReverseEyeShLive {
// 	// 	urlStr = fmt.Sprintf("http://%s.%s", sub, config.ReverseEyeDomain)
// 	// }

// 	u, _ := url.Parse(urlStr)
// 	return &proto.Reverse{
// 		Url:                utils.ParseUrl(u),
// 		Domain:             u.Hostname(),
// 		Ip:                 u.Host,
// 		IsDomainNameServer: false,
// 	}
// }

// func (c *Checker) newJNDI() *proto.Reverse {
// 	// randomstr := utils.CreateRandomString(22)
// 	// urlStr := fmt.Sprintf("http://%s:%s/%s", config.ReverseJndi, config.ReverseLdapPort, randomstr)
// 	// u, _ := url.Parse(urlStr)
// 	// url := utils.ParseUrl(u)
// 	// return &proto.Reverse{
// 	// 	Url:                url,
// 	// 	Domain:             u.Hostname(),
// 	// 	Ip:                 config.ReverseJndi,
// 	// 	IsDomainNameServer: false,
// 	// }
// 	return &proto.Reverse{}
// }

func checkExpression(expression string) string {
	if strings.Contains(expression, "!= \"\"") {
		pos := strings.Index(expression, "!= \"\"")
		name := strings.Trim(strings.TrimSpace(expression[:pos]), "\"")
		return name
	}
	return ""

}

func setVariableMap(find string, variableMap map[string]any) string {
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
	}
	return find
}
