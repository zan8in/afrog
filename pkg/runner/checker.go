package runner

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
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

type bruteConfig struct {
	Mode     string
	Continue bool
	Commit   string
}

type savedVar struct {
	value  any
	exists bool
}

func celSafeIdent(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "_"
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			b = append(b, c)
		} else {
			b = append(b, '_')
		}
	}
	if len(b) == 0 {
		return "_"
	}
	if b[0] >= '0' && b[0] <= '9' {
		b = append([]byte{'_'}, b...)
	}
	return string(b)
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
		baseReq := cloneRuleRequest(rule.Request)
		bruteCfg, bruteVars, bruteOrder := parseBrute(rule.Brute)
		bruteTruncated := false
		bruteRequests := 0

		if len(bruteVars) == 0 {
			rule.Request = cloneRuleRequest(baseReq)
			c.preRenderRuleRequest(&rule.Request)

			reqType := strings.ToLower(rule.Request.Type)
			if len(rule.Request.Raw) > 0 {
				err = RawHTTPExecutor{}.Execute(target, rule, c.Options, c.VariableMap)
			} else {
				exec, ok := executors[reqType]
				if !ok {
					exec = HTTPExecutor{}
				}
				err = exec.Execute(target, rule, c.Options, c.VariableMap)
			}

			if err == nil {
				isMatch = c.evalRuleMatch(&rule, pocItem)
			}
		} else {
			coreSnapshot := snapshotVars(c.VariableMap, []string{"request", "response", "fulltarget", "target"})

			found := false
			iterErr := error(nil)
			lastAttemptSnapshot := map[string]savedVar(nil)
			winnerSnapshot := map[string]savedVar(nil)
			reqCount := 0
			maxReq := 0
			if c.Options != nil {
				maxReq = c.Options.BruteMaxRequests
			}
			commit := strings.ToLower(strings.TrimSpace(bruteCfg.Commit))
			if commit == "" {
				commit = "winner"
			}
			for _, key := range bruteOrder {
				c.CustomLib.UpdateCompileOption(key, decls.String)
			}
			forEachBrutePayload(bruteCfg, bruteVars, bruteOrder, func(payload map[string]string) bool {
				if maxReq > 0 && reqCount >= maxReq {
					bruteTruncated = true
					return true
				}
				reqCount++
				attemptSnapshot := snapshotVars(c.VariableMap, append([]string{"request", "response", "fulltarget", "target"}, bruteOrder...))

				for _, key := range bruteOrder {
					if v, ok := payload[key]; ok {
						c.VariableMap[key] = v
					}
				}

				ruleAttempt := rule
				ruleAttempt.Request = cloneRuleRequest(baseReq)
				c.preRenderRuleRequest(&ruleAttempt.Request)

				reqType := strings.ToLower(ruleAttempt.Request.Type)
				if len(ruleAttempt.Request.Raw) > 0 {
					iterErr = RawHTTPExecutor{}.Execute(target, ruleAttempt, c.Options, c.VariableMap)
				} else {
					exec, ok := executors[reqType]
					if !ok {
						exec = HTTPExecutor{}
					}
					iterErr = exec.Execute(target, ruleAttempt, c.Options, c.VariableMap)
				}

				lastAttemptSnapshot = snapshotVars(c.VariableMap, []string{"request", "response", "fulltarget", "target"})
				if iterErr == nil {
					if c.evalRuleMatch(&ruleAttempt, pocItem) {
						found = true
						isMatch = true
						if commit == "winner" || commit == "first" {
							if winnerSnapshot == nil {
								winnerSnapshot = snapshotVars(c.VariableMap, append([]string{"request", "response", "fulltarget", "target"}, bruteOrder...))
							} else {
								restoreVars(c.VariableMap, winnerSnapshot)
							}
							if !bruteCfg.Continue {
								return true
							}
						} else if commit == "last" {
							if !bruteCfg.Continue {
								return true
							}
						} else if commit == "none" {
							commitSnapshot := snapshotVars(c.VariableMap, []string{"request", "response", "fulltarget", "target"})
							restoreVars(c.VariableMap, attemptSnapshot)
							restoreVars(c.VariableMap, commitSnapshot)
							if !bruteCfg.Continue {
								return true
							}
						}
					} else {
						restoreVars(c.VariableMap, attemptSnapshot)
					}
				} else {
					restoreVars(c.VariableMap, attemptSnapshot)
				}

				return false
			})

			bruteRequests = reqCount
			if !found {
				restoreVars(c.VariableMap, coreSnapshot)
				if lastAttemptSnapshot != nil {
					restoreVars(c.VariableMap, lastAttemptSnapshot)
				}
			}
			truncVar := "__brute_truncated_" + celSafeIdent(k)
			c.VariableMap[truncVar] = bruteTruncated
			c.CustomLib.UpdateCompileOption(truncVar, decls.Bool)
			if iterErr != nil {
				err = iterErr
			}
		}

		c.CustomLib.WriteRuleFunctionsROptions(k, isMatch)

		if len(rule.Output) > 0 && isMatch {
			c.UpdateVariableMap(rule.Output)
		}

		if len(rule.Extractors) > 0 && isMatch {
			c.UpdateVariableMapExtractor(rule.Extractors)
		}

		pocRstTemp := result.PocResult{IsVul: isMatch, BruteTruncated: bruteTruncated, BruteRequests: bruteRequests}
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

func cloneRuleRequest(req poc.RuleRequest) poc.RuleRequest {
	out := req
	if req.Headers != nil {
		h := make(map[string]string, len(req.Headers))
		for k, v := range req.Headers {
			h[k] = v
		}
		out.Headers = h
	}
	return out
}

func snapshotVars(variableMap map[string]any, keys []string) map[string]savedVar {
	out := make(map[string]savedVar, len(keys))
	for _, k := range keys {
		v, ok := variableMap[k]
		out[k] = savedVar{value: v, exists: ok}
	}
	return out
}

func restoreVars(variableMap map[string]any, snapshot map[string]savedVar) {
	for k, sv := range snapshot {
		if sv.exists {
			variableMap[k] = sv.value
		} else {
			delete(variableMap, k)
		}
	}
}

func parseBrute(brute yaml.MapSlice) (bruteConfig, map[string][]string, []string) {
	cfg := bruteConfig{Mode: "clusterbomb", Commit: "winner"}
	vars := map[string][]string{}
	order := make([]string, 0, len(brute))

	for _, item := range brute {
		key, ok := item.Key.(string)
		if !ok {
			continue
		}
		kLower := strings.ToLower(strings.TrimSpace(key))

		switch v := item.Value.(type) {
		case bool:
			if kLower == "continue" {
				cfg.Continue = v
				continue
			}
		case int:
			if kLower == "continue" {
				cfg.Continue = v != 0
				continue
			}
		case int64:
			if kLower == "continue" {
				cfg.Continue = v != 0
				continue
			}
		case string:
			if kLower == "mode" {
				cfg.Mode = strings.ToLower(strings.TrimSpace(v))
				continue
			}
			if kLower == "commit" {
				cfg.Commit = strings.ToLower(strings.TrimSpace(v))
				continue
			}
			if kLower == "continue" {
				b, _ := strconv.ParseBool(strings.TrimSpace(v))
				cfg.Continue = b
				continue
			}
		case []any:
			list := make([]string, 0, len(v))
			for _, it := range v {
				if it == nil {
					continue
				}
				list = append(list, fmt.Sprintf("%v", it))
			}
			if len(list) > 0 {
				vars[key] = list
				order = append(order, key)
			}
		case []string:
			if len(v) > 0 {
				vars[key] = append([]string{}, v...)
				order = append(order, key)
			}
		}
	}

	return cfg, vars, order
}

func forEachBrutePayload(cfg bruteConfig, vars map[string][]string, order []string, fn func(map[string]string) bool) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "clusterbomb"
	}
	if len(order) == 0 {
		return
	}

	if mode == "pitchfork" {
		minLen := -1
		for _, k := range order {
			l := len(vars[k])
			if l <= 0 {
				return
			}
			if minLen == -1 || l < minLen {
				minLen = l
			}
		}
		for i := 0; i < minLen; i++ {
			payload := make(map[string]string, len(order))
			for _, k := range order {
				payload[k] = vars[k][i]
			}
			if fn(payload) {
				return
			}
		}
		return
	}

	payload := make(map[string]string, len(order))
	var walk func(idx int) bool
	walk = func(idx int) bool {
		if idx >= len(order) {
			return fn(payload)
		}
		key := order[idx]
		list := vars[key]
		for _, v := range list {
			payload[key] = v
			if walk(idx + 1) {
				return true
			}
		}
		return false
	}
	_ = walk(0)
}

func (c *Checker) evalRuleMatch(rule *poc.Rule, pocItem *poc.Poc) bool {
	if rule == nil {
		return false
	}

	if len(rule.Expressions) > 0 {
		for _, expression := range rule.Expressions {
			evalResult, err := c.CustomLib.RunEval(expression, c.VariableMap)
			if err == nil {
				isMatch := evalResult.Value().(bool)
				if isMatch {
					if name := checkExpression(expression); len(name) > 0 {
						pocItem.Id = name
						pocItem.Info.Name = name
					}
					return true
				}
			}
		}
		return false
	}

	evalResult, err := c.CustomLib.RunEval(rule.Expression, c.VariableMap)
	if err == nil {
		if v, ok := evalResult.Value().(bool); ok {
			return v
		}
	}
	return false
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

		// 新增：根据 YAML 值的实际类型分支处理
		switch v := item.Value.(type) {
		case string:
			// oob() 函数特殊处理
			if v == "oob()" {
				c.VariableMap[key] = c.oob()
				c.CustomLib.UpdateCompileOption(key, decls.NewObjectType("proto.OOB"))
				continue
			}

			// 原有字符串路径：走 CEL 求值
			out, err := c.CustomLib.RunEval(v, c.VariableMap)
			if err != nil {
				// fixed set string failed bug
				c.VariableMap[key] = fmt.Sprintf("%v", v)
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

		case int:
			c.VariableMap[key] = v
			c.CustomLib.UpdateCompileOption(key, decls.Int)
			continue
		case int64:
			c.VariableMap[key] = int(v)
			c.CustomLib.UpdateCompileOption(key, decls.Int)
			continue
		case float64:
			c.VariableMap[key] = v
			c.CustomLib.UpdateCompileOption(key, decls.Double)
			continue
		case bool:
			c.VariableMap[key] = v
			c.CustomLib.UpdateCompileOption(key, decls.Bool)
			continue
		default:
			// 其他类型统一按字符串存（保证兼容）
			c.VariableMap[key] = fmt.Sprintf("%v", v)
			c.CustomLib.UpdateCompileOption(key, decls.String)
			continue
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

func (c *Checker) renderCELPlaceholders(s string) string {
	// 为空直接返回
	if len(s) == 0 {
		return s
	}
	re := regexp.MustCompile(`\{\{(.+?)\}\}`)
	return re.ReplaceAllStringFunc(s, func(m string) string {
		// 提取 {{ ... }} 内的表达式文本
		expr := strings.TrimSpace(m[2 : len(m)-2])
		// 优先走 CEL 求值
		out, err := c.CustomLib.RunEval(expr, c.VariableMap)
		if err != nil {
			// 求值失败，保留原占位符，后续仍可由 setVariableMap 做简单变量替换
			return m
		}
		switch v := out.Value().(type) {
		case *proto.UrlType:
			return utils.UrlTypeToString(v)
		case []byte:
			return string(v)
		default:
			return fmt.Sprintf("%v", v)
		}
	})
}

// 对当前 rule 的请求字段进行预渲染（仅替换能成功求值的表达式）
func (c *Checker) preRenderRuleRequest(req *poc.RuleRequest) {
	// HTTP(S)/RAW/NETX 通用字段
	req.Path = c.renderCELPlaceholders(strings.TrimSpace(req.Path))
	req.Host = c.renderCELPlaceholders(strings.TrimSpace(req.Host))
	req.Body = c.renderCELPlaceholders(strings.TrimSpace(req.Body))
	req.Raw = c.renderCELPlaceholders(strings.TrimSpace(req.Raw))
	req.Data = c.renderCELPlaceholders(strings.TrimSpace(req.Data))

	// CEL 渲染后做一次简单 {{var}} 替换作为兜底
	req.Path = setVariableMap(req.Path, c.VariableMap)
	req.Host = setVariableMap(req.Host, c.VariableMap)
	req.Body = setVariableMap(req.Body, c.VariableMap)
	req.Raw = setVariableMap(req.Raw, c.VariableMap)
	req.Data = setVariableMap(req.Data, c.VariableMap)

	// headers 逐项处理（深拷贝避免并发写入共享 map）
	if req.Headers != nil {
		newHeaders := make(map[string]string, len(req.Headers))
		for hk, hv := range req.Headers {
			h := c.renderCELPlaceholders(strings.TrimSpace(hv))
			newHeaders[hk] = setVariableMap(h, c.VariableMap)
		}
		req.Headers = newHeaders
	}
}
