package poc

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

type TaskTimeoutPolicy struct {
	VisibleCapSec int
	NetCapSec     int
	GoCapSec      int
}

const (
	taskTimeoutBaseSec             = 60
	taskTimeoutRuleBonusStepSec    = 12
	taskTimeoutRuleBonusCapSec     = 48
	taskTimeoutOOBBaseSec          = 20
	taskTimeoutOOBWeightSec        = 8
	taskTimeoutOOBCapSec           = 60
	taskTimeoutSleepBaseSec        = 20
	taskTimeoutSleepWeightSec      = 10
	taskTimeoutSleepCapSec         = 120
	taskTimeoutBruteBaseSec        = 20
	taskTimeoutBruteWeightSec      = 4
	taskTimeoutBruteCapSec         = 180
	taskTimeoutExpressionWeightSec = 8
	taskTimeoutExpressionCapSec    = 32
	taskTimeoutPayloadBonusSec     = 20
	taskTimeoutPayloadCapSec       = 40
	taskTimeoutNetBonusSec         = 60
	taskTimeoutGoBonusSec          = 180
)

var (
	oobCheckRe     = regexp.MustCompile(`(?i)oobCheck\s*\([^,]+,\s*(\d+)\s*\)`)
	sleepCallRe    = regexp.MustCompile(`(?i)\bsleep\s*\(\s*(\d+)\s*\)`)
	waitForDelayRe = regexp.MustCompile(`(?i)WAITFOR\s+DELAY\s+'(?:\d+:)?(\d+):(\d+)'`)
)

type taskTimeoutCategory string

const (
	taskTimeoutCategoryHTTP taskTimeoutCategory = "http"
	taskTimeoutCategoryNet  taskTimeoutCategory = "net"
	taskTimeoutCategoryGo   taskTimeoutCategory = "go"
)

type TaskTimeoutEstimate struct {
	TimeoutSec int
	Reason     string
}

func EstimateTaskTimeout(p Poc, policy TaskTimeoutPolicy) TaskTimeoutEstimate {
	category := detectTaskTimeoutCategory(p)
	capSec := taskTimeoutCategoryCap(policy, category)
	if capSec <= 0 {
		capSec = taskTimeoutBaseSec
	}

	ruleBonus := minInt(maxInt(len(p.Rules)-1, 0)*taskTimeoutRuleBonusStepSec, taskTimeoutRuleBonusCapSec)
	oobBonus := estimateOOBBonus(p)
	sleepBonus := estimateSleepBonus(p)
	bruteBonus := estimateBruteBonus(p)
	expressionBonus := estimateExpressionBonus(p.Expression)
	payloadBonus := estimatePayloadBonus(p)
	typeBonus := estimateTypeBonus(category)

	total := taskTimeoutBaseSec + ruleBonus + oobBonus + sleepBonus + bruteBonus + expressionBonus + payloadBonus + typeBonus
	if total > capSec {
		total = capSec
	}

	parts := []string{
		fmt.Sprintf("base=%ds", taskTimeoutBaseSec),
	}
	if ruleBonus > 0 {
		parts = append(parts, fmt.Sprintf("rules=%ds", ruleBonus))
	}
	if oobBonus > 0 {
		parts = append(parts, fmt.Sprintf("oob=%ds", oobBonus))
	}
	if sleepBonus > 0 {
		parts = append(parts, fmt.Sprintf("sleep=%ds", sleepBonus))
	}
	if bruteBonus > 0 {
		parts = append(parts, fmt.Sprintf("brute=%ds", bruteBonus))
	}
	if expressionBonus > 0 {
		parts = append(parts, fmt.Sprintf("expr=%ds", expressionBonus))
	}
	if payloadBonus > 0 {
		parts = append(parts, fmt.Sprintf("payload=%ds", payloadBonus))
	}
	if typeBonus > 0 {
		parts = append(parts, fmt.Sprintf("type=%ds", typeBonus))
	}
	parts = append(parts, fmt.Sprintf("cap=%ds/%s", capSec, category))

	return TaskTimeoutEstimate{
		TimeoutSec: total,
		Reason:     strings.Join(parts, ","),
	}
}

func detectTaskTimeoutCategory(p Poc) taskTimeoutCategory {
	if strings.TrimSpace(strings.ToLower(p.Transport)) == GO_Type || strings.TrimSpace(strings.ToLower(p.Gopoc)) != "" {
		return taskTimeoutCategoryGo
	}
	hasNet := false
	for _, item := range p.Rules {
		reqType := normalizeTaskTimeoutRequestType(item.Value.Request.Type, p.Transport)
		switch reqType {
		case GO_Type:
			return taskTimeoutCategoryGo
		case TCP_Type, UDP_Type, SSL_Type, JS_Type:
			hasNet = true
		}
	}
	if hasNet {
		return taskTimeoutCategoryNet
	}
	return taskTimeoutCategoryHTTP
}

func taskTimeoutCategoryCap(policy TaskTimeoutPolicy, category taskTimeoutCategory) int {
	switch category {
	case taskTimeoutCategoryGo:
		return policy.GoCapSec
	case taskTimeoutCategoryNet:
		return policy.NetCapSec
	default:
		return policy.VisibleCapSec
	}
}

func estimateOOBBonus(p Poc) int {
	maxOOB := 0
	for _, item := range p.Rules {
		rule := item.Value
		candidates := []string{rule.Expression}
		candidates = append(candidates, rule.Expressions...)
		for _, candidate := range candidates {
			matches := oobCheckRe.FindAllStringSubmatch(candidate, -1)
			for _, match := range matches {
				if len(match) < 2 {
					continue
				}
				sec, err := strconv.Atoi(match[1])
				if err != nil {
					continue
				}
				if sec > maxOOB {
					maxOOB = sec
				}
			}
		}
	}
	if maxOOB <= 0 {
		return 0
	}
	return minInt(taskTimeoutOOBBaseSec+maxOOB*taskTimeoutOOBWeightSec, taskTimeoutOOBCapSec)
}

func estimateSleepBonus(p Poc) int {
	maxSleepSec := 0
	for _, item := range p.Rules {
		rule := item.Value
		if rule.BeforeSleep > 0 && rule.BeforeSleep > maxSleepSec {
			maxSleepSec = rule.BeforeSleep
		}
		candidates := collectSleepCandidates(rule)
		for _, candidate := range candidates {
			if sec := maxSleepDurationSeconds(candidate); sec > maxSleepSec {
				maxSleepSec = sec
			}
		}
	}
	if maxSleepSec <= 0 {
		return 0
	}
	return minInt(taskTimeoutSleepBaseSec+maxSleepSec*taskTimeoutSleepWeightSec, taskTimeoutSleepCapSec)
}

func collectSleepCandidates(rule Rule) []string {
	candidates := []string{
		rule.Expression,
		rule.Request.Path,
		rule.Request.Body,
		rule.Request.Data,
		rule.Request.Raw,
	}
	candidates = append(candidates, rule.Expressions...)
	for k, v := range rule.Request.Headers {
		candidates = append(candidates, k, v)
	}
	for _, step := range rule.Request.Steps {
		if step.Write != nil {
			candidates = append(candidates, step.Write.Data)
		}
		if step.Read != nil {
			candidates = append(candidates, step.Read.ReadUntil)
		}
	}
	return candidates
}

func maxSleepDurationSeconds(src string) int {
	maxSleep := 0
	for _, match := range sleepCallRe.FindAllStringSubmatch(src, -1) {
		if len(match) < 2 {
			continue
		}
		sec, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		if sec > maxSleep {
			maxSleep = sec
		}
	}
	for _, match := range waitForDelayRe.FindAllStringSubmatch(src, -1) {
		if len(match) < 3 {
			continue
		}
		minute, err1 := strconv.Atoi(match[1])
		second, err2 := strconv.Atoi(match[2])
		if err1 != nil || err2 != nil {
			continue
		}
		sec := minute*60 + second
		if sec > maxSleep {
			maxSleep = sec
		}
	}
	return maxSleep
}

func estimateBruteBonus(p Poc) int {
	totalRequests := 0
	for _, item := range p.Rules {
		totalRequests += estimateRuleBruteRequests(item.Value.Brute)
	}
	if totalRequests <= 0 {
		return 0
	}
	return minInt(taskTimeoutBruteBaseSec+totalRequests*taskTimeoutBruteWeightSec, taskTimeoutBruteCapSec)
}

func estimateRuleBruteRequests(brute yaml.MapSlice) int {
	if len(brute) == 0 {
		return 0
	}
	mode := "sniper"
	lengths := make([]int, 0, len(brute))
	for _, item := range brute {
		key := strings.TrimSpace(strings.ToLower(fmt.Sprint(item.Key)))
		switch key {
		case "mode":
			mode = strings.TrimSpace(strings.ToLower(fmt.Sprint(item.Value)))
		case "commit", "continue":
			continue
		default:
			if n := yamlListLength(item.Value); n > 0 {
				lengths = append(lengths, n)
			}
		}
	}
	if len(lengths) == 0 {
		return 0
	}

	switch mode {
	case "pitchfork":
		maxLen := 0
		for _, n := range lengths {
			if n > maxLen {
				maxLen = n
			}
		}
		return maxLen
	case "clusterbomb":
		total := 1
		for _, n := range lengths {
			total *= n
		}
		return total
	default:
		total := 0
		for _, n := range lengths {
			total += n
		}
		return total
	}
}

func yamlListLength(v any) int {
	switch vv := v.(type) {
	case []any:
		return len(vv)
	case []string:
		return len(vv)
	case []int:
		return len(vv)
	default:
		return 0
	}
}

func estimateExpressionBonus(expr string) int {
	if strings.TrimSpace(expr) == "" {
		return 0
	}
	logicOps := strings.Count(expr, "&&") + strings.Count(expr, "||")
	if logicOps <= 0 {
		return 0
	}
	return minInt(logicOps*taskTimeoutExpressionWeightSec, taskTimeoutExpressionCapSec)
}

func estimatePayloadBonus(p Poc) int {
	bonus := 0
	for _, item := range p.Rules {
		req := item.Value.Request
		if len(req.Headers) >= 8 {
			bonus += taskTimeoutPayloadBonusSec
			break
		}
	}
	for _, item := range p.Rules {
		req := item.Value.Request
		if longestPayloadLen(req) >= 400 {
			bonus += taskTimeoutPayloadBonusSec
			break
		}
	}
	return minInt(bonus, taskTimeoutPayloadCapSec)
}

func longestPayloadLen(req RuleRequest) int {
	longest := len(req.Body)
	longest = maxInt(longest, len(req.Data))
	longest = maxInt(longest, len(req.Raw))
	longest = maxInt(longest, len(req.Path))
	for k, v := range req.Headers {
		longest = maxInt(longest, len(k)+len(v))
	}
	for _, step := range req.Steps {
		if step.Write != nil {
			longest = maxInt(longest, len(step.Write.Data))
		}
	}
	return longest
}

func estimateTypeBonus(category taskTimeoutCategory) int {
	switch category {
	case taskTimeoutCategoryGo:
		return taskTimeoutGoBonusSec
	case taskTimeoutCategoryNet:
		return taskTimeoutNetBonusSec
	default:
		return 0
	}
}

func normalizeTaskTimeoutRequestType(reqType, transport string) string {
	reqType = strings.TrimSpace(strings.ToLower(reqType))
	if reqType != "" {
		return reqType
	}
	transport = strings.TrimSpace(strings.ToLower(transport))
	if transport != "" {
		return transport
	}
	return HTTP_Type
}

func TaskTimeoutDuration(p *Poc, fixedFallbackSec int) time.Duration {
	estimateSec := 0
	if p != nil && p.EstimatedTaskTimeoutSec > 0 {
		estimateSec = p.EstimatedTaskTimeoutSec
	}
	if fixedFallbackSec > estimateSec {
		estimateSec = fixedFallbackSec
	}
	if estimateSec <= 0 {
		return 0
	}
	return time.Duration(estimateSec) * time.Second
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
