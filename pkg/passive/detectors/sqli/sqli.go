// Package sqli 实现被动 SQL 注入检测。
//
// 判定遵循「三重确认」，任一环不成立即放弃，宁可漏报也绝不报错：
//  1. 基线稳定性：同请求原样重放多次，响应必须高度一致。动态页面直接跳过。
//  2. 布尔差分：恒真 / 恒假 payload 的响应差异必须显著且可复现。
//  3. 时间盲注：仅在布尔差分不成立时兜底，必须同时满足「延时触发」与「对照不触发」。
//
// 另一个关键点是响应归一化：应用常把参数值反射到页面，若不剔除 payload 文本，
// 任何反射型页面都会被误判成注入。
package sqli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/passive"
)

const (
	// DetectorName 是检测器标识。
	DetectorName = "sqli"
	// VulnType 是漏洞类型标识。
	VulnType = "sqli"

	// maxTraceResponseBytes 是单条证据留档的响应体上限。
	//
	// 证据链会成倍放大存储：一次布尔确认就带 5 条请求/响应。必须设上限，且截断要
	// 显式标注，绝不能让复核者误以为看到的是完整响应。
	maxTraceResponseBytes = 512 << 10
)

// Options 是 SQLi 检测器的判定参数。
type Options struct {
	// MaxPoints 是单个事务最多深测的注入点数。
	MaxPoints int
	// MaxFindings 是单个事务最多产出的发现数。
	MaxFindings int
	// MaxTimePoints 是最多对几个点做时间盲注，避免慢查询拖长检测时间。
	MaxTimePoints int
	// BaselineRounds 是基线重放次数。
	BaselineRounds int
	// StabilityThreshold 是基线两次重放的最低相似度，低于此值判定页面不稳定并跳过。
	StabilityThreshold float64
	// TrueSimilarityMin 是恒真响应与基线的最低相似度。
	TrueSimilarityMin float64
	// FalseSimilarityMax 是恒假响应与基线的最高相似度。
	FalseSimilarityMax float64
	// MinDifference 是恒真与恒假相对基线的相似度最小差值。
	MinDifference float64
	// RepeatSimilarityMin 是同一 payload 两次响应之间的最低相似度。
	RepeatSimilarityMin float64
	// MinBodyBytes 是参与检测的响应体最小长度。
	MinBodyBytes int
	// TimeSleepSeconds 是时间盲注的 SLEEP 秒数。
	TimeSleepSeconds int
	// TimeTriggerThreshold 是判定「延时已触发」的最小增量。
	TimeTriggerThreshold time.Duration
	// TimeControlThreshold 是判定「对照未触发」的最大增量。
	TimeControlThreshold time.Duration
}

// DefaultOptions 返回面向「零误报」的保守默认值。
func DefaultOptions() Options {
	return Options{
		MaxPoints:            8,
		MaxFindings:          4,
		MaxTimePoints:        2,
		BaselineRounds:       2,
		StabilityThreshold:   0.99,
		TrueSimilarityMin:    0.97,
		FalseSimilarityMax:   0.90,
		MinDifference:        0.08,
		RepeatSimilarityMin:  0.95,
		MinBodyBytes:         16,
		TimeSleepSeconds:     3,
		TimeTriggerThreshold: 2500 * time.Millisecond,
		TimeControlThreshold: 1000 * time.Millisecond,
	}
}

// Detector 是 SQL 注入被动检测器。
type Detector struct {
	opts Options
}

// New 创建检测器。
func New(opts Options) *Detector {
	def := DefaultOptions()
	if opts.MaxPoints <= 0 {
		opts.MaxPoints = def.MaxPoints
	}
	if opts.MaxFindings <= 0 {
		opts.MaxFindings = def.MaxFindings
	}
	if opts.MaxTimePoints <= 0 {
		opts.MaxTimePoints = def.MaxTimePoints
	}
	if opts.BaselineRounds < 2 {
		opts.BaselineRounds = def.BaselineRounds
	}
	if opts.StabilityThreshold <= 0 {
		opts.StabilityThreshold = def.StabilityThreshold
	}
	if opts.TrueSimilarityMin <= 0 {
		opts.TrueSimilarityMin = def.TrueSimilarityMin
	}
	if opts.FalseSimilarityMax <= 0 || opts.FalseSimilarityMax >= 1 {
		opts.FalseSimilarityMax = def.FalseSimilarityMax
	}
	if opts.MinDifference <= 0 {
		opts.MinDifference = def.MinDifference
	}
	if opts.RepeatSimilarityMin <= 0 {
		opts.RepeatSimilarityMin = def.RepeatSimilarityMin
	}
	if opts.MinBodyBytes <= 0 {
		opts.MinBodyBytes = def.MinBodyBytes
	}
	if opts.TimeSleepSeconds <= 0 {
		opts.TimeSleepSeconds = def.TimeSleepSeconds
	}
	if opts.TimeTriggerThreshold <= 0 {
		opts.TimeTriggerThreshold = def.TimeTriggerThreshold
	}
	if opts.TimeControlThreshold <= 0 {
		opts.TimeControlThreshold = def.TimeControlThreshold
	}
	return &Detector{opts: opts}
}

// Name 实现 passive.Detector。
func (d *Detector) Name() string { return DetectorName }

// Interest 是零流量门控：只有「有参数、有正文、非二进制」的事务才值得检测。
func (d *Detector) Interest(tx *passive.CapturedTransaction) bool {
	if tx == nil || tx.Request == nil || tx.Response == nil {
		return false
	}
	if len(tx.Response.Body) < d.opts.MinBodyBytes {
		return false
	}
	if isBinaryContent(tx.Response.Headers.Get("Content-Type")) {
		return false
	}
	return len(passive.ParseInjectionPoints(tx.Request)) > 0
}

// InterestReason 实现 passive.InterestReasoner，把「为什么不检测」讲清楚。
//
// 与 Interest 的判定顺序必须保持一致，否则界面会给出与实际判定不符的原因。
func (d *Detector) InterestReason(tx *passive.CapturedTransaction) string {
	if tx == nil || tx.Request == nil || tx.Response == nil {
		return "缺少完整请求或响应"
	}
	if n := len(tx.Response.Body); n < d.opts.MinBodyBytes {
		return fmt.Sprintf("响应体仅 %d 字节，小于检测下限 %d 字节", n, d.opts.MinBodyBytes)
	}
	if ct := tx.Response.Headers.Get("Content-Type"); isBinaryContent(ct) {
		return "响应为二进制内容（" + strings.TrimSpace(ct) + "），不做注入检测"
	}
	if n := len(passive.ParseInjectionPoints(tx.Request)); n == 0 {
		return "没有可注入参数（仅检测 query / 表单 / Cookie 参数）"
	}
	return ""
}

// Detect 实现 passive.Detector。
func (d *Detector) Detect(ctx context.Context, tx *passive.CapturedTransaction, probe passive.Prober) ([]passive.Finding, error) {
	points := passive.ParseInjectionPoints(tx.Request)
	if len(points) == 0 {
		return nil, nil
	}
	if len(points) > d.opts.MaxPoints {
		points = points[:d.opts.MaxPoints]
	}

	findings := make([]passive.Finding, 0, 1)
	timeTested := 0

	for _, p := range points {
		if len(findings) >= d.opts.MaxFindings {
			break
		}

		base, baseTraces, ok := d.stableBaseline(ctx, tx, probe, p)
		if !ok {
			continue
		}

		if f, ok := d.detectBoolean(ctx, tx, probe, p, base, baseTraces); ok {
			findings = append(findings, f)
			continue
		}

		if timeTested >= d.opts.MaxTimePoints {
			continue
		}
		timeTested++
		if f, ok := d.detectTime(ctx, tx, probe, p, base, baseTraces); ok {
			findings = append(findings, f)
		}
	}

	return findings, nil
}

// baseline 是一条注入点的稳定基线。
type baseline struct {
	// body 是归一化后的响应体，用于相似度比较。
	body []byte
	// rawLen 是原始（未归一化）响应体长度，用于 Evidence。
	rawLen int
	// maxDuration 是多次原样重放中的最大耗时，作为时间盲注的保守基线。
	maxDuration time.Duration
}

// stableBaseline 重放多次并确认响应稳定。不稳定则放弃该注入点。
//
// 这一步是误报控制的第一道也是最重要的一道闸：大量站点的响应本身带有时间戳、
// 随机 token、A/B 分桶等内容，任何差分在他们身上都不成立。
func (d *Detector) stableBaseline(ctx context.Context, tx *passive.CapturedTransaction, probe passive.Prober, p passive.InjectionPoint) (*baseline, []passive.Trace, bool) {
	bodies := make([][]byte, 0, d.opts.BaselineRounds)
	traces := make([]passive.Trace, 0, 1)
	var maxDur time.Duration
	var rawLen int

	for i := 0; i < d.opts.BaselineRounds; i++ {
		res, err := probe.Replay(ctx, tx)
		if err != nil || res == nil {
			return nil, nil, false
		}
		if res.Duration > maxDur {
			maxDur = res.Duration
		}
		if rawLen == 0 {
			rawLen = len(res.Body)
			// 只留档第一轮基线：它是后续所有差分的比较基准，其余轮次的价值
			// 体现在「响应是否一致」的结论里，不必重复占位。
			traces = append(traces, traceOf(tx, p, false, "", "基线", "", res))
		}
		bodies = append(bodies, passive.Normalize(res.Body, p.Original))
	}

	minSim := 1.0
	for i := 1; i < len(bodies); i++ {
		sim := passive.Similarity(bodies[0], bodies[i])
		if sim < minSim {
			minSim = sim
		}
		if sim < d.opts.StabilityThreshold {
			return nil, nil, false
		}
	}
	if len(traces) > 0 {
		traces[0].Note = fmt.Sprintf("原样重放 %d 次响应一致（最低相似度 %.3f），耗时 %s，响应体 %d 字节",
			d.opts.BaselineRounds, minSim, maxDur.Round(time.Millisecond), rawLen)
	}

	return &baseline{body: bodies[0], rawLen: rawLen, maxDuration: maxDur}, traces, true
}

// detectBoolean 依次尝试各闭合方式的布尔差分，命中即返回。
func (d *Detector) detectBoolean(ctx context.Context, tx *passive.CapturedTransaction, probe passive.Prober, p passive.InjectionPoint, base *baseline, baseTraces []passive.Trace) (passive.Finding, bool) {
	for _, pair := range boolPairs(p.Original) {
		if f, ok := d.confirmBoolean(ctx, tx, probe, p, base, baseTraces, pair); ok {
			return f, true
		}
	}
	return passive.Finding{}, false
}

// confirmBoolean 对一组 payload 做两轮确认。
//
// 只发一轮请求是不够的：任何一次网络抖动或后端负载波动都可能造出"看起来像"
// 的差异。第二轮的价值在于验证错误页是稳定复现的，而不是偶发。
func (d *Detector) confirmBoolean(ctx context.Context, tx *passive.CapturedTransaction, probe passive.Prober, p passive.InjectionPoint, base *baseline, baseTraces []passive.Trace, pair boolPair) (passive.Finding, bool) {
	trueRes, err := probe.Mutate(ctx, tx, passive.Mutation{Point: p, Value: pair.trueValue})
	if err != nil || trueRes == nil {
		return passive.Finding{}, false
	}
	falseRes, err := probe.Mutate(ctx, tx, passive.Mutation{Point: p, Value: pair.falseValue})
	if err != nil || falseRes == nil {
		return passive.Finding{}, false
	}

	strips := []string{p.Original, pair.trueValue, pair.falseValue}
	trueNorm := passive.Normalize(trueRes.Body, strips...)
	falseNorm := passive.Normalize(falseRes.Body, strips...)

	simTrue := passive.Similarity(trueNorm, base.body)
	simFalse := passive.Similarity(falseNorm, base.body)

	if simTrue < d.opts.TrueSimilarityMin {
		return passive.Finding{}, false
	}
	if simFalse > d.opts.FalseSimilarityMax {
		return passive.Finding{}, false
	}
	if simTrue-simFalse < d.opts.MinDifference {
		return passive.Finding{}, false
	}

	// 第二轮确认：复用同一组 payload，要求结论完全一致。
	trueRes2, err := probe.Mutate(ctx, tx, passive.Mutation{Point: p, Value: pair.trueValue})
	if err != nil || trueRes2 == nil {
		return passive.Finding{}, false
	}
	falseRes2, err := probe.Mutate(ctx, tx, passive.Mutation{Point: p, Value: pair.falseValue})
	if err != nil || falseRes2 == nil {
		return passive.Finding{}, false
	}

	trueNorm2 := passive.Normalize(trueRes2.Body, strips...)
	falseNorm2 := passive.Normalize(falseRes2.Body, strips...)

	simTrueRepeat := passive.Similarity(trueNorm, trueNorm2)
	simFalseRepeat := passive.Similarity(falseNorm, falseNorm2)

	if simTrueRepeat < d.opts.RepeatSimilarityMin {
		return passive.Finding{}, false
	}
	if simFalseRepeat < d.opts.RepeatSimilarityMin {
		return passive.Finding{}, false
	}
	if passive.Similarity(trueNorm2, base.body) < d.opts.TrueSimilarityMin {
		return passive.Finding{}, false
	}
	if passive.Similarity(falseNorm2, base.body) > d.opts.FalseSimilarityMax {
		return passive.Finding{}, false
	}

	evidence := fmt.Sprintf(
		"布尔差分：恒真响应与基线相似度 %.3f（%d 字节），恒假响应相似度 %.3f（%d 字节），差值 %.3f；两轮重放结果一致。闭合方式 %s。",
		simTrue, len(trueRes.Body), simFalse, len(falseRes.Body), simTrue-simFalse, pair.label,
	)

	// 证据链：基线 + 恒真/恒假各两轮。缺了反向载荷或缺少复现，结论都无法自证。
	traces := append([]passive.Trace{}, baseTraces...)
	traces = append(traces,
		traceOf(tx, p, true, pair.trueValue, "恒真 #1",
			fmt.Sprintf("与基线相似度 %.3f，响应 %d 字节", simTrue, len(trueRes.Body)), trueRes),
		traceOf(tx, p, true, pair.falseValue, "恒假 #1",
			fmt.Sprintf("与基线相似度 %.3f，响应 %d 字节", simFalse, len(falseRes.Body)), falseRes),
		traceOf(tx, p, true, pair.trueValue, "恒真 #2",
			fmt.Sprintf("复现验证，与第 1 次一致度 %.3f", simTrueRepeat), trueRes2),
		traceOf(tx, p, true, pair.falseValue, "恒假 #2",
			fmt.Sprintf("复现验证，与第 1 次一致度 %.3f", simFalseRepeat), falseRes2),
	)

	return d.buildFinding(tx, p, pair.trueValue, pair.falseValue, trueRes, evidence, traces), true
}

// detectTime 做时间盲注兜底。
//
// 必须同时满足三件事才成立：延时 payload 的耗时显著高于基线、对照 payload 不延时、
// 且延时能够再复现一次。缺任何一条都可能是网络抖动或目标偶发慢查询。
func (d *Detector) detectTime(ctx context.Context, tx *passive.CapturedTransaction, probe passive.Prober, p passive.InjectionPoint, base *baseline, baseTraces []passive.Trace) (passive.Finding, bool) {
	for _, pair := range timePairs(p.Original, d.opts.TimeSleepSeconds) {
		trigger, err := probe.Mutate(ctx, tx, passive.Mutation{Point: p, Value: pair.trueValue})
		if err != nil || trigger == nil {
			continue
		}
		if trigger.Duration < base.maxDuration+d.opts.TimeTriggerThreshold {
			continue
		}

		control, err := probe.Mutate(ctx, tx, passive.Mutation{Point: p, Value: pair.falseValue})
		if err != nil || control == nil {
			continue
		}
		if control.Duration >= base.maxDuration+d.opts.TimeControlThreshold {
			continue
		}

		trigger2, err := probe.Mutate(ctx, tx, passive.Mutation{Point: p, Value: pair.trueValue})
		if err != nil || trigger2 == nil {
			continue
		}
		if trigger2.Duration < base.maxDuration+d.opts.TimeTriggerThreshold {
			continue
		}

		evidence := fmt.Sprintf(
			"时间盲注：触发请求耗时 %s / %s，对照请求耗时 %s，基线耗时 %s，SLEEP(%d) 两次复现一致。闭合方式 %s。",
			trigger.Duration.Round(time.Millisecond),
			trigger2.Duration.Round(time.Millisecond),
			control.Duration.Round(time.Millisecond),
			base.maxDuration.Round(time.Millisecond),
			d.opts.TimeSleepSeconds,
			pair.label,
		)

		// 证据链：基线 + 延时触发两次 + 不延时的对照，缺了对照就无法排除「目标本来就慢」。
		traces := append([]passive.Trace{}, baseTraces...)
		traces = append(traces,
			traceOf(tx, p, true, pair.trueValue, "延时触发 #1",
				fmt.Sprintf("耗时 %s，超出基线 %s（阈值 %s）",
					trigger.Duration.Round(time.Millisecond),
					base.maxDuration.Round(time.Millisecond),
					d.opts.TimeTriggerThreshold), trigger),
			traceOf(tx, p, true, pair.falseValue, "对照组",
				fmt.Sprintf("耗时 %s，未触发延时（阈值 %s）",
					control.Duration.Round(time.Millisecond),
					d.opts.TimeControlThreshold), control),
			traceOf(tx, p, true, pair.trueValue, "延时触发 #2",
				fmt.Sprintf("复现验证，耗时 %s", trigger2.Duration.Round(time.Millisecond)), trigger2),
		)

		return d.buildFinding(tx, p, pair.trueValue, pair.falseValue, trigger, evidence, traces), true
	}
	return passive.Finding{}, false
}

func (d *Detector) buildFinding(tx *passive.CapturedTransaction, p passive.InjectionPoint, trueValue, falseValue string, res *passive.CapturedResponse, evidence string, traces []passive.Trace) passive.Finding {
	reqClone := tx.Request.Clone()
	_ = passive.ApplyMutation(reqClone, passive.Mutation{Point: p, Value: trueValue})

	reqRaw, resRaw := passive.RawHTTPDump(reqClone, res)

	var latencyMs int64
	if res != nil {
		latencyMs = res.Duration.Milliseconds()
	}

	return passive.Finding{
		Detector:   DetectorName,
		VulnType:   VulnType,
		Severity:   "high",
		Confidence: passive.ConfidenceCertain,
		Title:      "SQL 注入",
		Target:     targetOf(tx),
		Location:   string(p.Location) + ":" + p.Name,
		Payload:    trueValue,
		LatencyMs:  latencyMs,
		Evidence:   evidence,
		Request:    reqRaw,
		Response:   resRaw,
		Traces:     traces,
		Extra: map[string]any{
			"false_payload": falseValue,
			"parameter":     p.Name,
			"location":      string(p.Location),
			"original":      p.Original,
		},
	}
}

// traceOf 把一次参与判定的请求/响应整理成证据留档。
//
// mutated 为 false 表示原样重放（基线），此时 payload 记原始值。
func traceOf(tx *passive.CapturedTransaction, p passive.InjectionPoint, mutated bool, value, label, note string, res *passive.CapturedResponse) passive.Trace {
	req := tx.Request.Clone()
	if mutated {
		_ = passive.ApplyMutation(req, passive.Mutation{Point: p, Value: value})
	} else {
		value = p.Original
	}

	reqRaw, resRaw := passive.RawHTTPDump(req, res)

	tr := passive.Trace{
		Label:    label,
		Payload:  value,
		Note:     note,
		Request:  string(reqRaw),
		Response: capTraceResponse(string(resRaw)),
	}
	if res != nil {
		tr.Status = res.Status
		tr.LatencyMs = res.Duration.Milliseconds()
	}
	return tr
}

// capTraceResponse 给单条留档的响应体设上限，避免证据链把数据库撑爆。
// 截断必须显式标注，复核者要能一眼看出看到的不是完整响应。
func capTraceResponse(s string) string {
	if len(s) <= maxTraceResponseBytes {
		return s
	}
	return s[:maxTraceResponseBytes] + fmt.Sprintf("\r\n\r\n[afrog] 响应超出 %d KB 已截断，原始 %d 字节",
		maxTraceResponseBytes>>10, len(s))
}

func targetOf(tx *passive.CapturedTransaction) string {
	if tx == nil || tx.Request == nil || tx.Request.URL == nil {
		return ""
	}
	u := *tx.Request.URL
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func isBinaryContent(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if ct == "" {
		return false
	}
	prefixes := []string{
		"image/", "audio/", "video/", "font/",
		"application/octet-stream", "application/zip", "application/pdf",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	return false
}
