// Package sqli 实现被动 SQL 注入检测。
//
// 判定遵循「多重确认」，任一环不成立即放弃，宁可漏报也绝不报错：
//  1. 基线稳定性：同请求原样重放多次，响应必须高度一致。动态页面直接跳过。
//  2. 报错型：破坏语法闭合的探针必须逼出数据库专有的报错特征，且基线里本来没有、
//     还能复现。这是最省流量的确认路径，因此排在最前。
//  3. 布尔差分：恒真 / 恒假 payload 的响应差异必须显著且可复现。
//  4. 时间盲注：仅在布尔差分不成立时兜底。除了「延时触发 + 对照不触发 + 可复现」，
//     还要把延时秒数逐档上调（n / 2n / 3n），要求延时差同步成比例且持续增长——单点延时
//     可能是偶发慢查询，成比例且线性增长才说明延时确实由我们给出的秒数驱动。
//
// 在「零误报」之上，本检测器追求验证的广度：
//   - 数据库方言：布尔条件各方言通用，按闭合上下文展开（含 LIKE、双层括号等边界）；
//     时间盲注覆盖 MySQL / PostgreSQL / MSSQL / Oracle，并先用响应里的强信号指认
//     方言，把候选收敛到最可能命中的那一类；
//   - WAF / EDR 绕过：观察到拦截迹象时追加语义等价的混淆 payload
//     （大小写、内联注释、等价空白、等价运算符、等价注释终止），以及依赖后端
//     多做一层解码的编码类绕过（双重 URL、%uXXXX、十六进制字符实体）；
//   - 注入点：query / RESTful 路径段 / 表单 / JSON 字符串字段（含嵌套与数组）/
//     XML 元素文本 / multipart 字段 / Cookie / Referer / User-Agent /
//     X-Forwarded-For。头部注入点单独设档：请求头几乎每个浏览器请求都带，若与
//     query 同权深测会成倍放大流量，因此「只有头部注入点」的事务只跑报错型，
//     且只发单引号探针——零基线重放 + 每个点最多两次请求。
//
// 广度不牺牲准确率：每一条候选都必须通过同一套差分门控，增加候选只是增加
// 「证明漏洞存在」的机会，而不是降低结论门槛。
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

	// timeDegreeFactor 是时间盲注「加档」的倍数：先在 SLEEP(n) 上确认延时，
	// 再用 SLEEP(2n) 验证延时差是否随秒数成比例增长。
	timeDegreeFactor = 2

	// timeThirdDegreeFactor 是三档复核的秒数倍率（相对基准档）：两档成比例后再看
	// 第三档是否继续增长，进一步排除「服务端把延时顶到某个固定上限」这类伪成比例。
	timeThirdDegreeFactor = 3

	// timeSaturationTolerance 用于识别「服务端把两档延时都压到了同一个上限」
	// （如查询超时、连接超时）。此时两档耗时接近，属于可解释形态，不按比例失配处理。
	timeSaturationTolerance = 500 * time.Millisecond
)

// 注入技术类型，用于证据说明与结果归类。
const (
	techniqueError   = "error"
	techniqueBoolean = "boolean"
	techniqueTime    = "time"
)

// Options 是 SQLi 检测器的判定参数。
type Options struct {
	// MaxPoints 是单个事务最多深测的注入点数。
	MaxPoints int
	// MaxFindings 是单个事务最多产出的发现数。
	MaxFindings int
	// MaxErrorPoints 是最多对几个点做报错型检测。报错型成本最低，但每个点仍要
	// 尝试若干探针，设上限避免参数多的请求放大流量。
	MaxErrorPoints int
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
	// ShortPageLineTolerance 是短页面上允许的「噪声行」数（按行级对称差计）：
	// 恒真响应与基线的对称差不超过该值、非空行数保持不变、且相似度不低于
	// ShortPageSimilarityFloor、长度漂移也在允许范围内时，仍视为「结构一致」。
	//
	// 存在的理由是按行 Jaccard 在短页面上的脆性：N 行正文改一行，相似度恰为
	// (N-1)/(N+1)——N=104 时是 0.981（达标），N=14 时只有 0.867（跌破 0.97）。
	// 真实短页面常有一行动态 UI（导航高亮、A/B 分桶）差异，不给绝对量豁免就会把
	// 结构其实一致的恒真响应判成不成立，造成漏报。注意「改一行」的对称差是 2
	// （旧行 + 新行），因此默认取 2。
	//
	// 豁免要求非空行数不变，是为了排除「结果集变空」（对称差同样是 2，但是删了
	// 两行）——那正是恒假条件的形态，不能当噪声放行。
	ShortPageLineTolerance int
	// ShortPageSimilarityFloor 是上述豁免的相似度下限，防止把真实的结构性破坏放进来。
	ShortPageSimilarityFloor float64
	// MinBodyBytes 是参与检测的响应体最小长度。
	MinBodyBytes int
	// TimeSleepSeconds 是时间盲注的 SLEEP 秒数。
	TimeSleepSeconds int
	// TimeTriggerThreshold 是判定「延时已触发」的最小增量。
	TimeTriggerThreshold time.Duration
	// TimeControlThreshold 是判定「对照未触发」的最大增量。
	TimeControlThreshold time.Duration
	// TimeRatioMin / TimeRatioMax 是加档后的延时差倍率允许区间。
	//
	// 秒数翻倍，延时差也应约翻倍，因此区间围绕 2 展开。区间不宜过窄：真实网络的
	// 抖动会让倍率上下浮，过窄会把真漏洞判成漏报。
	TimeRatioMin float64
	TimeRatioMax float64
	// DisableEvasion 关闭 WAF / EDR 绕过。
	//
	// 零值 false 表示启用，与「零值跟随默认」的约定一致：绕过只在观察到拦截迹象时
	// 才付出额外流量，默认开启不会给正常站点带来额外开销。
	DisableEvasion bool
	// EvasionAlways 为 true 时无条件尝试绕过 payload，而不只在观察到拦截迹象时。
	//
	// 会显著增加重放流量，仅在明确需要最大广度（例如已知目标有静默拦截的 WAF）时开启。
	EvasionAlways bool
}

// DefaultOptions 返回面向「零误报」的保守默认值。
func DefaultOptions() Options {
	return Options{
		MaxPoints:           8,
		MaxFindings:         4,
		MaxErrorPoints:      3,
		MaxTimePoints:       2,
		BaselineRounds:      2,
		StabilityThreshold:  0.99,
		TrueSimilarityMin:   0.97,
		FalseSimilarityMax:  0.90,
		MinDifference:       0.08,
		RepeatSimilarityMin: 0.95,
		// 短页面豁免：允许一行被改写（对称差 2），相似度不得低于 0.80。
		ShortPageLineTolerance:   2,
		ShortPageSimilarityFloor: 0.80,
		MinBodyBytes:             16,
		TimeSleepSeconds:         3,
		TimeTriggerThreshold:     2500 * time.Millisecond,
		TimeControlThreshold:     1000 * time.Millisecond,
		TimeRatioMin:             1.5,
		TimeRatioMax:             3.0,
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
	if opts.MaxErrorPoints <= 0 {
		opts.MaxErrorPoints = def.MaxErrorPoints
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
	if opts.ShortPageLineTolerance <= 0 {
		opts.ShortPageLineTolerance = def.ShortPageLineTolerance
	}
	if opts.ShortPageSimilarityFloor <= 0 {
		opts.ShortPageSimilarityFloor = def.ShortPageSimilarityFloor
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
	if opts.TimeRatioMin <= 0 {
		opts.TimeRatioMin = def.TimeRatioMin
	}
	// 只校验「上界不大于下界」这一种无效配置；其余情况按原值使用，便于测试收紧区间。
	if opts.TimeRatioMax <= opts.TimeRatioMin {
		opts.TimeRatioMax = def.TimeRatioMax
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
		return "没有可注入参数（query / 路径 / 表单 / JSON / XML / multipart / Cookie / 请求头里都没有可变异的值）"
	}
	return ""
}

// Detect 实现 passive.Detector。
func (d *Detector) Detect(ctx context.Context, tx *passive.CapturedTransaction, probe passive.Prober) ([]passive.Finding, error) {
	points := passive.ParseInjectionPoints(tx.Request)
	if len(points) == 0 {
		return nil, nil
	}
	// 「只有头部注入点」的事务走轻量档：请求头（Referer / User-Agent /
	// X-Forwarded-For）几乎每个浏览器请求都带，若与 query / 表单同权深测，动态流量
	// 会被成倍放大。这类事务只跑报错型——成本最低、证据最直接，且判定不依赖相似度，
	// 可以零流量建立对照（直接用捕获到的原始响应当基线）。
	headerOnly := true
	for _, p := range points {
		if p.Location != passive.LocationHeader {
			headerOnly = false
			break
		}
	}
	if len(points) > d.opts.MaxPoints {
		points = points[:d.opts.MaxPoints]
	}

	findings := make([]passive.Finding, 0, 1)
	errorTested := 0
	timeTested := 0

	for _, p := range points {
		if len(findings) >= d.opts.MaxFindings {
			break
		}

		if headerOnly {
			if errorTested >= d.opts.MaxErrorPoints {
				continue
			}
			errorTested++
			base, baseTraces := capturedBaseline(tx, p)
			sess := &pointSession{baseStatus: base.status}
			sess.observeDialect(tx.Response)
			if f, ok := d.tryErrorProbes(ctx, tx, probe, p, base, baseTraces, sess, headerErrorProbes); ok {
				findings = append(findings, f)
			}
			continue
		}

		base, baseTraces, ok := d.stableBaseline(ctx, tx, probe, p)
		if !ok {
			continue
		}

		sess := &pointSession{baseStatus: base.status}
		// 方言指纹来自原始捕获响应，零额外流量；有它就能把时间盲注候选收敛到
		// 最可能命中的方言上。
		sess.observeDialect(tx.Response)

		// 第零层：报错型。两次请求即可定论，证据最直接，因此排在布尔差分前面。
		if errorTested < d.opts.MaxErrorPoints {
			errorTested++
			if f, ok := d.tryErrorProbes(ctx, tx, probe, p, base, baseTraces, sess, errorProbes); ok {
				findings = append(findings, f)
				continue
			}
		}

		// 第一层：通用布尔差分的全部闭合上下文。
		if f, ok := d.tryCandidates(ctx, tx, probe, p, base, baseTraces, sess, techniqueBoolean, boolPairs(p.Original)); ok {
			findings = append(findings, f)
			continue
		}

		// 第二层：按数据库方言逐一尝试时间盲注，顺序参考方言指纹。
		if timeTested < d.opts.MaxTimePoints {
			timeTested++
			pairs := timePairs(p.Original, d.opts.TimeSleepSeconds)
			if sess.dialectHint != "" {
				pairs = orderByDialectHint(pairs, sess.dialectHint)
			}
			if f, ok := d.tryCandidates(ctx, tx, probe, p, base, baseTraces, sess, techniqueTime, pairs); ok {
				findings = append(findings, f)
				continue
			}
		}

		// 第三层：WAF / EDR 绕过兜底。
		//
		// 只有在观察到拦截迹象时才投入这部分流量：它成倍于前两层，而绝大多数
		// 站点既没有 WAF 也不存在「被拦住的漏洞」。
		if d.evasionEnabled() && (sess.wafSuspected || d.opts.EvasionAlways) {
			if f, ok := d.tryCandidates(ctx, tx, probe, p, base, baseTraces, sess, techniqueBoolean, evasionBoolPairs(p.Original)); ok {
				findings = append(findings, f)
				continue
			}
			if f, ok := d.tryCandidates(ctx, tx, probe, p, base, baseTraces, sess, techniqueTime, evasionTimePairs(p.Original, d.opts.TimeSleepSeconds)); ok {
				findings = append(findings, f)
			}
		}
	}

	return findings, nil
}

func (d *Detector) evasionEnabled() bool { return !d.opts.DisableEvasion }

// tryCandidates 依次尝试候选，任一条通过门控即返回。
//
// 顺序即成本：候选按命中概率排列，前面的先试，命中后立即停止，
// 因此「候选变多」只在未命中的站点上体现为流量。
func (d *Detector) tryCandidates(ctx context.Context, tx *passive.CapturedTransaction, probe passive.Prober, p passive.InjectionPoint, base *baseline, baseTraces []passive.Trace, sess *pointSession, technique string, pairs []boolPair) (passive.Finding, bool) {
	for _, pair := range pairs {
		var (
			f  passive.Finding
			ok bool
		)
		if technique == techniqueTime {
			f, ok = d.confirmTime(ctx, tx, probe, p, base, baseTraces, sess, pair)
		} else {
			f, ok = d.confirmBoolean(ctx, tx, probe, p, base, baseTraces, sess, pair)
		}
		if ok {
			return f, true
		}
	}
	return passive.Finding{}, false
}

// tryErrorProbes 依次用破坏语法闭合的探针触发数据库报错，任一条通过门控即返回。
//
// 门控三步，缺一不可：基线里本来没有该报错特征、注入后出现了、再打一次还能出现。
// 第一条排除了「站点自带文案」，第三条排除了偶发（如后端恰好抽风返回了错误页）。
func (d *Detector) tryErrorProbes(ctx context.Context, tx *passive.CapturedTransaction, probe passive.Prober, p passive.InjectionPoint, base *baseline, baseTraces []passive.Trace, sess *pointSession, probes []errorProbe) (passive.Finding, bool) {
	for _, ep := range probes {
		value := fmt.Sprintf(ep.tmpl, p.Original)

		res, err := probe.Mutate(ctx, tx, passive.Mutation{Point: p, Value: value})
		if err != nil || res == nil {
			continue
		}
		sess.observe(res)
		dialect, marker := reportError(res.Body)
		if marker == "" {
			continue
		}
		// 基线里本来就有的特征不算：那是页面的固有文案，不是被我们打出来的报错。
		if containsMarker(base.body, marker) {
			continue
		}

		res2, err := probe.Mutate(ctx, tx, passive.Mutation{Point: p, Value: value})
		if err != nil || res2 == nil {
			continue
		}
		sess.observe(res2)
		if _, marker2 := reportError(res2.Body); marker2 == "" {
			continue
		}

		return d.buildErrorFinding(tx, p, ep, dialect, marker, value, res, res2, baseTraces), true
	}
	return passive.Finding{}, false
}

// buildErrorFinding 组装报错型的发现。
func (d *Detector) buildErrorFinding(tx *passive.CapturedTransaction, p passive.InjectionPoint, ep errorProbe, dialect, marker, value string, res, res2 *passive.CapturedResponse, baseTraces []passive.Trace) passive.Finding {
	// 复用 buildFinding 的字段约定：恒假槽位放「原样值」，即这次报错型的对照组。
	pair := boolPair{
		label:      "报错型/" + ep.name,
		dialect:    dialect,
		trueValue:  value,
		falseValue: p.Original,
	}

	evidence := fmt.Sprintf(
		"报错型：注入 %q 后响应出现 %s 报错特征「%s」，基线响应不含该特征，且复现一致——说明参数被直接拼进了 SQL 语句。",
		value, dialect, marker,
	)

	// 证据链：基线（对照）+ 报错触发两次。基线本身就是对照，不必另发请求。
	traces := append([]passive.Trace{}, baseTraces...)
	traces = append(traces,
		traceOf(tx, p, true, value, "报错触发 #1",
			fmt.Sprintf("响应出现 %s 报错特征「%s」", dialect, marker), res),
		traceOf(tx, p, true, value, "报错触发 #2",
			"复现验证，报错特征再次出现", res2),
	)

	return d.buildFinding(tx, p, pair, techniqueError, res, evidence, traces)
}

// baseline 是一条注入点的稳定基线。
type baseline struct {
	// body 是归一化后的响应体，用于相似度比较。
	body []byte
	// rawLen 是原始（未归一化）响应体长度，用于 Evidence。
	rawLen int
	// maxDuration 是多次原样重放中的最大耗时，作为时间盲注的保守基线。
	maxDuration time.Duration
	// status 是基线的响应状态码，用于识别「注入后被拒」的拦截迹象。
	status int
}

// stableBaseline 重放多次并确认响应稳定。不稳定则放弃该注入点。
//
// 这一步是误报控制的第一道也是最重要的一道闸：大量站点的响应本身带有时间戳、
// 随机 token、A/B 分桶等内容，任何差分在他们身上都不成立。
func (d *Detector) stableBaseline(ctx context.Context, tx *passive.CapturedTransaction, probe passive.Prober, p passive.InjectionPoint) (*baseline, []passive.Trace, bool) {
	bodies := make([][]byte, 0, d.opts.BaselineRounds)
	traces := make([]passive.Trace, 0, 1)
	var maxDur time.Duration
	var rawLen, status int

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
			status = res.Status
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

	return &baseline{body: bodies[0], rawLen: rawLen, maxDuration: maxDur, status: status}, traces, true
}

// capturedBaseline 直接拿捕获到的原始响应当对照，不额外发任何请求。
//
// 只用于「只有头部注入点」的报错型轻量档：报错特征的判定不依赖响应相似度
// （页面抖动不可能凭空造出数据库报错），因此不需要基线稳定性判定，省下的重放量
// 正好抵消头部注入点带来的流量放大。
func capturedBaseline(tx *passive.CapturedTransaction, p passive.InjectionPoint) (*baseline, []passive.Trace) {
	res := tx.Response
	raw := res.Body
	return &baseline{
			body:        passive.Normalize(raw, p.Original),
			rawLen:      len(raw),
			maxDuration: res.Duration,
			status:      res.Status,
		}, []passive.Trace{
			traceOf(tx, p, false, "", "基线",
				fmt.Sprintf("取自捕获到的原始响应（未重放），响应体 %d 字节", len(raw)), res),
		}
}

// trueMatchesBaseline 判断恒真响应是否与基线「结构一致」。
//
// 主判据是行级相似度 ≥ TrueSimilarityMin。对短页面额外放行少量噪声行（见
// Options.ShortPageLineTolerance），但要同时满足三个结构性交叉验证——
// 非空行数不变、相似度不低于下限、长度漂移在允许范围内，缺一不可。
//
// 其中「非空行数必须相同」是关键守卫：对称差为 2 有两种成因，一是「改 1 行」
// （行数不变，典型的动态 UI 噪声），二是「删 2 行」（行数少 2，正是恒假条件下
// 结果集变空的形态）。只看对称差会把后者当噪声放行，从而把恒假响应误判成恒真；
// 要求行数不变即可把豁免严格限定为「纯内容改写」，行数有增减的一律回到严格阈值。
//
// 豁免天然只作用于短页面：对称差 ≤ 2 且行数不变时，长页面（非空行数 ≥ 66）的
// 相似度本来就 ≥ 0.97，走不到豁免分支；能落进这里的必然是「严格阈值在数学上
// 吸收不了这点噪声」的小页面。
//
// 返回 (相似度, 是否通过, 是否走了短页豁免)。
func (d *Detector) trueMatchesBaseline(norm []byte, base *baseline) (float64, bool, bool) {
	sim := passive.Similarity(norm, base.body)
	if sim >= d.opts.TrueSimilarityMin {
		return sim, true, false
	}
	if passive.DiffLines(norm, base.body) > d.opts.ShortPageLineTolerance {
		return sim, false, false
	}
	if passive.LineCount(norm) != passive.LineCount(base.body) {
		return sim, false, false
	}
	if sim < d.opts.ShortPageSimilarityFloor {
		return sim, false, false
	}
	if !withinLengthDrift(norm, base.body) {
		return sim, false, false
	}
	return sim, true, true
}

// withinLengthDrift 判断两段归一化正文的长度是否接近。
//
// 归一化会把 payload 统一替换成等长占位符，因此「结果集不变」时长度天然接近；
// 长度漂移明显则说明正文内容确实变了——此时单看「差了几行」不足以判定结构一致，
// 必须一并否决，这是短页豁免的结构化交叉验证。
func withinLengthDrift(a, b []byte) bool {
	diff := len(a) - len(b)
	if diff < 0 {
		diff = -diff
	}
	return diff <= len(b)/20+32
}

// confirmBoolean 对一组 payload 做两轮确认。
//
// 只发一轮请求是不够的：任何一次网络抖动或后端负载波动都可能造出"看起来像"
// 的差异。第二轮的价值在于验证错误页是稳定复现的，而不是偶发。
func (d *Detector) confirmBoolean(ctx context.Context, tx *passive.CapturedTransaction, probe passive.Prober, p passive.InjectionPoint, base *baseline, baseTraces []passive.Trace, sess *pointSession, pair boolPair) (passive.Finding, bool) {
	trueRes, err := probe.Mutate(ctx, tx, passive.Mutation{Point: p, Value: pair.trueValue})
	if err != nil || trueRes == nil {
		return passive.Finding{}, false
	}
	sess.observe(trueRes)
	falseRes, err := probe.Mutate(ctx, tx, passive.Mutation{Point: p, Value: pair.falseValue})
	if err != nil || falseRes == nil {
		return passive.Finding{}, false
	}
	sess.observe(falseRes)

	strips := []string{p.Original, pair.trueValue, pair.falseValue}
	trueNorm := passive.Normalize(trueRes.Body, strips...)
	falseNorm := passive.Normalize(falseRes.Body, strips...)

	simTrue, trueOK, relaxed := d.trueMatchesBaseline(trueNorm, base)
	if !trueOK {
		return passive.Finding{}, false
	}
	simFalse := passive.Similarity(falseNorm, base.body)

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
	sess.observe(trueRes2)
	falseRes2, err := probe.Mutate(ctx, tx, passive.Mutation{Point: p, Value: pair.falseValue})
	if err != nil || falseRes2 == nil {
		return passive.Finding{}, false
	}
	sess.observe(falseRes2)

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
	if _, ok, _ := d.trueMatchesBaseline(trueNorm2, base); !ok {
		return passive.Finding{}, false
	}
	if passive.Similarity(falseNorm2, base.body) > d.opts.FalseSimilarityMax {
		return passive.Finding{}, false
	}

	evidence := fmt.Sprintf(
		"布尔差分：恒真响应与基线相似度 %.3f（%d 字节），恒假响应相似度 %.3f（%d 字节），差值 %.3f；两轮重放结果一致。%s。",
		simTrue, len(trueRes.Body), simFalse, len(falseRes.Body), simTrue-simFalse, describePair(pair),
	)
	if relaxed {
		// 透明化：这条结论借用了「短页噪声行豁免」，必须如实写进证据，复核者要能
		// 看出它没有走最严格的相似度门控。
		evidence += fmt.Sprintf(" 恒真响应与基线相差 %d 行（≤ 短页噪声行阈值 %d 行），长度漂移在允许范围内，按结构一致处理。",
			passive.DiffLines(trueNorm, base.body), d.opts.ShortPageLineTolerance)
	}

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

	return d.buildFinding(tx, p, pair, techniqueBoolean, trueRes, evidence, traces), true
}

// confirmTime 做时间盲注兜底。
//
// 判定要同时成立四件事：对照（延时 0）不慢、延时 payload 显著超出参照点、同档延时
// 能够复现、且把秒数翻倍后延时差同步成比例增长。前三件排除了「目标本来就慢」与
// 偶发抖动；第四件是关键增量——偶发的慢查询不会随着我们给出的秒数线性变化。
func (d *Detector) confirmTime(ctx context.Context, tx *passive.CapturedTransaction, probe passive.Prober, p passive.InjectionPoint, base *baseline, baseTraces []passive.Trace, sess *pointSession, pair boolPair) (passive.Finding, bool) {
	// 对照组：与触发 payload 同形、只是延时为 0。它既是「不延时确实不慢」的证据，
	// 也是所有延时差的参照点——用同形对照比用原始基线更干净。
	control, err := probe.Mutate(ctx, tx, passive.Mutation{Point: p, Value: pair.falseValue})
	if err != nil || control == nil {
		return passive.Finding{}, false
	}
	sess.observe(control)
	if control.Duration >= base.maxDuration+d.opts.TimeControlThreshold {
		return passive.Finding{}, false
	}

	ref := base.maxDuration
	if control.Duration > ref {
		ref = control.Duration
	}

	// 同档触发两次：既证明延时存在，也证明它能复现。
	trigger1, ok := d.timeTrigger(ctx, tx, probe, sess, p, pair.trueValue, ref)
	if !ok {
		return passive.Finding{}, false
	}
	trigger2, ok := d.timeTrigger(ctx, tx, probe, sess, p, pair.trueValue, ref)
	if !ok {
		return passive.Finding{}, false
	}

	d1 := trigger1.Duration - ref
	seconds := pair.seconds
	if seconds <= 0 {
		seconds = d.opts.TimeSleepSeconds
	}

	// 加档验证：秒数翻倍，延时差应随之翻倍。
	//
	// 少数场景（WAF 绕过候选没保留秒数模板）拿不到可加档的 payload，此时退回
	// 「同档复现」这一层判定——它已是旧版口径，足以排除偶发抖动。
	var (
		highVal  = highDegreeValue(pair, p.Original)
		highRes  *passive.CapturedResponse
		highDiff time.Duration
		// thirdDiff 是第三档（3n）相对参照点的延时差；thirdDegree 是这一档的证据留档，
		// 只在三档复核真正执行且通过时才非零。
		thirdDiff   time.Duration
		thirdDegree passive.Trace
	)
	ratio := 0.0
	if highVal != "" {
		highRes, err = probe.Mutate(ctx, tx, passive.Mutation{Point: p, Value: highVal})
		if err != nil || highRes == nil {
			return passive.Finding{}, false
		}
		sess.observe(highRes)
		highDiff = highRes.Duration - ref

		saturated := absDuration(highDiff-d1) <= timeSaturationTolerance
		if !saturated {
			// 加档延时至少要有可见的增长，再看倍率是否落在合理区间。
			if highDiff < d1+d.opts.TimeTriggerThreshold/2 {
				return passive.Finding{}, false
			}
			ratio = float64(highDiff) / float64(d1)
			if ratio < d.opts.TimeRatioMin || ratio > d.opts.TimeRatioMax {
				return passive.Finding{}, false
			}
		}
	}

	// 三档复核：秒数再上一档，延时差必须继续增长。
	//
	// 只增不减：它不接受任何新结论，只在「两档成比例」之上再加一道反证。某些限流 /
	// 排队会把两档延时都顶到同一个上限，恰好落进倍率区间，看起来像成比例；三档若
	// 不再增长就会暴露它。两档已被判定饱和时跳过，避免与饱和口径自相矛盾。
	if highRes != nil && absDuration(highDiff-d1) > timeSaturationTolerance {
		if thirdVal := degreeValue(pair, p.Original, timeThirdDegreeFactor); thirdVal != "" {
			thirdRes, err := probe.Mutate(ctx, tx, passive.Mutation{Point: p, Value: thirdVal})
			if err != nil || thirdRes == nil {
				return passive.Finding{}, false
			}
			sess.observe(thirdRes)
			thirdDiff = thirdRes.Duration - ref
			if thirdDiff <= highDiff {
				return passive.Finding{}, false
			}
			thirdDegree = traceOf(tx, p, true, thirdVal, "延时触发（三档）",
				fmt.Sprintf("秒数升至 %d 秒，耗时 %s，延时差 %s（基准档 %s），延时仍随秒数增长",
					seconds*timeThirdDegreeFactor, thirdRes.Duration.Round(time.Millisecond),
					thirdDiff.Round(time.Millisecond), d1.Round(time.Millisecond)), thirdRes)
		}
	}

	evidence := d.timeEvidence(pair, seconds, control, base, trigger1, trigger2, highRes, d1, highDiff, ratio, thirdDiff)

	// 证据链：基线 + 对照组 + 延时触发两次（+ 加档一次 + 三档一次）。缺了对照就无法
	// 排除「目标本来就慢」，缺了加档就说不清延时是否真由秒数驱动。
	traces := append([]passive.Trace{}, baseTraces...)
	traces = append(traces,
		traceOf(tx, p, true, pair.falseValue, "对照组",
			fmt.Sprintf("延时为 0，耗时 %s，未触发（允许增量 %s）",
				control.Duration.Round(time.Millisecond), d.opts.TimeControlThreshold), control),
		traceOf(tx, p, true, pair.trueValue, "延时触发 #1",
			fmt.Sprintf("耗时 %s，超出参照点 %s（阈值 %s）",
				trigger1.Duration.Round(time.Millisecond), ref.Round(time.Millisecond),
				d.opts.TimeTriggerThreshold), trigger1),
		traceOf(tx, p, true, pair.trueValue, "延时触发 #2",
			fmt.Sprintf("复现验证，耗时 %s，与第 1 次一致",
				trigger2.Duration.Round(time.Millisecond)), trigger2),
	)
	if highRes != nil {
		traces = append(traces, traceOf(tx, p, true, highVal, "延时触发（加档）",
			fmt.Sprintf("秒数翻倍至 %d 秒，耗时 %s，延时差 %s（基准档 %s）",
				seconds*timeDegreeFactor, highRes.Duration.Round(time.Millisecond),
				highDiff.Round(time.Millisecond), d1.Round(time.Millisecond)), highRes))
	}
	if thirdDegree.Label != "" {
		traces = append(traces, thirdDegree)
	}

	f := d.buildFinding(tx, p, pair, techniqueTime, trigger1, evidence, traces)
	// 方言指纹只影响候选顺序，不影响结论；如实写进证据与结构字段，便于复核者
	// 判断这次命中有没有「先验偏好」的成分。
	if sess.dialectHint != "" {
		f.Evidence += fmt.Sprintf(" 时间盲注候选顺序参考方言指纹：%s（依据：%s）。", sess.dialectHint, sess.dialectHintReason)
		f.Extra["dbms_hint"] = sess.dialectHint
		f.Extra["dbms_hint_reason"] = sess.dialectHintReason
	}
	return f, true
}

// timeEvidence 组织时间盲注的证据说明。
func (d *Detector) timeEvidence(pair boolPair, seconds int, control *passive.CapturedResponse, base *baseline, trigger1, trigger2 *passive.CapturedResponse, highRes *passive.CapturedResponse, d1, highDiff time.Duration, ratio float64, thirdDiff time.Duration) string {
	head := fmt.Sprintf(
		"时间盲注：对照组（延时 0）耗时 %s，基线耗时 %s；同档 SLEEP(%d) 触发耗时 %s / %s，延时差 %s。",
		control.Duration.Round(time.Millisecond),
		base.maxDuration.Round(time.Millisecond),
		seconds,
		trigger1.Duration.Round(time.Millisecond),
		trigger2.Duration.Round(time.Millisecond),
		d1.Round(time.Millisecond),
	)
	if highRes == nil {
		return head + fmt.Sprintf("（该候选无法加档复验，按同档复现判定。）%s。", describePair(pair))
	}
	if absDuration(highDiff-d1) <= timeSaturationTolerance {
		return head + fmt.Sprintf(
			"加档 SLEEP(%d) 耗时 %s、延时差 %s，与基准档持平，判断为服务端已达到固定耗时上限（如查询超时）。%s。",
			seconds*timeDegreeFactor, highRes.Duration.Round(time.Millisecond),
			highDiff.Round(time.Millisecond), describePair(pair),
		)
	}
	tail := fmt.Sprintf(
		"加档 SLEEP(%d) 耗时 %s、延时差 %s，倍率 %.2f——延时随秒数成比例增长。",
		seconds*timeDegreeFactor, highRes.Duration.Round(time.Millisecond),
		highDiff.Round(time.Millisecond), ratio,
	)
	if thirdDiff > 0 {
		tail += fmt.Sprintf(" 三档 SLEEP(%d) 延时差 %s，仍随秒数继续增长，线性关系成立。",
			seconds*timeThirdDegreeFactor, thirdDiff.Round(time.Millisecond))
	}
	return head + tail + fmt.Sprintf("%s。", describePair(pair))
}

// timeTrigger 发一次延时 payload，要求耗时显著超过参照点，否则判为未触发。
func (d *Detector) timeTrigger(ctx context.Context, tx *passive.CapturedTransaction, probe passive.Prober, sess *pointSession, p passive.InjectionPoint, value string, ref time.Duration) (*passive.CapturedResponse, bool) {
	res, err := probe.Mutate(ctx, tx, passive.Mutation{Point: p, Value: value})
	if err != nil || res == nil {
		return nil, false
	}
	sess.observe(res)
	if res.Duration < ref+d.opts.TimeTriggerThreshold {
		return nil, false
	}
	return res, true
}

// highDegreeValue 按「加档」秒数重新生成时间盲注的触发 payload。
func highDegreeValue(pair boolPair, orig string) string {
	return degreeValue(pair, orig, timeDegreeFactor)
}

// degreeValue 按给定秒数倍率重新生成时间盲注的触发 payload。
// 返回空串表示该候选没有可用的秒数模板（如未保留模板的 WAF 绕过候选）。
func degreeValue(pair boolPair, orig string, factor int) string {
	if pair.timeTrueTmpl == "" {
		return ""
	}
	seconds := pair.seconds * factor
	if seconds <= 0 {
		seconds = factor
	}
	return fmt.Sprintf(pair.timeTrueTmpl, orig, seconds)
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// describePair 把候选的技术特征整理成可读说明，供人工复核。
func describePair(pair boolPair) string {
	parts := []string{"构造方式 " + pair.label}
	if pair.evasion != "" {
		parts = append(parts, "WAF 绕过 "+pair.evasion)
	}
	return strings.Join(parts, "，")
}

func (d *Detector) buildFinding(tx *passive.CapturedTransaction, p passive.InjectionPoint, pair boolPair, technique string, res *passive.CapturedResponse, evidence string, traces []passive.Trace) passive.Finding {
	reqClone := tx.Request.Clone()
	_ = passive.ApplyMutation(reqClone, passive.Mutation{Point: p, Value: pair.trueValue})

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
		Payload:    pair.trueValue,
		LatencyMs:  latencyMs,
		Evidence:   evidence,
		Request:    reqRaw,
		Response:   resRaw,
		Traces:     traces,
		Extra: map[string]any{
			"technique":     technique,
			"dialect":       pair.dialect,
			"evasion":       pair.evasion,
			"construct":     pair.label,
			"false_payload": pair.falseValue,
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
