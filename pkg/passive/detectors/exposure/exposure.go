// Package exposure 实现被动「敏感信息暴露」检测（A 档）。
//
// 与纯零流量检测器不同，本检测器会发请求——但它是**主机级一次性探针**，不是逐请求
// 检测：对每个 origin 只在首次遇到时探一轮，探完即把该 origin 标记为已探，之后
// 任何流量都不再触发。这条设计把「主动扫描」的流量代价严格钉死在「每 origin 一轮」，
// 而不会随流量规模线性膨胀。
//
// 探针路径由「根 + 流量推导」得出：以触发事务的路径为起点，逐级上推父目录，最多
// 落到 2 层，再加上根目录。使用者在站点上走过 /app/user/profile，探针就会覆盖
// /、/app/、/app/user/ 三处，而不是盲目爆破字典。每个 base path 下只查一份固定的
// 核心文件清单（.git/HEAD、.env、backup.zip 等）。
//
// 三条硬约束：
//
//  1. 内容签名强校验。敏感暴露的判定绝不能只看状态码——WAF 的软拦截同样返回 200，
//     只是正文换成了一张拦截页。每个文件类型都带签名（.git/HEAD 必须以 ref: 开头、
//     .env 必须是 KEY=VALUE 行、zip 必须有 PK 魔数……），并且默认排除 HTML 正文，
//     只有在签名确实成立时才认定为命中。
//  2. 绕过仅在拦截信号下触发。只有先看到 403/406/429/501/503 这类明确的拦截状态
//     （或响应头里出现已知防护设备特征），才会为这条路径投入绕过变体。正常 404 说明
//     文件本就不存在，投入绕过纯属浪费流量。
//  3. 严格预算。核心探测 ≤ MaxProbes，绕过探测独立计 ≤ MaxBypass，双预算各自封顶，
//     保证单 origin 的探针流量有明确上界。
//
// 归属项目与范围裁剪由代理层完成：范围外（HostDeny / HostAllow 之外）的流量根本不会
// 进入调度层，因此本检测器天然不会去探被排除的主机。
package exposure

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/zan8in/afrog/v3/pkg/guard"
	"github.com/zan8in/afrog/v3/pkg/passive"
)

const (
	// DetectorName 是检测器标识。
	DetectorName = "exposure"
	// VulnType 是漏洞类型标识。
	VulnType = "exposure"

	// bypassToken 是路径穿越绕过里使用的固定占位段。
	//
	// 用固定值而非随机值，是为了让变体形状可被单测断言；代价是可能被特征库记住，
	// 但这只是众多变体里的一条。
	bypassToken = "_afrog-bypass"
)

// fileSpec 描述一份待探测的敏感文件及其判定签名。
type fileSpec struct {
	// Name 是展示名，同时用作 Location（如 ".git/HEAD"）。
	Name string
	// Rel 是相对 base path 的路径（如 ".git/HEAD"）。
	Rel string
	// Severity 是命中后的严重级别。
	Severity string
	// AllowBinary 为 true 时不禁用二进制正文（zip、.DS_Store 这类本身就是二进制）。
	AllowBinary bool
	// AllowHTML 为 true 时不禁用 HTML 正文（swagger-ui.html 本身就是 HTML）。
	AllowHTML bool
	// Match 在状态码 200 的前提下做内容签名判定，返回 (是否命中, 命中的签名说明)。
	Match func(res *passive.CapturedResponse) (bool, string)
}

// Options 是暴露类检测器的判定参数。
type Options struct {
	// MaxBasePaths 是单个 origin 最多探测的 base path 数（含根）。
	MaxBasePaths int
	// MaxDepth 是从触发路径上推的父目录层数上限。
	MaxDepth int
	// MaxProbes 是核心探测的请求预算（每 origin）。
	MaxProbes int
	// MaxBypass 是绕过探测的请求预算（每 origin）。
	MaxBypass int
	// MaxFindings 是单个 origin 最多产出的发现数。
	MaxFindings int
}

// DefaultOptions 返回默认参数。
func DefaultOptions() Options {
	return Options{
		MaxBasePaths: 3,
		MaxDepth:     2,
		MaxProbes:    60,
		MaxBypass:    30,
		MaxFindings:  20,
	}
}

// Detector 是敏感信息暴露被动检测器。
type Detector struct {
	opts Options

	mu sync.Mutex
	// claimed 记录「已认领探测权」的 origin：一次性探针的并发闸门。
	//
	// 认领发生在 Interest 而非 Detect：多条指向同一 origin 的事务可能在极短时间内
	// 同时通过门控，若等到 Detect 才去重，这几条会一起进入检测池各探一轮。在门控
	// 阶段用 LoadOrStore 语义认领，天然只放一条过去。
	claimed map[string]struct{}
	// policy 缓存每个 origin 的高危动作裁决：空串表示放行，非空为拒绝原因。
	//
	// 只裁决一次：闸门配置在进程启动时确定，逐请求重复裁决会把审计刷满
	// （一个页面几十条请求就是几十条同样的记录），也让门控池承担不必要的加锁。
	policy map[string]string
}

// New 创建检测器。
func New(opts Options) *Detector {
	def := DefaultOptions()
	if opts.MaxBasePaths <= 0 {
		opts.MaxBasePaths = def.MaxBasePaths
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = def.MaxDepth
	}
	if opts.MaxProbes <= 0 {
		opts.MaxProbes = def.MaxProbes
	}
	if opts.MaxBypass <= 0 {
		opts.MaxBypass = def.MaxBypass
	}
	if opts.MaxFindings <= 0 {
		opts.MaxFindings = def.MaxFindings
	}
	return &Detector{
		opts:    opts,
		claimed: make(map[string]struct{}),
		policy:  make(map[string]string),
	}
}

// Name 实现 passive.Detector。
func (d *Detector) Name() string { return DetectorName }

// Interest 是零流量门控，同时承担「每 origin 一次性」的认领。
func (d *Detector) Interest(tx *passive.CapturedTransaction) bool {
	if tx == nil || tx.Request == nil || tx.Request.URL == nil {
		return false
	}
	u := tx.Request.URL
	if u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	// 静态资源路径不做探针：它们通常由 CDN 直出，走到这里说明用户正停在某个静态
	// 文件上，从中推导 base path 没有意义。
	if isStaticAsset(u.Path) {
		return false
	}
	// 高危动作闸门：敏感路径探测会主动发请求，必须受 allow/deny/ask 约束。
	// 被拒的 origin 不认领，之后即使补上白名单（重启后）也能重新探测。
	if reason, decided := d.cachedPolicy(u.Host); decided {
		if reason != "" {
			return false
		}
	} else {
		decision := guard.Check(guard.ActionExposureProbe, u.Host)
		d.rememberPolicy(u.Host, policyDenialReason(decision))
		if !decision.Allowed {
			return false
		}
	}
	return d.claim(u.Host)
}

// InterestReason 实现 passive.InterestReasoner。
func (d *Detector) InterestReason(tx *passive.CapturedTransaction) string {
	if tx == nil || tx.Request == nil || tx.Request.URL == nil {
		return "缺少可用的请求 URL"
	}
	u := tx.Request.URL
	if u.Host == "" {
		return "请求 URL 缺少 Host"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "请求 URL 的协议不是 http/https"
	}
	if isStaticAsset(u.Path) {
		return "请求路径是静态资源，不推导敏感路径"
	}
	// 被闸门拒绝时如实给出原因，而不是笼统的「已完成探测」。
	if reason, decided := d.cachedPolicy(u.Host); decided && reason != "" {
		return reason
	}
	return "该主机已完成一次性敏感路径探测"
}

// Detect 实现 passive.Detector：对本次认领到的 origin 执行一轮探针。
func (d *Detector) Detect(ctx context.Context, tx *passive.CapturedTransaction, probe passive.Prober) ([]passive.Finding, error) {
	if tx == nil || tx.Request == nil || tx.Request.URL == nil {
		return nil, nil
	}
	bases := buildBasePaths(tx.Request.URL, d.opts.MaxDepth, d.opts.MaxBasePaths)
	if len(bases) == 0 {
		return nil, nil
	}

	findings := make([]passive.Finding, 0, 4)
	probes, bypassed := 0, 0

	for _, base := range bases {
		if probes >= d.opts.MaxProbes || len(findings) >= d.opts.MaxFindings {
			break
		}
		for _, spec := range coreFiles {
			if probes >= d.opts.MaxProbes || len(findings) >= d.opts.MaxFindings {
				break
			}

			full := base + spec.Rel
			res := d.fetch(ctx, probe, tx, full)
			probes++
			if res == nil {
				continue
			}

			if intercepted(res) {
				// 命中拦截：为该路径投入绕过变体，直到某条绕过既能穿过拦截、又能
				// 通过内容签名。
				f, used := d.tryBypass(ctx, probe, tx, base, spec, bypassed)
				bypassed += used
				probes += used
				if f != nil {
					findings = append(findings, *f)
				}
				continue
			}

			if ok, snippet := runSpec(spec, res); ok {
				findings = append(findings, buildFinding(tx, full, base, spec, res, snippet, false))
			}
		}
	}

	return findings, nil
}

// tryBypass 依次尝试路径绕过变体，返回首个命中与消耗的请求数。
func (d *Detector) tryBypass(ctx context.Context, probe passive.Prober, tx *passive.CapturedTransaction, base string, spec fileSpec, used int) (*passive.Finding, int) {
	spent := 0
	for _, variant := range bypassVariants(base, spec.Rel) {
		if used+spent >= d.opts.MaxBypass {
			break
		}
		res := d.fetch(ctx, probe, tx, variant)
		spent++
		if res == nil || intercepted(res) {
			continue
		}
		if ok, snippet := runSpec(spec, res); ok {
			f := buildFinding(tx, variant, base, spec, res, snippet, true)
			return &f, spent
		}
	}
	return nil, spent
}

// fetch 用触发事务的头部（Cookie / Authorization 等原样保留）向指定路径发一次 GET。
//
// 通过构造合成事务走 Prober.Replay，而不是自建 http.Client：这样单目标并发与全局
// 速率治理对探针同样生效，探针不会成为绕过限速的旁路。
func (d *Detector) fetch(ctx context.Context, probe passive.Prober, tx *passive.CapturedTransaction, rawPath string) *passive.CapturedResponse {
	req := buildProbeRequest(tx.Request, rawPath)
	if req == nil {
		return nil
	}
	res, err := probe.Replay(ctx, &passive.CapturedTransaction{
		ID:       tx.ID,
		Request:  req,
		Upstream: tx.Upstream,
	})
	if err != nil {
		return nil
	}
	return res
}

// cachedPolicy 读取已缓存的闸门裁决；decided=false 表示这个 origin 还没裁决过。
func (d *Detector) cachedPolicy(host string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	reason, ok := d.policy[host]
	return reason, ok
}

func (d *Detector) rememberPolicy(host, reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.policy[host] = reason
}

// policyDenialReason 把裁决收敛成缓存约定：放行是空串，拒绝是非空原因。
func policyDenialReason(decision guard.Decision) string {
	if decision.Allowed {
		return ""
	}
	if decision.Reason != "" {
		return decision.Reason
	}
	return "敏感路径探测被安全策略拒绝"
}

// claim 认领一个 origin 的探测权，返回是否为首次认领。
func (d *Detector) claim(host string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.claimed[host]; ok {
		return false
	}
	d.claimed[host] = struct{}{}
	return true
}

// buildProbeRequest 由触发请求派生一个指向 rawPath 的 GET 请求。
//
// 保留原请求头（鉴权、Cookie、UA）是好处的：很多敏感文件只对已登录会话开放，
// 带上会话才能检出「登录后仍可匿名访问的 .git」这类真实问题。但必须剔除与正文
// 相关的头，否则会把 POST 的 Content-Type 带进 GET 造成语义错乱。
func buildProbeRequest(src *passive.CapturedRequest, rawPath string) *passive.CapturedRequest {
	if src == nil || src.URL == nil {
		return nil
	}
	origin := src.URL.Scheme + "://" + src.URL.Host
	target, err := url.Parse(origin + rawPath)
	if err != nil {
		return nil
	}
	h := src.Headers.Clone()
	if h != nil {
		h.Del("Content-Length")
		h.Del("Content-Type")
		h.Del("Transfer-Encoding")
		h.Del("Content-Encoding")
	}
	return &passive.CapturedRequest{Method: http.MethodGet, URL: target, Headers: h}
}

// buildBasePaths 由触发路径推导出待探测的 base path 列表（根 + 逐级父目录）。
//
// 末段若不像目录（无尾斜杠）则丢弃——它多半是页面/资源名（index.php、profile），
// 不是目录。上推层数受 maxDepth 限制，最终再按 maxBase 截断。
func buildBasePaths(u *url.URL, maxDepth, maxBase int) []string {
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	segs := splitSegments(p)
	if len(segs) > 0 && !strings.HasSuffix(p, "/") {
		segs = segs[:len(segs)-1]
	}

	out := []string{"/"}
	cur := "/"
	for i, seg := range segs {
		if i >= maxDepth {
			break
		}
		cur += seg + "/"
		out = append(out, cur)
	}
	if maxBase > 0 && len(out) > maxBase {
		out = out[:maxBase]
	}
	return out
}

func splitSegments(p string) []string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	out := make([]string, 0, len(parts))
	for _, s := range parts {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// bypassVariants 生成一条路径的绕过变体（Tier 1 + Tier 2，共 9 类）。
//
// Tier 1 是「路径形态」层面的变形（多余斜杠、尾随点、编码空白），Tier 2 是
// 「编码/参数」层面的变形（编码点、编码斜杠、附加查询与片段、路径穿越）。它们
// 针对的是「反向代理按原始串匹配拦截、但后端按解码后语义路由」这类常见错配。
func bypassVariants(base, rel string) []string {
	encDot := encodeLeadingDot(rel)
	encSlash := strings.Replace(rel, "/", "%2f", 1)

	raw := []string{
		base + "./" + rel,                 // /app/./.git/HEAD
		base + "/" + rel,                  // /app//.git/HEAD
		base + rel + "/.",                 // /app/.git/HEAD/.
		base + rel + "%20",                // /app/.git/HEAD%20
		base + encDot,                     // /app/%2egit/HEAD
		base + rel + "%23",                // /app/.git/HEAD%23
		base + rel + "?x=1",               // /app/.git/HEAD?x=1
		base + encSlash,                   // /app/.git%2fHEAD
		base + bypassToken + "/../" + rel, // /app/_afrog-bypass/../.git/HEAD
	}

	// 原路径本身不算变体：它在进入绕过分支前已经请求过一次了。
	normal := base + rel
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, v := range raw {
		if v == normal || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// encodeLeadingDot 把相对路径开头的点编码成 %2e（如 .git → %2egit）。
func encodeLeadingDot(rel string) string {
	if strings.HasPrefix(rel, ".") {
		return "%2e" + rel[1:]
	}
	return rel
}

// intercepted 判定一次探测是否被防护设备拦下。
//
// 只看两类可靠信号：明确的拦截状态码，以及响应头上的已知设备特征。刻意不看正文
// 关键词——「Access Denied」之类文案在正常页面里也可能出现，用它触发绕过会造成
// 大量无谓流量。
func intercepted(res *passive.CapturedResponse) bool {
	if res == nil {
		return false
	}
	switch res.Status {
	case http.StatusForbidden, http.StatusNotAcceptable, http.StatusTooManyRequests,
		http.StatusNotImplemented, http.StatusServiceUnavailable:
		return true
	}
	srv := strings.ToLower(res.Headers.Get("Server"))
	for _, kw := range []string{"cloudflare", "yunsuo", "safedog", "bigip", "tengine-waf", "modsecurity"} {
		if strings.Contains(srv, kw) {
			return true
		}
	}
	if res.Headers.Get("X-Sucuri-ID") != "" || res.Headers.Get("X-WAF-Status") != "" {
		return true
	}
	return false
}

// runSpec 执行内容签名判定：先过通用门（200 + 正文类型），再交给具体签名。
func runSpec(spec fileSpec, res *passive.CapturedResponse) (bool, string) {
	if res == nil || res.Status != http.StatusOK {
		return false, ""
	}
	ct := res.Headers.Get("Content-Type")
	if !spec.AllowBinary && isBinaryContent(ct) {
		return false, ""
	}
	if !spec.AllowHTML && looksHTML(res.Body) {
		return false, ""
	}
	return spec.Match(res)
}

// buildFinding 组装一条暴露类发现。Target 取精确 URL——暴露类要能直接定位到
// 「哪条路径上存在该文件」，这是可复核性的基础。
func buildFinding(tx *passive.CapturedTransaction, rawPath, base string, spec fileSpec, res *passive.CapturedResponse, snippet string, bypass bool) passive.Finding {
	req := buildProbeRequest(tx.Request, rawPath)
	reqRaw, resRaw := passive.RawHTTPDump(req, res)

	var latency int64
	if res != nil {
		latency = res.Duration.Milliseconds()
	}

	target := tx.Request.URL.Scheme + "://" + tx.Request.URL.Host + rawPath
	evidence := "路径 " + rawPath + " 返回状态 200，且内容签名「" + snippet + "」成立，判定为敏感文件暴露。"
	if bypass {
		evidence = "直接请求被防护设备拦截，改用绕过路径 " + rawPath + " 后返回状态 200，且内容签名「" + snippet + "」成立，判定为敏感文件暴露（存在防护绕过）。"
	}

	return passive.Finding{
		Detector:   DetectorName,
		VulnType:   VulnType,
		Severity:   spec.Severity,
		Confidence: passive.ConfidenceCertain,
		Title:      "敏感文件暴露：" + spec.Name,
		Target:     target,
		Location:   spec.Name,
		LatencyMs:  latency,
		Evidence:   evidence,
		Request:    reqRaw,
		Response:   resRaw,
		Traces: []passive.Trace{{
			Label:     "探针请求",
			Status:    res.Status,
			LatencyMs: latency,
			Note:      evidence,
			Request:   string(reqRaw),
			Response:  capTraceResponse(string(resRaw)),
		}},
		Extra: map[string]any{
			"signature": snippet,
			"base_path": base,
			"path":      rawPath,
			"bypass":    bypass,
		},
	}
}

// -----------------------------------
// 核心文件清单
// -----------------------------------

// coreFiles 是每个 base path 下固定的探测清单。
//
// 清单刻意保持精简（10 条）：探针是「流量驱动」的补充，不是字典爆破；每增加一条
// 就让每个 origin 的流量代价上抬一档。这里只留检出价值最高、签名最确定的项。
var coreFiles = []fileSpec{
	{Name: ".git/HEAD", Rel: ".git/HEAD", Severity: "high", Match: matchGitHead},
	{Name: ".git/config", Rel: ".git/config", Severity: "high", Match: matchGitConfig},
	{Name: ".svn/entries", Rel: ".svn/entries", Severity: "high", Match: matchSvnEntries},
	{Name: ".env", Rel: ".env", Severity: "high", Match: matchDotEnv},
	{Name: "web.config", Rel: "web.config", Severity: "medium", Match: matchWebConfig},
	{Name: ".DS_Store", Rel: ".DS_Store", Severity: "low", AllowBinary: true, Match: matchDSStore},
	{Name: "actuator/env", Rel: "actuator/env", Severity: "medium", Match: matchActuatorEnv},
	{Name: "swagger-ui.html", Rel: "swagger-ui.html", Severity: "low", AllowHTML: true, Match: matchSwagger},
	{Name: "backup.zip", Rel: "backup.zip", Severity: "high", AllowBinary: true, Match: matchZip},
	{Name: "db.sql", Rel: "db.sql", Severity: "high", Match: matchSQLDump},
}

// matchGitHead 匹配 .git/HEAD：内容要么是 "ref: refs/..."，要么是一串 40 位 SHA。
func matchGitHead(res *passive.CapturedResponse) (bool, string) {
	s := strings.TrimSpace(string(res.Body))
	if strings.HasPrefix(s, "ref: ") {
		return true, "ref: " + firstLine(s)
	}
	// 分离的 HEAD：40 位十六进制 SHA，可能带换行。
	line := firstLine(s)
	if len(line) == 40 && isHex(line) {
		return true, "分离 HEAD 提交号 " + line
	}
	return false, ""
}

// matchGitConfig 匹配 .git/config：Git 配置节头与版本号同时存在。
func matchGitConfig(res *passive.CapturedResponse) (bool, string) {
	body := string(res.Body)
	if strings.Contains(body, "[core]") && strings.Contains(strings.ToLower(body), "repositoryformatversion") {
		return true, "[core] repositoryformatversion"
	}
	return false, ""
}

// matchSvnEntries 匹配 .svn/entries，兼容新旧两种格式。
func matchSvnEntries(res *passive.CapturedResponse) (bool, string) {
	s := strings.TrimSpace(string(res.Body))
	if strings.HasPrefix(s, "<?xml") && strings.Contains(s, "<entry") {
		return true, "<entry> XML 条目"
	}
	// 旧格式：首行是版本号，次行是目录名。
	lines := strings.Split(s, "\n")
	if len(lines) >= 2 && isDigits(strings.TrimSpace(lines[0])) && strings.TrimSpace(lines[0]) != "" {
		return true, "SVN entries 版本号 " + strings.TrimSpace(lines[0])
	}
	return false, ""
}

// matchDotEnv 匹配 .env：至少一行 KEY=VALUE，且不含明显的脚本/HTML 特征。
func matchDotEnv(res *passive.CapturedResponse) (bool, string) {
	body := string(res.Body)
	lower := strings.ToLower(body)
	for _, bad := range []string{"<script", "<!doctype", "<?php", "function(", "=>"} {
		if strings.Contains(lower, bad) {
			return false, ""
		}
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq <= 0 {
			continue
		}
		if isEnvKey(line[:eq]) {
			return true, "环境变量行 " + line
		}
	}
	return false, ""
}

// matchWebConfig 匹配 .NET 的 web.config。
func matchWebConfig(res *passive.CapturedResponse) (bool, string) {
	body := strings.ToLower(string(res.Body))
	if strings.Contains(body, "<configuration") {
		return true, "<configuration>"
	}
	return false, ""
}

// matchDSStore 匹配 macOS 的 .DS_Store，以固定魔数开头。
func matchDSStore(res *passive.CapturedResponse) (bool, string) {
	if bytes.HasPrefix(res.Body, []byte{0x00, 0x00, 0x00, 0x01, 'B', 'u', 'd', '1'}) {
		return true, "Bud1 魔数"
	}
	return false, ""
}

// matchActuatorEnv 匹配 Spring Boot Actuator 的 /env 端点。
func matchActuatorEnv(res *passive.CapturedResponse) (bool, string) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(res.Body, &payload); err != nil {
		return false, ""
	}
	for _, key := range []string{"propertySources", "activeProfiles", "systemProperties"} {
		if _, ok := payload[key]; ok {
			return true, "Actuator 字段 " + key
		}
	}
	return false, ""
}

// matchSwagger 匹配 Swagger / OpenAPI UI。
func matchSwagger(res *passive.CapturedResponse) (bool, string) {
	body := strings.ToLower(string(res.Body))
	for _, kw := range []string{"swagger-ui", "swagger ui", `"swagger"`, "openapi"} {
		if strings.Contains(body, kw) {
			return true, kw
		}
	}
	return false, ""
}

// matchZip 匹配 zip 归档（backup.zip），以 PK 魔数开头。
func matchZip(res *passive.CapturedResponse) (bool, string) {
	if bytes.HasPrefix(res.Body, []byte("PK\x03\x04")) {
		return true, "PK 魔数"
	}
	return false, ""
}

// matchSQLDump 匹配 SQL 导出文件。
func matchSQLDump(res *passive.CapturedResponse) (bool, string) {
	body := strings.ToUpper(string(res.Body))
	if strings.Contains(body, "CREATE TABLE") {
		return true, "CREATE TABLE"
	}
	if strings.Contains(body, "INSERT INTO") {
		return true, "INSERT INTO"
	}
	return false, ""
}

// -----------------------------------
// 小工具
// -----------------------------------

const maxTraceResponseBytes = 512 << 10

func capTraceResponse(s string) string {
	if len(s) <= maxTraceResponseBytes {
		return s
	}
	return s[:maxTraceResponseBytes] + "\r\n\r\n[afrog] 响应超出 512 KB 已截断"
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return s != ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isEnvKey 判定 key 是否符合环境变量命名（字母或下划线开头，仅含字母数字下划线）。
func isEnvKey(key string) bool {
	if key == "" {
		return false
	}
	for i, r := range key {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '_':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// looksHTML 粗判正文是否是 HTML 文档。
//
// 它是「WAF 软拦截」与「SPA 回退到首页」两类误报的通用闸门：这两者都会以 200 +
// HTML 返回，任何基于「文件存在」的判定都必须先把它们挡掉。
func looksHTML(body []byte) bool {
	head := strings.ToLower(string(body))
	if len(head) > 1024 {
		head = head[:1024]
	}
	head = strings.TrimSpace(head)
	for _, kw := range []string{"<!doctype html", "<html", "<head", "<body", "<!--"} {
		if strings.HasPrefix(head, kw) || strings.Contains(head, kw) {
			return true
		}
	}
	return false
}

// isBinaryContent 判定 Content-Type 是否属于二进制类别。
func isBinaryContent(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if ct == "" {
		return false
	}
	for _, p := range []string{
		"image/", "audio/", "video/", "font/",
		"application/octet-stream", "application/zip", "application/pdf",
	} {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	return false
}

// staticAssetExts 是判定为静态资源的后缀。
var staticAssetExts = []string{
	".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
	".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".mp3", ".avif",
}

func isStaticAsset(path string) bool {
	p := strings.ToLower(path)
	for _, ext := range staticAssetExts {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}
