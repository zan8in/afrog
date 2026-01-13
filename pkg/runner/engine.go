package runner

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"strconv"

	"github.com/zan8in/afrog/v3/pkg/config"
	db2 "github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/fingerprint"
	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/portscan"
	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/report"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/targets"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
	"github.com/zan8in/oobadapter/pkg/oobadapter"
)

var CheckerPool = sync.Pool{
	New: func() any {
		return &Checker{
			Options: &config.Options{},
			// OriginalRequest: &http.Request{},
			VariableMap: make(map[string]any),
			Result:      &result.Result{},
			CustomLib:   NewCustomLib(),
		}
	},
}

var titleExtractRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

type openPortsCollector struct {
	mu   sync.Mutex
	open map[string][]int
}

func newOpenPortsCollector() *openPortsCollector {
	return &openPortsCollector{
		open: make(map[string][]int),
	}
}

func extractTitle(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	m := titleExtractRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	t := strings.TrimSpace(string(m[1]))
	if t == "" {
		return ""
	}
	t = strings.Join(strings.Fields(t), " ")
	return t
}

func (runner *Runner) webProbe(ctx context.Context, idx *targets.TargetIndex) []string {
	if runner == nil || idx == nil || runner.options == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return nil
	}

	var printSeq uint64

	seen := make(map[string]struct{})
	candidates := make([]string, 0, len(idx.URLs)+len(idx.HostPorts)+len(idx.Hosts))
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		candidates = append(candidates, s)
	}
	for _, u := range idx.URLs {
		add(u)
	}
	for _, hp := range idx.HostPorts {
		add(hp)
	}
	for _, h := range idx.Hosts {
		add(h)
	}
	if len(candidates) == 0 {
		return nil
	}

	rate := runner.options.RateLimit
	if rate <= 0 {
		rate = 1
	}
	con := runner.options.Concurrency
	if con <= 0 {
		con = 1
	}

	ticker := time.NewTicker(time.Second / time.Duration(rate))
	defer ticker.Stop()

	type task struct {
		raw string
	}
	tasks := make(chan task, con*4)
	var wg sync.WaitGroup

	var mu sync.Mutex
	webURLs := make([]string, 0)
	webURLByKey := make(map[string]string)
	webMetaByKey := make(map[string]WebMeta)

	record := func(urlStr string, meta WebMeta) {
		key := fingerprint.KeyFromTarget(urlStr)
		if key == "" {
			return
		}
		if runner.options != nil {
			runner.options.Targets.SetNum(urlStr, ActiveTarget)
		}
		mu.Lock()
		if _, ok := webURLByKey[key]; ok {
			mu.Unlock()
			return
		}
		webURLByKey[key] = urlStr
		webMetaByKey[key] = meta
		webURLs = append(webURLs, urlStr)
		mu.Unlock()
		if runner.options != nil && !runner.options.SDKMode && !runner.options.Silent {
			extinfo := ""
			if t := strings.TrimSpace(meta.Title); t != "" {
				extinfo += "[" + log.LogColor.Title(t) + "]"
			}
			serverOrPowered := ""
			if s := strings.TrimSpace(meta.Server); s != "" {
				serverOrPowered = s
			}
			if p := strings.TrimSpace(meta.PoweredBy); p != "" {
				if serverOrPowered == "" {
					serverOrPowered = p
				} else {
					serverOrPowered += "," + p
				}
			}
			if serverOrPowered != "" {
				extinfo += "[" + log.LogColor.DarkGray(serverOrPowered) + "]"
			}

			number := utils.GetNumberText(int(atomic.AddUint64(&printSeq, 1)))
			seq := log.LogColor.Time(number)
			if extinfo == "" {
				fmt.Printf("\r%v %s\r\n", seq, urlStr)
			} else {
				fmt.Printf("\r%v %s %s\r\n", seq, urlStr, extinfo)
			}
		}
	}

	fetchMeta := func(urlStr string) WebMeta {
		vm := make(map[string]any, 4)
		if ctx != nil {
			vm[retryhttpclient.ContextVarKey] = ctx
		}
		rule := poc.Rule{}
		rule.Request.Method = "GET"
		rule.Request.Path = "/"
		rule.Request.FollowRedirects = true
		_ = retryhttpclient.Request(urlStr, runner.options.Header, rule, vm)

		meta := WebMeta{URL: urlStr}
		resp, _ := vm["response"].(*proto.Response)
		if resp == nil {
			return meta
		}
		if len(resp.Headers) > 0 {
			meta.Server = strings.TrimSpace(resp.Headers["server"])
			meta.PoweredBy = strings.TrimSpace(resp.Headers["x-powered-by"])
		}
		meta.Title = extractTitle(resp.Body)
		return meta
	}

	for i := 0; i < con; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-runner.ctx.Done():
					return
				case <-ctx.Done():
					return
				case it, ok := <-tasks:
					if !ok {
						return
					}
					select {
					case <-runner.ctx.Done():
						return
					case <-ctx.Done():
						return
					case <-ticker.C:
					}
					u, err := retryhttpclient.CheckProtocol(it.raw)
					if err != nil || strings.TrimSpace(u) == "" {
						continue
					}
					meta := fetchMeta(u)
					record(u, meta)
				}
			}
		}()
	}

	for _, c := range candidates {
		if runner.ctx.Err() != nil || (ctx != nil && ctx.Err() != nil) {
			break
		}
		select {
		case <-runner.ctx.Done():
			break
		case <-ctx.Done():
			break
		case tasks <- task{raw: c}:
		}
	}
	close(tasks)
	wg.Wait()

	runner.webMu.Lock()
	for k, v := range webURLByKey {
		runner.webURLByKey[k] = v
	}
	for k, v := range webMetaByKey {
		runner.webMetaByKey[k] = v
	}
	runner.webMu.Unlock()

	return webURLs
}

func (c *openPortsCollector) Add(host string, port int) {
	c.mu.Lock()
	c.open[host] = append(c.open[host], port)
	c.mu.Unlock()
}

func (c *openPortsCollector) Snapshot() map[string][]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make(map[string][]int, len(c.open))
	for host, ports := range c.open {
		cp[host] = append([]int(nil), ports...)
	}
	return cp
}

func shouldSkipRequires(target string, p poc.Poc, keyForTarget func(string) string, fingerTagsByKey map[string]map[string]struct{}) bool {
	if len(p.Info.Requires) == 0 {
		return false
	}
	reqSet := make(map[string]struct{}, len(p.Info.Requires))
	for _, r := range p.Info.Requires {
		rr := strings.ToLower(strings.TrimSpace(r))
		if rr == "" {
			continue
		}
		reqSet[rr] = struct{}{}
	}
	if len(reqSet) == 0 {
		return false
	}

	mode := strings.ToLower(strings.TrimSpace(p.Info.RequiresMode))
	if mode == "" {
		mode = "strict"
	}
	if mode != "strict" && mode != "opportunistic" {
		mode = "strict"
	}

	if len(fingerTagsByKey) == 0 {
		return mode == "strict"
	}

	key := ""
	if keyForTarget != nil {
		key = keyForTarget(target)
	}
	if key == "" {
		return mode == "strict"
	}

	tts := fingerTagsByKey[key]
	if len(tts) == 0 {
		return mode == "strict"
	}
	for r := range reqSet {
		if _, ok := tts[r]; ok {
			return false
		}
	}
	return true
}

func shouldSkipFingerprintFilteredByMode(mode string, globalFingerTags map[string]struct{}, targetTags map[string]struct{}, pocTags map[string]struct{}) bool {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "strict"
	}
	if mode != "strict" && mode != "opportunistic" {
		mode = "strict"
	}
	if len(globalFingerTags) == 0 || len(pocTags) == 0 {
		return false
	}
	appSpecific := false
	for t := range pocTags {
		if _, ok := globalFingerTags[t]; ok {
			appSpecific = true
			break
		}
	}
	if !appSpecific {
		return false
	}
	if len(targetTags) == 0 {
		return mode == "strict"
	}
	for t := range pocTags {
		if _, ok := targetTags[t]; ok {
			return false
		}
	}
	return true
}

func (e *Engine) AcquireChecker() *Checker {
	c := CheckerPool.Get().(*Checker)
	c.Options = e.options
	c.Result.Output = e.options.Output
	return c
}

func (e *Engine) ReleaseChecker(c *Checker) {
	// *c.OriginalRequest = http.Request{}
	c.VariableMap = make(map[string]any)
	c.Result = &result.Result{}
	c.CustomLib = NewCustomLib()
	CheckerPool.Put(c)
}

type Engine struct {
	options     *config.Options
	ticker      *time.Ticker
	mu          sync.Mutex
	paused      uint32
	stopped     uint32
	quit        chan struct{}
	activeTasks int64
}

func NewEngine(options *config.Options) *Engine {
	engine := &Engine{
		options: options,
		quit:    make(chan struct{}),
	}
	return engine
}

func (runner *Runner) Execute() {

	options := runner.options

	pocSlice := options.CreatePocList()
	fingerprintPocs, pocSlice := options.FingerprintPoCs(pocSlice)

	reversePocs, otherPocs := options.ReversePoCs(pocSlice)

	// fmt.Println(len(reversePocs), len(otherPocs), len(pocSlice))
	// 如果无 OOB PoC 将跳过 OOB 存活检测
	// 在SDK模式下，只有明确启用OOB时才进行连接检测
	if len(reversePocs) > 0 {
		// 检查是否是SDK模式且未启用OOB
		if options.SDKMode && !options.EnableOOB {
			// SDK模式下未启用OOB，跳过连接检测
			OOB = nil
			OOBAlive = false
		} else {
			// 非SDK模式或已启用OOB，执行正常的连接检测
			runner.options.SetOOBAdapter()
			if oobAdapter, err := oobadapter.NewOOBAdapter(options.OOB, &oobadapter.ConnectorParams{
				Key:     options.OOBKey,
				Domain:  options.OOBDomain,
				HTTPUrl: options.OOBHttpUrl,
				ApiUrl:  options.OOBApiUrl,
			}); err == nil {
				OOB = oobAdapter
				OOBAlive = OOB.IsVaild()
			} else {
				OOBAlive = false
			}
		}
		// if !OOBAlive {
		// 	gologger.Error().Msg("Using OOB Server: " + options.OOB + " is not vaild")
		// }
	}

	runner.printOOBStatus(reversePocs)

	// portscan pre-scan: run after OOB status output to ensure ordering
	if options.PortScan {
		origTargets := runner.options.Targets.List()
		origSeen := make(map[string]struct{}, len(origTargets))
		for _, t := range origTargets {
			if s, ok := t.(string); ok && s != "" {
				origSeen[s] = struct{}{}
			}
		}

		var idx *targets.TargetIndex
		if runner.TargetIndex != nil {
			idx = runner.TargetIndex
		} else {
			seeds := make([]string, 0, runner.options.Targets.Len())
			for _, t := range runner.options.Targets.List() {
				if s, ok := t.(string); ok {
					s = strings.TrimSpace(s)
					if s != "" {
						seeds = append(seeds, s)
					}
				}
			}
			idx = targets.BuildTargetIndex(seeds)
			runner.TargetIndex = idx
		}

		hosts := idx.PreScanTargets()
		if len(hosts) > 0 {
			psOpts := portscan.DefaultOptions()
			psOpts.Targets = hosts
			// Let portscan module handle its own output and progress
			psOpts.Debug = !options.Silent
			psOpts.LiveStats = options.LiveStats
			psOpts.Quiet = false
			if options.PSPorts != "" {
				psOpts.Ports = options.PSPorts
			}
			// Do not override module logging flags here
			if options.PSRateLimit > 0 {
				psOpts.RateLimit = options.PSRateLimit
			}
			if options.PSTimeout > 0 {
				psOpts.Timeout = time.Duration(options.PSTimeout) * time.Millisecond
			}
			if options.PSRetries > 0 {
				psOpts.Retries = options.PSRetries
			}
			if options.PSSkipDiscovery {
				psOpts.SkipDiscovery = true
			}
			if options.PSS4Chunk != 0 {
				psOpts.S4ChunkSize = options.PSS4Chunk
			}
			collector := newOpenPortsCollector()
			psOpts.OnResult = func(r *portscan.ScanResult) {
				if options.OnPortScanResult != nil {
					options.OnPortScanResult(r.Host, r.Port)
				}
				if !options.SDKMode {
					gologger.Print().Msgf("%s:%d", r.Host, r.Port)
				}
				collector.Add(r.Host, r.Port)
			}
			if sc, err := portscan.NewScanner(psOpts); err == nil {
				baseCtx := runner.ctx
				if baseCtx == nil {
					baseCtx = context.Background()
				}
				_ = sc.Scan(baseCtx)
				newTargets := make([]string, 0)
				for host, ports := range collector.Snapshot() {
					seenPort := make(map[int]struct{})
					for _, p := range ports {
						if _, ok := seenPort[p]; ok {
							continue
						}
						seenPort[p] = struct{}{}
						newTargets = append(newTargets, net.JoinHostPort(host, strconv.Itoa(p)))
					}
				}
				if len(newTargets) > 0 {
					for _, nt := range newTargets {
						if _, ok := origSeen[nt]; ok {
							continue
						}
						origSeen[nt] = struct{}{}
						options.Targets.Append(nt)
						if runner.TargetIndex != nil {
							runner.TargetIndex.Add(nt)
						}
					}
				}
			}
		} else if !options.SDKMode {
			gologger.Info().Msgf("%-9s | %-9s | no valid hosts for pre-scan", utils.StageHostDiscovery, "skipped")
			gologger.Info().Msgf("%-9s | %-9s | no valid hosts for pre-scan", utils.StagePortScan, "skipped")
		}
	} else if !options.SDKMode {
		gologger.Info().Msgf("%-9s | %-9s | -ps not enabled", utils.StageHostDiscovery, "skipped")
		gologger.Info().Msgf("%-9s | %-9s | -ps not enabled", utils.StagePortScan, "skipped")
	}

	allTargets := make([]string, 0, runner.options.Targets.Len())
	for _, t := range runner.options.Targets.List() {
		s, ok := t.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		allTargets = append(allTargets, s)
	}

	idx := runner.TargetIndex

	if idx == nil {
		idx = targets.BuildTargetIndex(allTargets)
		runner.TargetIndex = idx
	}
	baseCtx := runner.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	netTargetsStrict := append([]string(nil), idx.HostPorts...)
	webTargets := runner.webProbe(baseCtx, idx)
	if !runner.options.SDKMode {
		webMetas := make([]WebMeta, 0, len(webTargets))
		runner.webMu.Lock()
		for _, u := range webTargets {
			key := fingerprint.KeyFromTarget(u)
			if key == "" {
				continue
			}
			meta, ok := runner.webMetaByKey[key]
			if !ok {
				continue
			}
			if strings.TrimSpace(meta.URL) == "" {
				meta.URL = u
			}
			webMetas = append(webMetas, meta)
		}
		runner.webMu.Unlock()
		if len(webMetas) > 0 {
			_, _ = sqlite.InsertWebProbeSummary(db2.TaskID, "webprobe", "webprobe", "webprobe", "webprobe", webMetas)
			if runner.Report != nil {
				entries := make([]report.WebProbeEntry, 0, len(webMetas))
				for i, meta := range webMetas {
					urlStr := strings.TrimSpace(meta.URL)
					if urlStr == "" {
						continue
					}
					number := utils.GetNumberText(i + 1)
					entries = append(entries, report.WebProbeEntry{
						Number:    number,
						URL:       urlStr,
						Title:     strings.TrimSpace(meta.Title),
						Server:    strings.TrimSpace(meta.Server),
						PoweredBy: strings.TrimSpace(meta.PoweredBy),
					})
				}
				_ = runner.Report.AppendWebProbeEntries(entries)
			}
		}
	}
	mergeTargets := func(parts ...[]string) []string {
		seen := make(map[string]struct{})
		out := make([]string, 0)
		for _, p := range parts {
			for _, t := range p {
				t = strings.TrimSpace(t)
				if t == "" {
					continue
				}
				if _, ok := seen[t]; ok {
					continue
				}
				seen[t] = struct{}{}
				out = append(out, t)
			}
		}
		return out
	}
	resolvedHosts := make([]string, 0, len(idx.Hosts))
	runner.webMu.Lock()
	for _, h := range idx.Hosts {
		key := fingerprint.KeyFromTarget(h)
		if key != "" {
			if u := strings.TrimSpace(runner.webURLByKey[key]); u != "" {
				resolvedHosts = append(resolvedHosts, u)
				continue
			}
		}
		resolvedHosts = append(resolvedHosts, h)
	}
	runner.webMu.Unlock()

	keyForWebDedup := func(target string) string {
		target = strings.TrimSpace(target)
		if target == "" {
			return ""
		}
		if strings.Contains(target, "://") {
			return fingerprint.KeyFromTarget(target)
		}
		host, port, err := net.SplitHostPort(target)
		if err == nil && host != "" && port != "" {
			return net.JoinHostPort(host, port)
		}
		return ""
	}

	dedupWebTargets := func(in []string) []string {
		bestByKey := make(map[string]string)
		out := make([]string, 0, len(in))
		seenLoose := make(map[string]struct{})
		for _, raw := range in {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			key := keyForWebDedup(raw)
			if key == "" {
				if _, ok := seenLoose[raw]; ok {
					continue
				}
				seenLoose[raw] = struct{}{}
				out = append(out, raw)
				continue
			}
			if prev, ok := bestByKey[key]; ok {
				prevIsURL := strings.Contains(prev, "://")
				rawIsURL := strings.Contains(raw, "://")
				if !prevIsURL && rawIsURL {
					bestByKey[key] = raw
				}
				continue
			}
			bestByKey[key] = raw
		}
		for _, v := range bestByKey {
			out = append(out, v)
		}
		return out
	}

	webScanTargets := dedupWebTargets(mergeTargets(idx.URLs, resolvedHosts, webTargets, idx.HostPorts))

	isNetOnlyPoc := func(p poc.Poc) bool {
		hasHTTP := false
		hasNet := false
		hasGo := false
		for _, rm := range p.Rules {
			t := strings.ToLower(strings.TrimSpace(rm.Value.Request.Type))
			switch t {
			case "", poc.HTTP_Type, poc.HTTPS_Type:
				hasHTTP = true
			case poc.TCP_Type, poc.UDP_Type, poc.SSL_Type:
				hasNet = true
			case poc.GO_Type:
				hasGo = true
			default:
				hasHTTP = true
			}
		}
		if hasGo {
			return false
		}
		return hasNet && !hasHTTP
	}

	taskCount := 0
	if !options.DisableFingerprint && len(fingerprintPocs) > 0 {
		fingerNet := make([]poc.Poc, 0)
		fingerWeb := make([]poc.Poc, 0)
		for _, p := range fingerprintPocs {
			if isNetOnlyPoc(p) {
				fingerNet = append(fingerNet, p)
			} else {
				fingerWeb = append(fingerWeb, p)
			}
		}
		if len(fingerNet) > 0 {
			taskCount += len(fingerNet) * len(netTargetsStrict)
		}
		if len(fingerWeb) > 0 {
			taskCount += len(fingerWeb) * len(webScanTargets)
		}
	}
	for _, p := range pocSlice {
		if !isNetOnlyPoc(p) {
			taskCount += len(webScanTargets)
		} else {
			taskCount += len(netTargetsStrict)
		}
	}
	options.Count += taskCount

	if options.Smart {
		options.SmartControl()
	}

	if !options.SDKMode {
		pocTotal := len(pocSlice)
		if !options.DisableFingerprint && len(fingerprintPocs) > 0 {
			pocTotal += len(fingerprintPocs)
		}
		gologger.Info().Msgf("%-9s | %-9s | targets=%d pocs=%d tasks=%d", utils.StageVulnScan, "started", options.Targets.Len(), pocTotal, options.Count)
	}

	if !options.DisableFingerprint && len(fingerprintPocs) > 0 {
		fingerNet := make([]poc.Poc, 0)
		fingerWeb := make([]poc.Poc, 0)
		for _, p := range fingerprintPocs {
			if isNetOnlyPoc(p) {
				fingerNet = append(fingerNet, p)
			} else {
				fingerWeb = append(fingerWeb, p)
			}
		}
		if len(fingerNet) > 0 && len(netTargetsStrict) > 0 {
			runner.runFingerprintStage(baseCtx, netTargetsStrict, fingerNet)
		}
		if len(fingerWeb) > 0 && len(webScanTargets) > 0 {
			runner.runFingerprintStage(baseCtx, webScanTargets, fingerWeb)
		}
	}

	normalizeTags := func(tags string, skipFingerprint bool) map[string]struct{} {
		tags = strings.TrimSpace(tags)
		if tags == "" {
			return nil
		}
		out := make(map[string]struct{})
		for _, t := range strings.Split(strings.ToLower(tags), ",") {
			tt := strings.TrimSpace(t)
			if tt == "" {
				continue
			}
			if skipFingerprint && tt == "fingerprint" {
				continue
			}
			out[tt] = struct{}{}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}

	keyForTarget := func(target string) string {
		target = strings.TrimSpace(target)
		if target == "" {
			return ""
		}
		if strings.Contains(target, "://") {
			return fingerprint.KeyFromTarget(target)
		}
		host, port, err := net.SplitHostPort(target)
		if err == nil && host != "" && port != "" {
			return net.JoinHostPort(host, port)
		}
		return ""
	}

	fingerTagsByKey := make(map[string]map[string]struct{})
	globalFingerTags := make(map[string]struct{})
	{
		runner.fingerMu.Lock()
		fingerSnap := make(map[string][]fingerprint.Hit, len(runner.fingerByKey))
		for k, v := range runner.fingerByKey {
			if len(v) == 0 {
				continue
			}
			vv := make([]fingerprint.Hit, len(v))
			copy(vv, v)
			fingerSnap[k] = vv
		}
		runner.fingerMu.Unlock()

		for k, hits := range fingerSnap {
			tagSet := make(map[string]struct{})
			for _, h := range hits {
				hs := normalizeTags(h.Tags, true)
				for t := range hs {
					tagSet[t] = struct{}{}
				}
			}
			if len(tagSet) == 0 {
				continue
			}
			fingerTagsByKey[k] = tagSet
			for t := range tagSet {
				globalFingerTags[t] = struct{}{}
			}
		}
	}

	pocTagsCache := make(map[string]map[string]struct{})
	shouldSkipFingerprintFiltered := func(target string, p poc.Poc) bool {
		if isNetOnlyPoc(p) {
			return false
		}
		if len(globalFingerTags) == 0 {
			return false
		}
		pt, ok := pocTagsCache[p.Id]
		if !ok {
			pt = normalizeTags(p.Info.Tags, true)
			pocTagsCache[p.Id] = pt
		}
		if len(pt) == 0 {
			return false
		}
		appSpecific := false
		for t := range pt {
			if _, ok := globalFingerTags[t]; ok {
				appSpecific = true
				break
			}
		}
		if !appSpecific {
			return false
		}
		key := keyForTarget(target)
		if key == "" {
			return false
		}
		tts := fingerTagsByKey[key]
		return shouldSkipFingerprintFilteredByMode(options.FingerprintFilterMode, globalFingerTags, tts, pt)
	}

	runStage := func(pocs []poc.Poc, rate, concurrency int) {
		if runner.engine == nil || atomic.LoadUint32(&runner.engine.stopped) != 0 || runner.options.VulnerabilityScannerBreakpoint {
			return
		}
		if rate <= 0 {
			rate = 1
		}
		if concurrency <= 0 {
			concurrency = 1
		}

		runner.engine.ticker = time.NewTicker(time.Second / time.Duration(rate))
		defer func() {
			if runner.engine.ticker != nil {
				runner.engine.ticker.Stop()
				runner.engine.ticker = nil
			}
		}()

		type stageTask struct {
			tap   *TransData
			pocID string
		}

		tasks := make(chan stageTask, concurrency*4)
		var workers sync.WaitGroup

		var counters sync.Map // map[string]*atomic.Int64
		getCounter := func(pocID string) *atomic.Int64 {
			if v, ok := counters.Load(pocID); ok {
				return v.(*atomic.Int64)
			}
			c := &atomic.Int64{}
			actual, _ := counters.LoadOrStore(pocID, c)
			return actual.(*atomic.Int64)
		}
		finish := func(pocID string) {
			v, ok := counters.Load(pocID)
			if !ok {
				return
			}
			if v.(*atomic.Int64).Add(-1) == 0 {
				runner.ScanProgress.Increment(pocID)
			}
		}

		for i := 0; i < concurrency; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for {
					select {
					case <-runner.engine.quit:
						return
					case <-runner.ctx.Done():
						return
					case task, ok := <-tasks:
						if !ok {
							return
						}
						runner.engine.waitTick()
						if atomic.LoadUint32(&runner.engine.stopped) != 0 || runner.options.VulnerabilityScannerBreakpoint {
							finish(task.pocID)
							continue
						}
						runner.exec(task.tap)
						finish(task.pocID)
					}
				}
			}()
		}

		for _, pocItem := range pocs {
			if atomic.LoadUint32(&runner.engine.stopped) != 0 || runner.options.VulnerabilityScannerBreakpoint || runner.ctx.Err() != nil {
				break
			}
			targetView := webScanTargets
			if isNetOnlyPoc(pocItem) {
				targetView = netTargetsStrict
			}

			if len(runner.options.Resume) > 0 && runner.ScanProgress.Contains(pocItem.Id) {
				for range targetView {
					runner.NotVulCallback()
				}
				continue
			}

			scheduled := 0
			for _, t := range targetView {
				if atomic.LoadUint32(&runner.engine.stopped) != 0 || runner.options.VulnerabilityScannerBreakpoint || runner.ctx.Err() != nil {
					break
				}

				if shouldSkipRequires(t, pocItem, keyForTarget, fingerTagsByKey) {
					runner.NotVulCallback()
					continue
				}

				if shouldSkipFingerprintFiltered(t, pocItem) {
					runner.NotVulCallback()
					continue
				}

				getCounter(pocItem.Id).Add(1)
				scheduled++

				task := stageTask{tap: &TransData{Target: t, Poc: pocItem}, pocID: pocItem.Id}
				select {
				case <-runner.engine.quit:
					finish(task.pocID)
				case <-runner.ctx.Done():
					finish(task.pocID)
				case tasks <- task:
				}
			}
			if scheduled == 0 {
				runner.ScanProgress.Increment(pocItem.Id)
			}
		}

		close(tasks)
		workers.Wait()
	}

	runStage(otherPocs, options.RateLimit, options.Concurrency)

	oobRate := options.OOBRateLimit
	if oobRate <= 0 {
		oobRate = options.RateLimit
	}
	oobCon := options.OOBConcurrency
	if oobCon <= 0 {
		oobCon = options.Concurrency
	}
	runStage(reversePocs, oobRate, oobCon)
}

func (runner *Runner) exec(tap *TransData) {
	options := runner.options

	if len(tap.Target) > 0 && len(tap.Poc.Id) > 0 {
		baseCtx := runner.ctx
		if baseCtx == nil {
			baseCtx = context.Background()
		}
		if baseCtx.Err() != nil {
			return
		}
		atomic.AddInt64(&runner.engine.activeTasks, 1)
		defer atomic.AddInt64(&runner.engine.activeTasks, -1)
		if options.PocExecutionDurationMonitor {
			done := make(chan struct{})
			go func() {
				runner.executeExpression(baseCtx, tap.Target, &tap.Poc)
				close(done)
			}()

			select {
			case <-done:
				return
			case <-baseCtx.Done():
				return
			case <-time.After(1 * time.Minute):
				gologger.Info().Msg(log.LogColor.Time(fmt.Sprintf("The PoC for [%s] on [%s] has been running for over [%d] minute.", tap.Target, tap.Poc.Id, 1)))
				var num = 1
				for {
					select {
					case <-done:
						gologger.Info().Msg(log.LogColor.Time(fmt.Sprintf("The PoC for [%s] on [%s] has completed execution, taking over [%d] minute.", tap.Target, tap.Poc.Id, num)))
						return
					case <-baseCtx.Done():
						return
					case <-time.After(1 * time.Minute):
						num++
						gologger.Info().Msg(log.LogColor.Time(fmt.Sprintf("The PoC for [%s] on [%s] has been running for over [%d] minute.", tap.Target, tap.Poc.Id, num)))
					}
				}
			}
		} else {
			runner.executeExpression(baseCtx, tap.Target, &tap.Poc)
		}
	}
}

func (runner *Runner) executeExpression(ctx context.Context, target string, poc *poc.Poc) {
	c := runner.engine.AcquireChecker()
	defer runner.engine.ReleaseChecker(c)

	defer func() {
		// https://github.com/zan8in/afrog/v3/issues/7
		if r := recover(); r != nil {
			c.Result.IsVul = false
			runner.OnResult(c.Result)
		}
	}()

	if ctx != nil {
		c.VariableMap[retryhttpclient.ContextVarKey] = ctx
	}
	c.Check(target, poc)
	if c.Result != nil {
		c.Result.FingerResult = runner.fingerprintForTarget(c.Result.Target)
	}
	runner.OnResult(c.Result)
}

type runnerFingerprintExecutor struct {
	runner *Runner
}

func (e runnerFingerprintExecutor) Exec(ctx context.Context, target string, p *poc.Poc) (matched bool, resolvedTarget string, err error) {
	if e.runner == nil || e.runner.engine == nil {
		return false, "", nil
	}
	c := e.runner.engine.AcquireChecker()
	defer e.runner.engine.ReleaseChecker(c)
	defer e.runner.NotVulCallback()

	if ctx != nil {
		c.VariableMap[retryhttpclient.ContextVarKey] = ctx
	}
	err = c.Check(target, p)
	if c.Result == nil {
		return false, "", err
	}
	if e.runner.options != nil && e.runner.options.Debug {
		pocID := ""
		if c.Result.PocInfo != nil {
			pocID = c.Result.PocInfo.Id
		}
		for i, pr := range c.Result.AllPocResult {
			idx := i + 1
			gologger.Info().Msgf("[%d][%s] Dumped Request\n", idx, pocID)
			if pr != nil && pr.ResultRequest != nil {
				gologger.Print().Msgf("%s\n", pr.ResultRequest.GetRaw())
			} else {
				gologger.Print().Msgf("%s\n", []byte{})
			}
			gologger.Info().Msgf("[%d][%s] Dumped Response\n", idx, pocID)
			if pr != nil && pr.ResultResponse != nil {
				gologger.Print().Msgf("%s\n", pr.ResultResponse.GetRaw())
			} else {
				gologger.Print().Msgf("%s\n", []byte{})
			}
		}
	}
	if c.Result.IsVul {
		key := fingerprint.KeyFromTarget(c.Result.Target)
		if key == "" {
			key = fingerprint.KeyFromTarget(target)
		}
		if key != "" {
			e.runner.setFingerprintResult(key, p.Id, c.Result)
			hit := fingerprint.Hit{
				ID:       p.Id,
				Name:     p.Info.Name,
				Tags:     p.Info.Tags,
				Severity: p.Info.Severity,
			}
			e.runner.fingerMu.Lock()
			e.runner.fingerByKey[key] = append(e.runner.fingerByKey[key], hit)
			e.runner.fingerMu.Unlock()
			if e.runner.OnFingerprint != nil {
				e.runner.OnFingerprint(key, []fingerprint.Hit{hit})
			}
		}
	}
	return c.Result.IsVul, c.Result.Target, err
}

func (runner *Runner) runFingerprintStage(ctx context.Context, targets []string, pocs []poc.Poc) {
	if runner == nil || runner.engine == nil || atomic.LoadUint32(&runner.engine.stopped) != 0 {
		return
	}
	if len(targets) == 0 || len(pocs) == 0 {
		return
	}
	if ctx != nil && ctx.Err() != nil {
		return
	}

	e := &fingerprint.Engine{Rate: runner.options.RateLimit, Concurrency: runner.options.Concurrency}
	e.Run(ctx, targets, pocs, runnerFingerprintExecutor{runner: runner})
}

func (runner *Runner) fingerprintForTarget(target string) []fingerprint.Hit {
	key := fingerprint.KeyFromTarget(target)
	if key == "" {
		return nil
	}
	runner.fingerMu.Lock()
	hits := runner.fingerByKey[key]
	runner.fingerMu.Unlock()
	if len(hits) == 0 {
		return nil
	}
	out := make([]fingerprint.Hit, len(hits))
	copy(out, hits)
	return out
}

func (e *Engine) waitTick() {
	if e.ticker == nil {
		return
	}
	start := time.Now()
	select {
	case <-e.ticker.C:
	case <-e.quit:
		return
	}
	retryhttpclient.AddTaskGateWait(time.Since(start))
	for atomic.LoadUint32(&e.paused) != 0 {
		select {
		case <-e.quit:
			return
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (e *Engine) Pause() {
	atomic.StoreUint32(&e.paused, 1)
	gologger.Debug().Msgf("engine paused: ticker gated")
}

func (e *Engine) Resume() {
	atomic.StoreUint32(&e.paused, 0)
	gologger.Debug().Msgf("engine resumed: ticker released")
}

func (e *Engine) IsPaused() bool {
	return atomic.LoadUint32(&e.paused) != 0
}

func (e *Engine) Stop() {
	if !atomic.CompareAndSwapUint32(&e.stopped, 0, 1) {
		return
	}
	e.mu.Lock()
	if e.ticker != nil {
		e.ticker.Stop()
	}
	e.mu.Unlock()
	close(e.quit)
	gologger.Debug().Msgf("engine stopped: ticker stopped and scheduling halted")
}

func (runner *Runner) NotVulCallback() {
	runner.OnResult(&result.Result{IsVul: false})
}

type TransData struct {
	Target string
	Poc    poc.Poc
}

// 获取OOB状态信息
func (runner *Runner) getOOBStatus(reversePocs []poc.Poc) (bool, string) {
	if len(reversePocs) == 0 {
		return true, "Not required (no OOB PoCs)"
	}

	runner.options.SetOOBAdapter()

	// 从配置中获取当前OOB服务名称
	serviceName := strings.ToLower(runner.options.OOB)

	if OOB == nil {
		return false, fmt.Sprintf("%s (Not configured)", serviceName)
	}

	if !OOB.IsVaild() {
		return false, fmt.Sprintf("%s (Connection failed)", serviceName)
	}

	return true, fmt.Sprintf("%s (Active)", serviceName)
}

// 新增OOB状态显示函数
func (runner *Runner) printOOBStatus(reversePocs []poc.Poc) {
	// 在SDK模式下，不显示OOB状态信息，由SDK自己控制显示
	if runner.options.SDKMode {
		return
	}

	status, msg := runner.getOOBStatus(reversePocs)

	if !status {
		config.PrintStatusLine(
			log.LogColor.Red(config.GetErrorSymbol()),
			"OOB: ",
			log.LogColor.Red(msg),
			"",
		)
		config.PrintSeparator()

		return
	}
	config.PrintStatusLine(
		log.LogColor.Low(config.GetOkSymbol()),
		"OOB: ",
		log.LogColor.Green(msg),
		"",
	)

	config.PrintSeparator()
}

// func parseElaspsedTime(time time.Duration) string {
// 	s := fmt.Sprintf("%v", time)
// 	if len(s) > 0 {
// 		if strings.HasSuffix(s, "s") && !strings.HasSuffix(s, "ms") {
// 			t := strings.Replace(s, "s", "", -1)
// 			ts, err := strconv.ParseFloat(t, 64)
// 			if err != nil {
// 				return s
// 			}
// 			if ts >= 40 {
// 				return log.LogColor.Midium(s)
// 			}
// 		}
// 		if strings.HasSuffix(s, "m") {
// 			return log.LogColor.Red(s)
// 		}
// 	}
// 	return log.LogColor.Green(s)
// }

// func JndiTest() bool {
// 	url := "http://" + config.ReverseJndi + ":" + config.ReverseApiPort + "/?api=test"
// 	resp, _, err := retryhttpclient.Get(url)
// 	if err != nil {
// 		return false
// 	}
// 	if strings.Contains(string(resp), "no") || strings.Contains(string(resp), "yes") {
// 		return true
// 	}
// 	return false
// }

// func CeyeTest() bool {
// 	url := fmt.Sprintf("http://%s.%s", "test", config.ReverseCeyeDomain)
// 	resp, _, err := retryhttpclient.Get(url)
// 	if err != nil {
// 		return false
// 	}
// 	if strings.Contains(string(resp), "\"meta\":") || strings.Contains(string(resp), "201") {
// 		return true
// 	}
// 	return false
// }

// func EyeTest() bool {
// 	index := strings.Index(config.ReverseEyeDomain, ".")
// 	domain := config.ReverseEyeDomain

// 	if index != -1 {
// 		domain = config.ReverseEyeDomain[:index]
// 	}

// 	url := fmt.Sprintf("http://%s/api/dns/%s/test/?token=%s", config.ReverseEyeHost, domain, config.ReverseEyeToken)
// 	resp, _, err := retryhttpclient.Get(url)
// 	if err != nil {
// 		return false
// 	}
// 	if strings.Contains(string(resp), "False") {
// 		return true
// 	}
// 	return false
// }
