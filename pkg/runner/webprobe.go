package runner

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zan8in/afrog/v3/pkg/fingerprint"
	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/targets"
	"github.com/zan8in/afrog/v3/pkg/utils"
)

var titleExtractRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func keyFromTargetWithPath(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if !strings.Contains(target, "://") {
		host, port, err := net.SplitHostPort(target)
		if err == nil && host != "" && port != "" {
			return net.JoinHostPort(host, port)
		}
		return ""
	}
	u, err := url.Parse(target)
	if err != nil || u == nil {
		return ""
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return ""
	}
	port := strings.TrimSpace(u.Port())
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return ""
		}
	}
	base := net.JoinHostPort(host, port)
	path := strings.TrimSpace(u.EscapedPath())
	path = strings.TrimRight(path, "/")
	if path == "" || path == "/" {
		return base
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

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
	if ctx == nil {
		ctx = context.Background()
	} else if ctx.Err() != nil {
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
	totalCandidates := len(candidates)
	var processed uint64
	var lastPercent int32 = -1
	if runner.getScanCtx().OnPhaseProgress != nil {
		runner.getScanCtx().OnPhaseProgress("webprobe", "running", 0, int64(totalCandidates), 0)
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
		if runner.OnWebProbe != nil {
			runner.OnWebProbe(meta)
		}
		if runner.options != nil && !runner.options.SDKMode && !runner.options.Silent {
			extinfo := ""
			if t := strings.TrimSpace(meta.Title); t != "" {
				t = utils.Str2UTF8(t)
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
		meta := WebMeta{URL: urlStr}
		u, err := url.Parse(urlStr)
		if err != nil {
			return meta
		}
		reqURI := strings.TrimSpace(u.RequestURI())
		if reqURI == "" {
			reqURI = "/"
		}
		rule := poc.Rule{}
		rule.Request.Method = "GET"
		rule.Request.Path = "^" + reqURI
		rule.Request.FollowRedirects = true
		_ = retryhttpclient.Request(urlStr, runner.options.Header, rule, vm)

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
					d := atomic.AddUint64(&processed, 1)
					if runner.getScanCtx().OnPhaseProgress != nil && totalCandidates > 0 {
						percent := int(d * 100 / uint64(totalCandidates))
						if percent > 100 {
							percent = 100
						}
						if int32(percent) != atomic.LoadInt32(&lastPercent) {
							atomic.StoreInt32(&lastPercent, int32(percent))
							runner.getScanCtx().OnPhaseProgress("webprobe", "running", int64(d), int64(totalCandidates), percent)
						}
					}
					select {
					case <-runner.ctx.Done():
						return
					case <-ctx.Done():
						return
					case <-ticker.C:
					}
					meta := fetchMeta(it.raw)
					record(it.raw, meta)
				}
			}
		}()
	}

	for _, c := range candidates {
		select {
		case <-runner.ctx.Done():
			close(tasks)
			wg.Wait()
			return webURLs
		case <-ctx.Done():
			close(tasks)
			wg.Wait()
			return webURLs
		case tasks <- task{raw: c}:
		}
	}
	close(tasks)
	wg.Wait()

	done := uint64(len(webURLs))
	status := "completed"
	select {
	case <-runner.ctx.Done():
		status = "interrupted"
	case <-ctx.Done():
		status = "interrupted"
	default:
	}
	percent := 100
	if totalCandidates > 0 {
		percent = int(done * 100 / uint64(totalCandidates))
		if percent > 100 {
			percent = 100
		}
	}
	if runner.getScanCtx().OnPhaseProgress != nil {
		runner.getScanCtx().OnPhaseProgress("webprobe", status, int64(done), int64(totalCandidates), percent)
	}

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
