package fingerprint

import (
	"context"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/poc"
)

type Hit struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Tags     string `json:"tags,omitempty"`
	Severity string `json:"severity,omitempty"`
}

type Executor interface {
	Exec(ctx context.Context, target string, poc *poc.Poc) (matched bool, resolvedTarget string, err error)
}

type Engine struct {
	Rate        int
	Concurrency int
}

func (e *Engine) Run(ctx context.Context, targets []string, pocs []poc.Poc, exec Executor) map[string][]Hit {
	out := make(map[string][]Hit)
	if ctx == nil || ctx.Err() != nil {
		return out
	}
	if len(targets) == 0 || len(pocs) == 0 || exec == nil {
		return out
	}

	rate := e.Rate
	if rate <= 0 {
		rate = 1
	}
	concurrency := e.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	ticker := time.NewTicker(time.Second / time.Duration(rate))
	defer ticker.Stop()

	type task struct {
		target string
		poc    *poc.Poc
	}

	tasks := make(chan task, concurrency*4)
	var wg sync.WaitGroup

	var mu sync.Mutex
	record := func(resolvedTarget string, hit Hit) {
		key := KeyFromTarget(resolvedTarget)
		if key == "" {
			return
		}
		mu.Lock()
		out[key] = append(out[key], hit)
		mu.Unlock()
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case t, ok := <-tasks:
					if !ok {
						return
					}
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
					}
					matched, resolvedTarget, _ := exec.Exec(ctx, t.target, t.poc)
					if matched {
						record(resolvedTarget, Hit{
							ID:       t.poc.Id,
							Name:     t.poc.Info.Name,
							Tags:     t.poc.Info.Tags,
							Severity: t.poc.Info.Severity,
						})
					}
				}
			}
		}()
	}

	for i := range pocs {
		if ctx.Err() != nil {
			break
		}
		pp := &pocs[i]
		for _, t := range targets {
			if ctx.Err() != nil {
				break
			}
			tasks <- task{target: t, poc: pp}
		}
	}

	close(tasks)
	wg.Wait()
	return out
}

func KeyFromTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
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
	return net.JoinHostPort(host, port)
}
