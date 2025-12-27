package runner

import (
	"fmt"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v3/pkg/utils"
)

func (r *Runner) monitorTargets() {
	if r.options.Targets.Len() == 0 {
		return
	}

	rate := r.options.RateLimit
	if rate <= 0 {
		rate = 1
	}
	interval := time.Second / time.Duration(rate)
	if interval <= 0 {
		interval = time.Nanosecond
	}

	concurrency := r.options.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	maxHostError := r.options.MaxHostError
	if maxHostError < 0 {
		maxHostError = 0
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	targets := r.options.Targets.List()

	jobs := make(chan string, concurrency*2)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-r.ctx.Done():
					return
				case t, ok := <-jobs:
					if !ok {
						return
					}

					for attempt := 0; attempt <= maxHostError; attempt++ {
						select {
						case <-r.ctx.Done():
							return
						case <-ticker.C:
						}

						_, err := r.checkURL(t)
						if err == nil {
							break
						}
						if r.options.Targets.Num(t) > maxHostError {
							break
						}
					}
				}
			}
		}()
	}

	for _, v := range targets {
		select {
		case <-r.ctx.Done():
			close(jobs)
			wg.Wait()
			return
		case jobs <- v.(string):
		}
	}
	close(jobs)
	wg.Wait()
}

func (r *Runner) checkURL(target string) (string, error) {

	tcount := r.options.Targets.Num(target)

	if tcount == ActiveTarget {
		return target, nil
	}

	if tcount > r.options.MaxHostError {
		return "", fmt.Errorf("%s is blacklisted", target)
	}

	// if target is not url, then check again
	if !utils.IsURL(target) {
		if newtarget, err := retryhttpclient.CheckProtocol(target); err == nil {
			if k := r.options.Targets.Key(target); k >= 0 {
				r.options.Targets.Update(k, newtarget)
				r.options.Targets.SetNum(newtarget, ActiveTarget)
			}
			return newtarget, nil
		}

		r.options.Targets.UpdateNum(target, 1)
		return target, fmt.Errorf("%s check protocol falied", target)
	}

	// if target is url more than zero, then check protocol against
	if r.options.Targets.Num(target) >= 0 {
		if newtarget, err := retryhttpclient.CheckProtocol(target); err == nil {
			r.options.Targets.SetNum(newtarget, ActiveTarget)
			return newtarget, nil
		}

		r.options.Targets.UpdateNum(target, 1)
		return target, fmt.Errorf("%s no response", target)
	}

	return target, nil
}
