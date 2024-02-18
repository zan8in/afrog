package runner

import (
	"fmt"
	"time"

	"github.com/remeh/sizedwaitgroup"
	"github.com/zan8in/afrog/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/pkg/utils"
)

func (r *Runner) monitorTargets() {
	if r.options.Targets.Len() == 0 {
		return
	}

	ticker := time.NewTicker(time.Second / time.Duration(r.options.RateLimit))
	swg := sizedwaitgroup.New(r.options.Concurrency)
	for i := 0; i <= r.options.MaxHostError; i++ {
		for _, v := range r.options.Targets.List() {
			swg.Add()
			<-ticker.C

			go func(v string) {
				defer swg.Done()
				r.checkURL(v)
			}(v.(string))
		}
	}
	swg.Wait()
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
