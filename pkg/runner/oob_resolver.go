package runner

import (
	"strings"
	"sync/atomic"
	"time"

	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/result"
	"gopkg.in/yaml.v2"
)

type oobPendingEntry struct {
	filter     string
	filterType string
	token      string
	timeoutSec int64
	target     string
	fulltarget string
	poc        poc.Poc
}

func (r *Runner) registerOOBPendings(res *result.Result, pendings []OOBPending) {
	if r == nil || res == nil || len(pendings) == 0 {
		return
	}
	if r.engine == nil || r.engine.oobMgr == nil {
		return
	}
	for _, p := range pendings {
		filter := strings.TrimSpace(p.Filter)
		filterType := strings.TrimSpace(p.FilterType)
		if filter == "" || filterType == "" {
			continue
		}
		key := filterType + "|" + filter + "|" + strings.TrimSpace(p.Token)

		ent := &oobPendingEntry{
			filter:     filter,
			filterType: filterType,
			token:      strings.TrimSpace(p.Token),
			timeoutSec: p.TimeoutSec,
			target:     res.Target,
			fulltarget: res.FullTarget,
		}
		if ent.fulltarget == "" {
			ent.fulltarget = ent.target
		}
		if res.PocInfo != nil {
			ent.poc = *res.PocInfo
		}

		r.oobPendingMu.Lock()
		if r.oobPending == nil {
			r.oobPending = make(map[string]*oobPendingEntry)
		}
		if old := r.oobPending[key]; old != nil {
			if ent.timeoutSec > old.timeoutSec {
				old.timeoutSec = ent.timeoutSec
			}
			if old.fulltarget == "" {
				old.fulltarget = ent.fulltarget
			}
			if old.target == "" {
				old.target = ent.target
			}
			if old.poc.Id == "" && ent.poc.Id != "" {
				old.poc = ent.poc
			}
		} else {
			r.oobPending[key] = ent
		}
		r.oobPendingMu.Unlock()

		r.engine.oobMgr.Watch(filter, filterType)
	}
}

func (r *Runner) startOOBResolver() {
	if r == nil || r.engine == nil || r.engine.oobMgr == nil {
		return
	}
	if r.oobResolverStop != nil || r.oobResolverDone != nil {
		return
	}
	r.oobResolverStop = make(chan struct{})
	r.oobResolverDone = make(chan struct{})

	interval := time.Duration(0)
	if r.options != nil && r.options.OOBPollInterval > 0 {
		interval = time.Duration(r.options.OOBPollInterval) * time.Second
	}
	if interval < 2*time.Second {
		interval = 2 * time.Second
	}

	go func() {
		defer close(r.oobResolverDone)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-r.oobResolverStop:
				return
			case <-ticker.C:
				r.resolveOOBPendingsOnce()
			}
		}
	}()
}

func (r *Runner) stopOOBResolver() {
	if r == nil || r.oobResolverStop == nil || r.oobResolverDone == nil {
		return
	}
	close(r.oobResolverStop)
	<-r.oobResolverDone
	r.oobResolverStop = nil
	r.oobResolverDone = nil
}

func (r *Runner) resolveOOBPendingsOnce() int {
	if r == nil || r.engine == nil || r.engine.oobMgr == nil || r.OnResult == nil {
		return 0
	}

	r.oobPendingMu.Lock()
	items := make([]struct {
		key string
		ent *oobPendingEntry
	}, 0, len(r.oobPending))
	for k, v := range r.oobPending {
		if v == nil {
			continue
		}
		items = append(items, struct {
			key string
			ent *oobPendingEntry
		}{key: k, ent: v})
	}
	r.oobPendingMu.Unlock()

	resolved := 0
	for _, it := range items {
		ent := it.ent
		snap, ok := r.engine.oobMgr.HitSnapshot(ent.filter, ent.filterType)
		if !ok {
			continue
		}
		if ent.token != "" && !strings.Contains(snap.Snippet, ent.token) {
			continue
		}

		ev := r.engine.oobMgr.Evidence(ent.filter, ent.filterType, 5)
		if strings.TrimSpace(ev) == "" {
			continue
		}

		pi := ent.poc
		rst := &result.Result{
			IsVul:      true,
			SkipCount:  true,
			Target:     ent.target,
			FullTarget: ent.fulltarget,
			PocInfo:    &pi,
			Extractor:  yaml.MapSlice{{Key: "oob_evidence", Value: ev}},
		}
		r.OnResult(rst)

		r.oobPendingMu.Lock()
		delete(r.oobPending, it.key)
		r.oobPendingMu.Unlock()
		resolved++
	}

	return resolved
}

func (r *Runner) finalizeOOBPendings() {
	if r == nil {
		return
	}
	if r.engine == nil || r.engine.oobMgr == nil {
		if r.options != nil && r.options.OnPhaseProgress != nil {
			r.options.OnPhaseProgress("oob_finalize", "skipped", 0, 0, 100)
		}
		return
	}

	r.stopOOBResolver()

	atomic.StoreUint32(&r.oobFinalizing, 1)
	defer atomic.StoreUint32(&r.oobFinalizing, 0)

	r.oobPendingMu.Lock()
	total := int64(len(r.oobPending))
	maxTo := int64(0)
	for _, v := range r.oobPending {
		if v == nil {
			continue
		}
		if v.timeoutSec > maxTo {
			maxTo = v.timeoutSec
		}
	}
	r.oobPendingMu.Unlock()

	if total == 0 {
		if r.options != nil && r.options.OnPhaseProgress != nil {
			r.options.OnPhaseProgress("oob_finalize", "skipped", 0, 0, 100)
		}
		return
	}

	if r.options != nil && r.options.OOBFinalizeTimeout >= 0 {
		maxTo = int64(r.options.OOBFinalizeTimeout)
	} else {
		if maxTo <= 0 {
			maxTo = 5
		}
		if maxTo < 5 {
			maxTo = 5
		}
		if maxTo > 60 {
			maxTo = 60
		}
	}

	interval := 2 * time.Second
	if r.options != nil && r.options.OOBPollInterval > 0 {
		interval = time.Duration(r.options.OOBPollInterval) * time.Second
		if interval < 2*time.Second {
			interval = 2 * time.Second
		}
	}

	deadline := time.Now().Add(time.Duration(maxTo) * time.Second)
	status := "running"

	emit := func(status string, remain int64) {
		if r.options == nil || r.options.OnPhaseProgress == nil {
			return
		}
		finished := total - remain
		if finished < 0 {
			finished = 0
		}
		if finished > total {
			finished = total
		}
		percent := 100
		if total > 0 {
			percent = int(finished * 100 / total)
			if percent > 100 {
				percent = 100
			}
			if percent < 0 {
				percent = 0
			}
		}
		r.options.OnPhaseProgress("oob_finalize", status, finished, total, percent)
	}

	for {
		if r.ctx != nil && r.ctx.Err() != nil {
			status = "interrupted"
			break
		}

		r.resolveOOBPendingsOnce()

		r.oobPendingMu.Lock()
		remain := int64(len(r.oobPending))
		r.oobPendingMu.Unlock()

		emit("running", remain)

		if remain == 0 {
			status = "completed"
			break
		}
		if maxTo == 0 || time.Now().After(deadline) {
			status = "deadline"
			break
		}
		time.Sleep(interval)
	}

	r.oobPendingMu.Lock()
	remain := int64(len(r.oobPending))
	r.oobPendingMu.Unlock()
	emit(status, remain)
}
