package runner

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/gologger"
)

type pedmStat struct {
	mu    sync.Mutex
	count uint64
	total time.Duration
	max   time.Duration
}

type pedmEntry struct {
	id     string
	target string
	pocID  string
	count  uint64
	total  time.Duration
	max    time.Duration
}

type pedmActiveTask struct {
	stage     string
	pocID     string
	target    string
	startedAt time.Time
	nextLogAt time.Time
}

type pedmActiveSnapshot struct {
	Active  int
	Queued  int
	Slow    int
	Longest time.Duration
	PocID   string
	Target  string
}

func (e *Engine) pedmReset() {
	atomic.StoreUint32(&e.startedTasks, 0)
	atomic.StoreUint32(&e.slowLogged, 0)
	e.pedmStopMonitor()
	e.pedmMu.Lock()
	e.pedmStatsByID = make(map[string]*pedmStat)
	e.pedmPairByID = make(map[string]*pedmStat)
	e.pedmMu.Unlock()
	e.pedmActiveMu.Lock()
	e.pedmActive = make(map[uint64]*pedmActiveTask)
	e.pedmActiveMu.Unlock()
}

func (e *Engine) pedmRecord(pocID string, dur time.Duration) {
	if e == nil {
		return
	}
	pocID = strings.TrimSpace(pocID)
	if pocID == "" {
		return
	}

	e.pedmMu.Lock()
	s := e.pedmEnsureStat(e.pedmStatsByID, pocID)
	e.pedmMu.Unlock()

	e.pedmApplyDuration(s, dur)
}

func (e *Engine) pedmRecordPair(target, pocID string, dur time.Duration) {
	if e == nil {
		return
	}
	key := pedmPairKey(target, pocID)
	if key == "" {
		return
	}

	e.pedmMu.Lock()
	s := e.pedmEnsureStat(e.pedmPairByID, key)
	e.pedmMu.Unlock()

	e.pedmApplyDuration(s, dur)
}

func (e *Engine) pedmEnsureStat(store map[string]*pedmStat, key string) *pedmStat {
	s := store[key]
	if s == nil {
		s = &pedmStat{}
		store[key] = s
	}
	return s
}

func (e *Engine) pedmApplyDuration(s *pedmStat, dur time.Duration) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.count++
	s.total += dur
	if dur > s.max {
		s.max = dur
	}
	s.mu.Unlock()
}

func (e *Engine) pedmMaybeLogSlow(options *config.Options, stage, pocID, target string, dur time.Duration) {
	if e == nil || options == nil {
		return
	}
	if options.PedmSlowThresholdSec <= 0 {
		return
	}
	if options.PedmSlowLogLimit <= 0 {
		return
	}
	threshold := time.Duration(options.PedmSlowThresholdSec) * time.Second
	if dur < threshold {
		return
	}
	if atomic.AddUint32(&e.slowLogged, 1) > uint32(options.PedmSlowLogLimit) {
		return
	}
	e.pedmLog(options, fmt.Sprintf("PEDM-SLOW | completed | stage=%s dur=%s poc=%s target=%s", stage, dur.String(), pocID, target))
}

func (e *Engine) pedmSummary(options *config.Options) {
	if e == nil || options == nil {
		return
	}
	if options.PedmSummaryTop <= 0 {
		return
	}

	e.pedmMu.Lock()
	entries := e.pedmCollectEntries(e.pedmStatsByID, false)
	pairEntries := e.pedmCollectEntries(e.pedmPairByID, true)
	e.pedmMu.Unlock()

	if len(entries) == 0 && len(pairEntries) == 0 {
		return
	}

	by := strings.ToLower(strings.TrimSpace(options.PedmSummaryBy))
	if by != "avg" && by != "max" {
		by = "max"
	}

	top := options.PedmSummaryTop
	if len(entries) > 0 {
		e.pedmSortEntries(entries, by)
		e.pedmPrintSummary("poc", top, by, entries)
	}
	if len(pairEntries) > 0 {
		e.pedmSortEntries(pairEntries, by)
		e.pedmPrintSummary("target+poc", top, by, pairEntries)
	}
}

func (e *Engine) pedmCollectEntries(store map[string]*pedmStat, splitPair bool) []pedmEntry {
	entries := make([]pedmEntry, 0, len(store))
	for id, s := range store {
		if s == nil {
			continue
		}
		s.mu.Lock()
		c := s.count
		t := s.total
		m := s.max
		s.mu.Unlock()
		if c == 0 {
			continue
		}
		entry := pedmEntry{id: id, count: c, total: t, max: m}
		if splitPair {
			entry.target, entry.pocID = pedmSplitPairKey(id)
		} else {
			entry.pocID = id
		}
		entries = append(entries, entry)
	}
	return entries
}

func (e *Engine) pedmSortEntries(entries []pedmEntry, by string) {
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		ai := e.pedmMetric(a, by)
		aj := e.pedmMetric(b, by)
		if ai != aj {
			return ai > aj
		}
		if a.pocID != b.pocID {
			return a.pocID < b.pocID
		}
		return a.target < b.target
	})
}

func (e *Engine) pedmMetric(entry pedmEntry, by string) time.Duration {
	if by == "avg" && entry.count > 0 {
		return entry.total / time.Duration(entry.count)
	}
	return entry.max
}

func (e *Engine) pedmPrintSummary(scope string, top int, by string, entries []pedmEntry) {
	if len(entries) == 0 {
		return
	}
	if top > len(entries) {
		top = len(entries)
	}
	if top <= 0 {
		return
	}

	e.pedmLog(e.options, fmt.Sprintf("PEDM-SUMMARY | scope=%s by=%s top=%d", scope, by, top))
	for i := 0; i < top; i++ {
		it := entries[i]
		avg := it.total / time.Duration(it.count)
		if scope == "target+poc" {
			e.pedmLog(e.options, fmt.Sprintf("PEDM #%d | target=%s | poc=%s | count=%d avg=%s max=%s", i+1, it.target, it.pocID, it.count, avg.String(), it.max.String()))
			continue
		}
		e.pedmLog(e.options, fmt.Sprintf("PEDM #%d | poc=%s | count=%d avg=%s max=%s", i+1, it.pocID, it.count, avg.String(), it.max.String()))
	}
}

func (e *Engine) pedmLog(options *config.Options, line string) {
	if strings.TrimSpace(line) == "" {
		return
	}
	if options != nil && e.getScanCtx().OnPedmLog != nil {
		e.getScanCtx().OnPedmLog(line)
		return
	}
	gologger.Info().Msg(log.LogColor.Time(line))
}

func pedmPairKey(target, pocID string) string {
	target = strings.TrimSpace(target)
	pocID = strings.TrimSpace(pocID)
	if target == "" || pocID == "" {
		return ""
	}
	return target + "\x00" + pocID
}

func pedmSplitPairKey(v string) (string, string) {
	parts := strings.SplitN(v, "\x00", 2)
	if len(parts) != 2 {
		return "", strings.TrimSpace(v)
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func (e *Engine) pedmStartMonitor(options *config.Options) {
	if e == nil || options == nil || !options.PocExecutionDurationMonitor || options.PedmSlowThresholdSec <= 0 {
		return
	}

	stop := make(chan struct{})
	e.pedmActiveMu.Lock()
	if e.pedmStop != nil {
		close(e.pedmStop)
	}
	e.pedmStop = stop
	e.pedmActiveMu.Unlock()

	threshold := time.Duration(options.PedmSlowThresholdSec) * time.Second
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
			}

			now := time.Now()
			logs := make([]string, 0)

			e.pedmActiveMu.Lock()
			activeCount := len(e.pedmActive)
			for _, task := range e.pedmActive {
				if task == nil || task.startedAt.IsZero() {
					continue
				}
				elapsed := now.Sub(task.startedAt)
				if elapsed < threshold {
					continue
				}
				if !task.nextLogAt.IsZero() && now.Before(task.nextLogAt) {
					continue
				}
				task.nextLogAt = now.Add(1 * time.Minute)
				logs = append(logs, fmt.Sprintf("PEDM-SLOW | running | stage=%s dur=%s active=%d poc=%s target=%s", task.stage, elapsed.Truncate(time.Second).String(), activeCount, task.pocID, task.target))
			}
			e.pedmActiveMu.Unlock()

			for _, line := range logs {
				e.pedmLog(options, line)
			}
		}
	}()
}

func (e *Engine) pedmStopMonitor() {
	if e == nil {
		return
	}
	e.pedmActiveMu.Lock()
	stop := e.pedmStop
	e.pedmStop = nil
	e.pedmActiveMu.Unlock()
	if stop != nil {
		close(stop)
	}
}

func (e *Engine) pedmStartTask(stage, pocID, target string) uint64 {
	if e == nil {
		return 0
	}
	taskID := atomic.AddUint64(&e.pedmTaskSeq, 1)
	e.pedmActiveMu.Lock()
	e.pedmActive[taskID] = &pedmActiveTask{
		stage:     strings.TrimSpace(stage),
		pocID:     strings.TrimSpace(pocID),
		target:    strings.TrimSpace(target),
		startedAt: time.Now(),
	}
	e.pedmActiveMu.Unlock()
	return taskID
}

func (e *Engine) pedmDoneTask(taskID uint64) {
	if e == nil || taskID == 0 {
		return
	}
	e.pedmActiveMu.Lock()
	delete(e.pedmActive, taskID)
	e.pedmActiveMu.Unlock()
}

func (e *Engine) pedmSnapshot(options *config.Options) pedmActiveSnapshot {
	if e == nil {
		return pedmActiveSnapshot{}
	}
	threshold := time.Duration(0)
	if options != nil && options.PedmSlowThresholdSec > 0 {
		threshold = time.Duration(options.PedmSlowThresholdSec) * time.Second
	}

	now := time.Now()
	snap := pedmActiveSnapshot{}
	snap.Queued = int(atomic.LoadInt64(&e.queuedTasks))
	e.pedmActiveMu.Lock()
	snap.Active = len(e.pedmActive)
	for _, task := range e.pedmActive {
		if task == nil || task.startedAt.IsZero() {
			continue
		}
		elapsed := now.Sub(task.startedAt)
		if threshold > 0 && elapsed >= threshold {
			snap.Slow++
		}
		if elapsed > snap.Longest {
			snap.Longest = elapsed
			snap.PocID = task.pocID
			snap.Target = task.target
		}
	}
	e.pedmActiveMu.Unlock()
	return snap
}

func (e *Engine) taskHardTimeout(taskPoc *poc.Poc) time.Duration {
	if e == nil || e.options == nil {
		return 0
	}
	fixedFallbackSec := 0
	if e.options.TaskHardTimeoutSec > 0 {
		fixedFallbackSec = e.options.TaskHardTimeoutSec
	}
	if e.options.TaskSmartTimeout {
		return poc.TaskTimeoutDuration(taskPoc, fixedFallbackSec)
	}
	if fixedFallbackSec <= 0 {
		return 0
	}
	return time.Duration(fixedFallbackSec) * time.Second
}

func (e *Engine) taskTimeoutLog(stage, pocID, target string, dur, limit time.Duration) {
	if e == nil || e.options == nil || !e.options.PocExecutionDurationMonitor {
		return
	}
	if dur <= 0 {
		dur = limit
	}
	e.pedmLog(e.options, fmt.Sprintf("TASK-TIMEOUT | stage=%s elapsed=%s limit=%s poc=%s target=%s", stage, dur.Truncate(time.Second).String(), limit.String(), pocID, target))
}
