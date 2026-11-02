package passive

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeDetector struct {
	name     string
	interest bool
	findings []Finding
	err      error
	panicOn  bool
	// calls 非空时统计 Detect 被调用的次数，用于验证短路是否真的省掉了检测。
	calls *int32
}

func (f *fakeDetector) Name() string { return f.name }

func (f *fakeDetector) Interest(*CapturedTransaction) bool { return f.interest }

func (f *fakeDetector) Detect(context.Context, *CapturedTransaction, Prober) ([]Finding, error) {
	if f.calls != nil {
		atomic.AddInt32(f.calls, 1)
	}
	if f.panicOn {
		panic("boom")
	}
	return f.findings, f.err
}

func newTestTransaction() *CapturedTransaction {
	return &CapturedTransaction{
		ID:      "tx",
		Request: &CapturedRequest{Method: "GET", Headers: nil},
	}
}

func TestEngineFiltersLowConfidence(t *testing.T) {
	var reported int32
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{&fakeDetector{
			name:     "fake",
			interest: true,
			findings: []Finding{{
				Detector:   "fake",
				VulnType:   "sqli",
				Confidence: ConfidenceProbable,
				Target:     "http://example.com/",
				Location:   "query:id",
			}},
		}},
		Prober:    &noopProber{},
		Workers:   1,
		OnFinding: func(Finding) { atomic.AddInt32(&reported, 1) },
	})
	eng.Start(context.Background())
	defer eng.Close()

	eng.Submit(newTestTransaction())
	waitFor(t, func() bool { return eng.Stats().Filtered == 1 })

	if atomic.LoadInt32(&reported) != 0 {
		t.Fatalf("low-confidence finding must not be reported")
	}
	if got := eng.Stats().Reported; got != 0 {
		t.Fatalf("Reported = %d, want 0", got)
	}
}

func TestEngineDeduplicates(t *testing.T) {
	var reported int32
	finding := Finding{
		Detector:   "fake",
		VulnType:   "sqli",
		Severity:   "high",
		Confidence: ConfidenceCertain,
		Target:     "http://example.com/list",
		Location:   "query:id",
	}
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{&fakeDetector{name: "fake", interest: true, findings: []Finding{finding}}},
		Prober:    &noopProber{},
		Workers:   1,
		OnFinding: func(Finding) { atomic.AddInt32(&reported, 1) },
	})
	eng.Start(context.Background())
	defer eng.Close()

	eng.Submit(newTestTransaction())
	waitFor(t, func() bool { return eng.Stats().Reported == 1 })
	eng.Submit(newTestTransaction())
	waitFor(t, func() bool { return eng.Stats().Duplicated == 1 })

	if got := atomic.LoadInt32(&reported); got != 1 {
		t.Fatalf("reported = %d, want 1 (duplicate must be suppressed)", got)
	}
}

// TestEngineTrafficVerdictForDuplicate 锁定「重复命中必须单独成一类结论」。
//
// 若去重被并入 no-finding，界面会把「确实检出了、只是此前报过」显示成
// 「检测无结论」，等于抹掉真实发现，正是本次要修的显示不一致。
func TestEngineTrafficVerdictForDuplicate(t *testing.T) {
	finding := Finding{
		Detector:   "fake",
		VulnType:   "sqli",
		Severity:   "high",
		Confidence: ConfidenceCertain,
		Target:     "http://example.com/list",
		Location:   "query:id",
	}
	var mu sync.Mutex
	var events []TrafficEvent
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{&fakeDetector{name: "fake", interest: true, findings: []Finding{finding}}},
		Prober:    &noopProber{},
		Workers:   1,
		OnTraffic: func(ev TrafficEvent) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		},
	})
	eng.Start(context.Background())
	defer eng.Close()

	eng.Submit(newTestTransaction())
	waitFor(t, func() bool { return eng.Stats().Reported == 1 })
	eng.Submit(newTestTransaction())
	waitFor(t, func() bool { return eng.Stats().Duplicated == 1 })

	mu.Lock()
	defer mu.Unlock()
	if len(events) < 2 {
		t.Fatalf("expected at least 2 traffic events, got %d", len(events))
	}
	last := events[len(events)-1]
	if last.Verdict != VerdictDuplicate {
		t.Fatalf("duplicate verdict = %q, want %q", last.Verdict, VerdictDuplicate)
	}
	if last.Duplicated != 1 {
		t.Fatalf("Duplicated = %d, want 1", last.Duplicated)
	}
	if last.Findings != 0 {
		t.Fatalf("Findings = %d, want 0 (duplicate must not count as a new finding)", last.Findings)
	}
}

// TestEngineShortCircuitsKnownHitPoints 锁定「已确认命中的注入点不再重复重放」。
//
// 同一注入点重复出现（浏览器刷新、前端轮询、?id 换值）时，结论不可能变，重跑一遍
// 只会重复消耗重放流量（含最贵的 WAF 绕过分支）。但也必须保证「未命中过的注入点
// 照常检测」——零漏报是底线，短路只允许发生在全部注入点都已确认命中的请求上。
func TestEngineShortCircuitsKnownHitPoints(t *testing.T) {
	var calls int32
	det := &fakeDetector{
		name:     "fake",
		interest: true,
		calls:    &calls,
		findings: []Finding{{
			Detector:   "fake",
			VulnType:   "sqli",
			Severity:   "high",
			Confidence: ConfidenceCertain,
			Target:     "http://example.com/list",
			Location:   "query:id",
		}},
	}
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{det},
		Prober:    &noopProber{},
		Workers:   1,
	})
	eng.Start(context.Background())
	defer eng.Close()

	// 第一次：正常检测并上报，注入点被记为已确认。
	eng.Submit(txAt(t, "http://example.com/list?id=1"))
	waitFor(t, func() bool { return eng.Stats().Reported == 1 })

	// 同一注入点换个值再来：必须短路，检测器不能再被调用。
	eng.Submit(txAt(t, "http://example.com/list?id=42"))
	waitFor(t, func() bool { return eng.Stats().Duplicated == 1 })
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("Detect 调用次数 = %d, want 1（已命中的注入点必须短路，不得重放）", got)
	}

	// 换一个未命中过的注入点：必须照常检测，不能被上一条的短路规则连坐。
	eng.Submit(txAt(t, "http://example.com/list?q=abc"))
	waitFor(t, func() bool { return atomic.LoadInt32(&calls) == 2 })
}

// txAt 构造一条带真实 URL 的事务（注入点来自 query，因此必须有 URL）。
func txAt(t *testing.T, raw string) *CapturedTransaction {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return &CapturedTransaction{
		ID:      "tx",
		Request: &CapturedRequest{Method: http.MethodGet, URL: u, Headers: http.Header{}},
	}
}

func TestEngineIsolatesDetectorPanic(t *testing.T) {
	var gotErr int32
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{&fakeDetector{name: "boom", interest: true, panicOn: true}},
		Prober:    &noopProber{},
		Workers:   1,
		OnError:   func(string, error) { atomic.AddInt32(&gotErr, 1) },
	})
	eng.Start(context.Background())
	defer eng.Close()

	eng.Submit(newTestTransaction())
	waitFor(t, func() bool { return eng.Stats().Errors == 1 })

	if atomic.LoadInt32(&gotErr) != 1 {
		t.Fatalf("panic must be surfaced as detector error")
	}
}

func TestEngineReportsDetectorError(t *testing.T) {
	var gotErr int32
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{&fakeDetector{name: "err", interest: true, err: errors.New("x")}},
		Prober:    &noopProber{},
		Workers:   1,
		OnError:   func(string, error) { atomic.AddInt32(&gotErr, 1) },
	})
	eng.Start(context.Background())
	defer eng.Close()

	eng.Submit(newTestTransaction())
	waitFor(t, func() bool { return atomic.LoadInt32(&gotErr) == 1 })
}

func TestEngineDropsWhenQueueFull(t *testing.T) {
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{&fakeDetector{name: "fake", interest: false}},
		Prober:    &noopProber{},
		Workers:   1,
		QueueSize: 1,
	})
	// 未 Start，所有提交都应被丢弃。
	accepted := 0
	for i := 0; i < 5; i++ {
		if eng.Submit(newTestTransaction()) {
			accepted++
		}
	}
	if accepted != 0 {
		t.Fatalf("accepted = %d, want 0 before Start", accepted)
	}
	if got := eng.Stats().Dropped; got != 5 {
		t.Fatalf("Dropped = %d, want 5", got)
	}
}

// TestEngineTracksHandledAndDrained 锁定「队列是否已排空」的判定依据。
//
// 关键点：Inspected 会漏掉「没有检测器感兴趣」的事务（它们在 handle 里直接
// continue，不会计入），所以队列空了也可能判成「还在处理」。排空必须看
// Handled / QueueDepth / InFlight——本用例用「无人感兴趣」的检测器把差异放大。
func TestEngineTracksHandledAndDrained(t *testing.T) {
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{&fakeDetector{name: "fake", interest: false}},
		Prober:    &noopProber{},
		Workers:   1,
		QueueSize: 4,
	})
	if !eng.Drained() {
		t.Fatalf("尚未投递任何事务时队列应为已排空")
	}

	eng.Start(context.Background())
	defer eng.Close()

	for i := 0; i < 3; i++ {
		eng.Submit(newTestTransaction())
	}
	waitFor(t, eng.Drained)

	st := eng.Stats()
	if st.Handled != 3 {
		t.Fatalf("Handled = %d, want 3（未通过门控的事务也必须计入已处理）", st.Handled)
	}
	if st.Inspected != 0 {
		t.Fatalf("Inspected = %d, want 0（无人感兴趣）", st.Inspected)
	}
	if st.QueueDepth != 0 || st.InFlight != 0 {
		t.Fatalf("QueueDepth = %d, InFlight = %d, want 0 / 0", st.QueueDepth, st.InFlight)
	}
	if st.Dropped != 0 {
		t.Fatalf("Dropped = %d, want 0", st.Dropped)
	}
}

// funcDetector 是行为可编程的检测器，用于构造「慢检测」等受控场景。
type funcDetector struct {
	name       string
	interestFn func(*CapturedTransaction) bool
	detectFn   func(context.Context, *CapturedTransaction, Prober) ([]Finding, error)
}

func (f *funcDetector) Name() string { return f.name }

func (f *funcDetector) Interest(tx *CapturedTransaction) bool { return f.interestFn(tx) }

func (f *funcDetector) Detect(ctx context.Context, tx *CapturedTransaction, p Prober) ([]Finding, error) {
	return f.detectFn(ctx, tx, p)
}

// TestEngineGateSurvivesSlowDetection 锁定两阶段流水线的核心收益：
// 一条病态慢的检测只能占住检测池，不得再堵死门控入口。
//
// 旧实现里门控与检测共用 worker，一个慢接口会让队列里几百条本该秒清的便宜事务
// 一起停滞——这正是拆池要根治的问题。
func TestEngineGateSurvivesSlowDetection(t *testing.T) {
	release := make(chan struct{})
	slow := &funcDetector{
		name: "slow",
		interestFn: func(tx *CapturedTransaction) bool {
			return tx.Request.URL != nil && tx.Request.URL.Path == "/slow"
		},
		detectFn: func(context.Context, *CapturedTransaction, Prober) ([]Finding, error) {
			<-release
			return nil, nil
		},
	}
	var mu sync.Mutex
	var verdicts []TrafficVerdict
	eng := NewEngine(EngineOptions{
		Detectors:       []Detector{slow},
		Prober:          &noopProber{},
		Workers:         2,
		DetectWorkers:   1,
		DetectQueueSize: 1,
		QueueSize:       8,
		OnTraffic: func(ev TrafficEvent) {
			mu.Lock()
			verdicts = append(verdicts, ev.Verdict)
			mu.Unlock()
		},
	})
	eng.Start(context.Background())
	defer eng.Close()

	// 让检测池被一条慢检测占满。
	eng.Submit(txAt(t, "http://example.com/slow?id=1"))
	waitFor(t, func() bool { return eng.Stats().DetectInFlight == 1 })

	// 此时门控入口必须仍能照常消化流量：一条没有检测器感兴趣的请求应被立即处理完。
	eng.Submit(txAt(t, "http://example.com/fast"))
	waitFor(t, func() bool { return eng.Stats().Handled >= 2 })

	// 慢检测仍在飞——证明上面那句「已处理」不是靠等它结束换来的。
	if got := eng.Stats().DetectInFlight; got != 1 {
		t.Fatalf("DetectInFlight = %d, want 1（慢检测应仍在进行，门控却已放行后续流量）", got)
	}

	mu.Lock()
	sawNoInterest := false
	for _, v := range verdicts {
		if v == VerdictNoInterest {
			sawNoInterest = true
		}
	}
	mu.Unlock()
	if !sawNoInterest {
		t.Fatalf("未观察到 no-interest 结论，门控可能未独立于检测运行")
	}

	close(release)
}

// TestEngineDropsDetectQueueOverflow 锁定「已确认需要检测却因检测能力饱和被丢弃」
// 必须独立可观测——它与入口丢弃不同，直接对应漏报风险。
func TestEngineDropsDetectQueueOverflow(t *testing.T) {
	release := make(chan struct{})
	slow := &funcDetector{
		name:       "slow",
		interestFn: func(*CapturedTransaction) bool { return true },
		detectFn: func(context.Context, *CapturedTransaction, Prober) ([]Finding, error) {
			<-release
			return nil, nil
		},
	}
	var mu sync.Mutex
	var verdicts []TrafficVerdict
	eng := NewEngine(EngineOptions{
		Detectors:       []Detector{slow},
		Prober:          &noopProber{},
		Workers:         1,
		DetectWorkers:   1,
		DetectQueueSize: 1,
		QueueSize:       8,
		OnTraffic: func(ev TrafficEvent) {
			mu.Lock()
			verdicts = append(verdicts, ev.Verdict)
			mu.Unlock()
		},
	})
	eng.Start(context.Background())
	defer eng.Close()

	eng.Submit(txAt(t, "http://example.com/a?id=1"))
	waitFor(t, func() bool { return eng.Stats().DetectInFlight == 1 })

	eng.Submit(txAt(t, "http://example.com/b?id=1")) // 占满检测队列
	waitFor(t, func() bool { return eng.Stats().Forwarded == 2 })

	eng.Submit(txAt(t, "http://example.com/c?id=1")) // 溢出 -> 丢弃
	waitFor(t, func() bool { return eng.Stats().DroppedDetect >= 1 })

	if got := eng.Stats().Dropped; got != 0 {
		t.Fatalf("Dropped = %d, want 0（入口未满，丢弃应算在检测队列头上）", got)
	}

	mu.Lock()
	sawDroppedDetect := false
	for _, v := range verdicts {
		if v == VerdictDroppedDetect {
			sawDroppedDetect = true
		}
	}
	mu.Unlock()
	if !sawDroppedDetect {
		t.Fatalf("未观察到 dropped-detect 结论，检测队列丢弃必须显式可观测")
	}

	close(release)
}

type noopProber struct{}

func (n *noopProber) Replay(context.Context, *CapturedTransaction) (*CapturedResponse, error) {
	return &CapturedResponse{Status: 200}, nil
}

func (n *noopProber) Mutate(context.Context, *CapturedTransaction, Mutation) (*CapturedResponse, error) {
	return &CapturedResponse{Status: 200}, nil
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met before deadline")
}
