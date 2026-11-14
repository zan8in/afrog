package passive

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"testing"
)

// coverageRecorder 收集引擎上报的覆盖度信号，用锁保护以便在 worker 协程中写入。
type coverageRecorder struct {
	mu   sync.Mutex
	sigs []CoverageSignal
}

func (r *coverageRecorder) add(sig CoverageSignal) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sigs = append(r.sigs, sig)
}

func (r *coverageRecorder) find(detector string) (CoverageSignal, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sigs {
		if s.Detector == detector {
			return s, true
		}
	}
	return CoverageSignal{}, false
}

func (r *coverageRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sigs)
}

// fakeLocalDetector 声明自己是本地类，用于验证本地阶段也会产生覆盖度。
type fakeLocalDetector struct {
	name     string
	interest bool
	findings []Finding
}

func (f *fakeLocalDetector) Name() string                       { return f.name }
func (f *fakeLocalDetector) Interest(*CapturedTransaction) bool { return f.interest }
func (f *fakeLocalDetector) CostClass() CostClass               { return CostLocal }
func (f *fakeLocalDetector) Detect(context.Context, *CapturedTransaction, Prober) ([]Finding, error) {
	return f.findings, nil
}

// fakeExtractor 用于验证提取器的覆盖度也被记录。
type fakeExtractor struct {
	name     string
	interest bool
}

func (f *fakeExtractor) Name() string                       { return f.name }
func (f *fakeExtractor) Interest(*CapturedTransaction) bool { return f.interest }
func (f *fakeExtractor) Extract(*CapturedTransaction) []Extraction {
	return nil
}

func coverageTransaction(method, rawURL string) *CapturedTransaction {
	u, _ := url.Parse(rawURL)
	return &CapturedTransaction{
		ID:      "tx-coverage",
		Request: &CapturedRequest{Method: method, URL: u, Headers: http.Header{}},
	}
}

// TestEngineCoverageSkippedWhenNotInterested 锁定「不感兴趣」也要进覆盖度台账。
//
// 这是覆盖度最有价值的一类：请求确实到达了检测器，但检测器认为它不具备条件。
// 如果这里不记，使用者只会看到某资产「没有记录」，无从判断是没流量还是被拒绝。
func TestEngineCoverageSkippedWhenNotInterested(t *testing.T) {
	rec := &coverageRecorder{}
	eng := NewEngine(EngineOptions{
		Detectors:  []Detector{&fakeDetector{name: "fake", interest: false}},
		Prober:     &noopProber{},
		Workers:    1,
		OnCoverage: rec.add,
	})
	eng.Start(context.Background())
	defer eng.Close()

	eng.Submit(coverageTransaction("GET", "https://Example.COM/api?id=1"))
	waitFor(t, func() bool { return rec.count() > 0 })

	sig, ok := rec.find("fake")
	if !ok {
		t.Fatalf("没有收到 fake 的覆盖度信号")
	}
	if sig.Target != "example.com" {
		t.Fatalf("Target = %q, want example.com（authority 口径、小写）", sig.Target)
	}
	if sig.State != CoverageSkipped {
		t.Fatalf("State = %q, want %q", sig.State, CoverageSkipped)
	}
	if sig.Reason == "" {
		t.Fatalf("跳过必须带原因，否则使用者无法判断为什么没测")
	}
}

// TestEngineCoverageHitAndTested 锁定本地阶段的两类结论：命中与已执行无结论。
func TestEngineCoverageHitAndTested(t *testing.T) {
	rec := &coverageRecorder{}
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{
			&fakeLocalDetector{name: "local-hit", interest: true, findings: []Finding{{
				Detector:   "local-hit",
				VulnType:   "misconfig",
				Confidence: ConfidenceCertain,
				Target:     "https://a.example",
				Location:   "response-header",
			}}},
			&fakeLocalDetector{name: "local-clean", interest: true},
		},
		Extractors: []Extractor{&fakeExtractor{name: "extract", interest: true}},
		Prober:     &noopProber{},
		Workers:    1,
		OnCoverage: rec.add,
	})
	eng.Start(context.Background())
	defer eng.Close()

	eng.Submit(coverageTransaction("GET", "https://a.example/"))
	waitFor(t, func() bool { return rec.count() >= 3 })

	if sig, ok := rec.find("local-hit"); !ok || sig.State != CoverageHit {
		t.Fatalf("local-hit 覆盖度 = %+v, want hit", sig)
	}
	if sig, ok := rec.find("local-clean"); !ok || sig.State != CoverageTested {
		t.Fatalf("local-clean 覆盖度 = %+v, want tested", sig)
	}
	if sig, ok := rec.find("extract"); !ok || sig.State != CoverageTested {
		t.Fatalf("extract 覆盖度 = %+v, want tested", sig)
	}
}

// TestEngineCoverageStaticSkipsNetworkOnly 锁定静态资源的口径：
// 网络类检测器记 skipped，本地类照常 tested。
func TestEngineCoverageStaticSkipsNetworkOnly(t *testing.T) {
	rec := &coverageRecorder{}
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{
			&fakeDetector{name: "network", interest: true},
			&fakeLocalDetector{name: "local", interest: true},
		},
		Prober:     &noopProber{},
		Workers:    1,
		OnCoverage: rec.add,
	})
	eng.Start(context.Background())
	defer eng.Close()

	tx := coverageTransaction("GET", "https://cdn.example/app.js")
	tx.Static = true
	eng.Submit(tx)
	waitFor(t, func() bool { return rec.count() >= 2 })

	if sig, ok := rec.find("network"); !ok || sig.State != CoverageSkipped {
		t.Fatalf("network 覆盖度 = %+v, want skipped", sig)
	}
	if sig, ok := rec.find("local"); !ok || sig.State != CoverageTested {
		t.Fatalf("local 覆盖度 = %+v, want tested", sig)
	}
}

// TestCoverageTargetFallsBackToHostHeader 锁定 MITM 隧道场景：
// URL.Host 为空时必须回退到 Host 头，否则覆盖度会出现「有流量但没有资产」的空洞。
func TestCoverageTargetFallsBackToHostHeader(t *testing.T) {
	tx := &CapturedTransaction{
		Request: &CapturedRequest{
			Method:  "GET",
			URL:     &url.URL{Path: "/api"},
			Headers: http.Header{"Host": []string{"Fallback.Example:8443"}},
		},
	}
	if got := coverageTarget(tx); got != "fallback.example:8443" {
		t.Fatalf("coverageTarget = %q, want fallback.example:8443", got)
	}
}
