package passive

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// reasonDetector 既能给出「不检测」的原因，也能返回预设结论，用于验证 TrafficEvent。
type reasonDetector struct {
	name     string
	interest bool
	reason   string
	findings []Finding
}

func (d *reasonDetector) Name() string { return d.name }

func (d *reasonDetector) Interest(*CapturedTransaction) bool { return d.interest }

func (d *reasonDetector) InterestReason(*CapturedTransaction) string { return d.reason }

func (d *reasonDetector) Detect(context.Context, *CapturedTransaction, Prober) ([]Finding, error) {
	return d.findings, nil
}

// trafficSink 收集调度层上报的流量结论。
type trafficSink struct {
	mu     sync.Mutex
	events []TrafficEvent
}

func (s *trafficSink) add(ev TrafficEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *trafficSink) wait(t *testing.T, n int) []TrafficEvent {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		if len(s.events) >= n {
			out := make([]TrafficEvent, len(s.events))
			copy(out, s.events)
			s.mu.Unlock()
			return out
		}
		s.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待 %d 条流量结论超时", n)
	return nil
}

// TestEngineReportsInterestReason 锁定「不检测」必须给出具体原因。
// 这是使用者能否看懂「捕获很多、检测为零」的关键。
func TestEngineReportsInterestReason(t *testing.T) {
	sink := &trafficSink{}
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{&reasonDetector{name: "sqli", interest: false, reason: "响应体仅 8 字节，小于检测下限 16 字节"}},
		Prober:    &noopProber{},
		Workers:   1,
		OnTraffic: sink.add,
	})
	eng.Start(context.Background())
	defer eng.Close()

	tx := newTestTransaction()
	tx.Response = &CapturedResponse{Status: 200}
	eng.Submit(tx)

	events := sink.wait(t, 1)
	ev := events[0]
	if ev.Verdict != VerdictNoInterest {
		t.Fatalf("verdict = %q, want %q", ev.Verdict, VerdictNoInterest)
	}
	if !strings.Contains(ev.Reason, "小于检测下限") {
		t.Fatalf("reason = %q, 缺少检测器给出的具体原因", ev.Reason)
	}
	if got := eng.Stats().Inspected; got != 0 {
		t.Fatalf("Inspected = %d, want 0（未通过门控不应计入已检测）", got)
	}
}

// TestEngineReportsNoFinding 锁定「检测跑了、没有结论」与「没有检测」的区别。
func TestEngineReportsNoFinding(t *testing.T) {
	sink := &trafficSink{}
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{&reasonDetector{name: "sqli", interest: true}},
		Prober:    &noopProber{},
		Workers:   1,
		OnTraffic: sink.add,
	})
	eng.Start(context.Background())
	defer eng.Close()

	eng.Submit(newTestTransaction())

	ev := sink.wait(t, 1)[0]
	if ev.Verdict != VerdictNoFinding {
		t.Fatalf("verdict = %q, want %q", ev.Verdict, VerdictNoFinding)
	}
	if len(ev.Detectors) != 1 || ev.Detectors[0] != "sqli" {
		t.Fatalf("detectors = %v, want [sqli]", ev.Detectors)
	}
	if got := eng.Stats().Inspected; got != 1 {
		t.Fatalf("Inspected = %d, want 1", got)
	}
}

// TestEngineReportsDropped 锁定队列满时也要落一条可观测记录，而不是静默丢弃。
func TestEngineReportsDropped(t *testing.T) {
	sink := &trafficSink{}
	eng := NewEngine(EngineOptions{
		Detectors: []Detector{&reasonDetector{name: "sqli", interest: true}},
		Prober:    &noopProber{},
		Workers:   1,
		QueueSize: 1,
		OnTraffic: sink.add,
	})
	// 未 Start：所有提交都会被丢弃，正好验证丢弃路径也会上报。

	if eng.Submit(newTestTransaction()) {
		t.Fatalf("未启动时不应接收事务")
	}

	ev := sink.wait(t, 1)[0]
	if ev.Verdict != VerdictDropped {
		t.Fatalf("verdict = %q, want %q", ev.Verdict, VerdictDropped)
	}
	if ev.Reason == "" {
		t.Fatalf("丢弃原因不能为空")
	}
}
