package gating

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// maxReasonKinds 限制否定原因的种类数，避免异常 PoC 库把内存撑爆；超出后只累计
// 总数、不再细分工因，并在报告里标注「…」。
const maxReasonKinds = 200

// Stats 汇总一次扫描的门控归因：按 Decision.Source 计数，让「为什么跑 / 为什么跳」
// 可追溯。三端共享同一份统计（写入事件流的归因与打印出来的报告同源）。
//
// 计数口径是「决策次数」，即 (目标 × PoC) 组合数；一条 PoC 对多个目标分别决策，
// 这与引擎调度粒度一致，也解释了「实际执行任务 = requires + fallback」。
//
// Stats 并发安全：引擎在多个 worker 里调度，Record 会被并发调用。
type Stats struct {
	// loaded 是本次参与门控的 PoC 数（不含指纹 PoC）。
	loaded int

	requires int64
	negative int64
	fallback int64

	mu          sync.Mutex
	negReasons  map[string]int64
	reasonCount int64
}

// NewStats 创建一个归因统计器。
func NewStats() *Stats { return &Stats{} }

// SetLoaded 记录本次参与门控的 PoC 总数。
func (s *Stats) SetLoaded(n int) { s.loaded = n }

// Record 记录一条决策。
func (s *Stats) Record(d Decision) {
	if s == nil {
		return
	}
	switch d.Source {
	case SourceRequires:
		atomic.AddInt64(&s.requires, 1)
	case SourceNegative:
		atomic.AddInt64(&s.negative, 1)
		s.recordReason(d.Reason)
	default:
		atomic.AddInt64(&s.fallback, 1)
	}
}

// recordReason 汇总否定原因；原因种类超过上限后只计数不再细分。
func (s *Stats) recordReason(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	atomic.AddInt64(&s.reasonCount, 1)
	if s.negReasons == nil {
		s.negReasons = make(map[string]int64)
	}
	if _, ok := s.negReasons[reason]; !ok && len(s.negReasons) >= maxReasonKinds {
		return
	}
	s.negReasons[reason]++
}

// Requires 返回 requires 命中放行的决策数。
func (s *Stats) Requires() int64 { return atomic.LoadInt64(&s.requires) }

// Negative 返回否定证据跳过的决策数。
func (s *Stats) Negative() int64 { return atomic.LoadInt64(&s.negative) }

// Fallback 返回无证据兜底放行的决策数。
func (s *Stats) Fallback() int64 { return atomic.LoadInt64(&s.fallback) }

// Executed 返回实际执行（requires + fallback）的决策数。
func (s *Stats) Executed() int64 { return s.Requires() + s.Fallback() }

// Report 生成人可读的归因报告。dry-run 与 -debug 下打印，让「跳过」有据可查。
func (s *Stats) Report() string {
	if s == nil {
		return ""
	}
	req, neg, fb := s.Requires(), s.Negative(), s.Fallback()
	total := req + neg + fb

	var b strings.Builder
	fmt.Fprintf(&b, "门控归因 (决策次数 = 目标 × PoC):\n")
	fmt.Fprintf(&b, "  加载 PoC            : %d\n", s.loaded)
	fmt.Fprintf(&b, "  决策总数            : %d\n", total)
	fmt.Fprintf(&b, "  ├─ requires 命中放行 : %d\n", req)
	fmt.Fprintf(&b, "  ├─ 否定证据跳过      : %d\n", neg)
	fmt.Fprintf(&b, "  └─ 兜底放行          : %d\n", fb)
	fmt.Fprintf(&b, "  实际执行任务        : %d", s.Executed())

	reasons := s.topReasons()
	if len(reasons) > 0 {
		fmt.Fprintf(&b, "\n  跳过原因 Top:")
		for _, r := range reasons {
			fmt.Fprintf(&b, "\n    %6d  %s", r.count, r.reason)
		}
	}
	if atomic.LoadInt64(&s.reasonCount) > int64(len(reasons)) && len(reasons) >= maxReasonKinds {
		fmt.Fprintf(&b, "\n    …(原因种类超过 %d，其余未细分)", maxReasonKinds)
	}
	return b.String()
}

type reasonStat struct {
	reason string
	count  int64
}

// topReasons 返回按次数降序排列的否定原因（最多 10 条）。
func (s *Stats) topReasons() []reasonStat {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.negReasons) == 0 {
		return nil
	}
	out := make([]reasonStat, 0, len(s.negReasons))
	for reason, count := range s.negReasons {
		out = append(out, reasonStat{reason: reason, count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].reason < out[j].reason
	})
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}
