package web

import (
	"fmt"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/passive"
)

// TestPassiveTrafficRingKeepsNewest 锁定环形缓冲的语义：
// 超出容量后必须保留最新记录，且顺序为「新在前」——排查问题看的永远是最新流量。
func TestPassiveTrafficRingKeepsNewest(t *testing.T) {
	l := &passiveTrafficLog{}
	total := passiveTrafficLimit + 100
	for i := 0; i < total; i++ {
		l.add(passive.TrafficEvent{ID: fmt.Sprint(i), Verdict: passive.VerdictNoInterest})
	}

	items, counts := l.snapshot(10, "")
	if counts.Total != uint64(total) {
		t.Fatalf("counts.Total = %d, want %d（计数不受缓冲容量影响）", counts.Total, total)
	}
	if len(items) != 10 {
		t.Fatalf("items = %d, want 10", len(items))
	}
	for i, ev := range items {
		want := fmt.Sprint(total - 1 - i)
		if ev.ID != want {
			t.Fatalf("items[%d].ID = %q, want %q（应为最新在前）", i, ev.ID, want)
		}
	}
}

// TestPassiveTrafficCountsByVerdict 锁定分类计数：
// 使用者要能一眼看出「多少条被当成静态资源放过了」。
func TestPassiveTrafficCountsByVerdict(t *testing.T) {
	l := &passiveTrafficLog{}
	l.add(passive.TrafficEvent{Verdict: passive.VerdictSkippedStatic})
	l.add(passive.TrafficEvent{Verdict: passive.VerdictSkippedStatic})
	l.add(passive.TrafficEvent{Verdict: passive.VerdictSkippedMethod})
	l.add(passive.TrafficEvent{Verdict: passive.VerdictNoInterest})
	l.add(passive.TrafficEvent{Verdict: passive.VerdictNoFinding})
	l.add(passive.TrafficEvent{Verdict: passive.VerdictFinding})
	l.add(passive.TrafficEvent{Verdict: passive.VerdictDropped})
	l.add(passive.TrafficEvent{Verdict: passive.VerdictError})

	_, c := l.snapshot(10, "")
	if c.Total != 8 {
		t.Fatalf("Total = %d, want 8", c.Total)
	}
	if c.SkippedStatic != 2 || c.SkippedMethod != 1 {
		t.Fatalf("skipped counts = %+v", c)
	}
	if c.NoInterest != 1 || c.NoFinding != 1 || c.Finding != 1 || c.Dropped != 1 || c.Error != 1 {
		t.Fatalf("verdict counts = %+v", c)
	}

	items, _ := l.snapshot(10, string(passive.VerdictSkippedStatic))
	if len(items) != 2 {
		t.Fatalf("filtered items = %d, want 2", len(items))
	}
}

// TestPassiveTrafficErrorsNewestFirst 锁定诊断页异常列表的展示顺序。
func TestPassiveTrafficErrorsNewestFirst(t *testing.T) {
	l := &passiveTrafficLog{}
	l.recordError("proxy", fmt.Errorf("第一次"))
	l.recordError("engine", fmt.Errorf("第二次"))

	errs := l.diagnosticsErrors()
	if len(errs) != 2 {
		t.Fatalf("errors = %d, want 2", len(errs))
	}
	if errs[0].Detail != "第二次" || errs[0].Scope != "engine" {
		t.Fatalf("errors[0] = %+v, want 最新在前", errs[0])
	}
}

// TestPassiveHintsGuideNextStep 锁定「下一步建议」：
// 这是把数字翻译成动作的地方，必须覆盖用户遇到的每一种「不知道怎么办」。
func TestPassiveHintsGuideNextStep(t *testing.T) {
	t.Run("未启动", func(t *testing.T) {
		hints := passiveHints(passiveDiagnostics{Running: false})
		if len(hints) != 1 || !contains(hints[0], "未启动") {
			t.Fatalf("hints = %v", hints)
		}
	})

	t.Run("无流量", func(t *testing.T) {
		hints := passiveHints(passiveDiagnostics{Running: true, Addr: "127.0.0.1:16869"})
		if !hasHint(hints, "尚未看到任何流量") || !hasHint(hints, "127.0.0.1:16869") {
			t.Fatalf("hints = %v", hints)
		}
	})

	t.Run("只有静态资源", func(t *testing.T) {
		hints := passiveHints(passiveDiagnostics{
			Running: true,
			Addr:    "127.0.0.1:16869",
			Counts:  passiveTrafficCounts{Total: 380, SkippedStatic: 380},
		})
		if !hasHint(hints, "只看到静态资源") {
			t.Fatalf("hints = %v", hints)
		}
	})

	t.Run("进了调度但没检测", func(t *testing.T) {
		hints := passiveHints(passiveDiagnostics{
			Running: true,
			Counts:  passiveTrafficCounts{Total: 10, NoInterest: 10},
			Stats:   passive.Stats{Submitted: 10, Inspected: 0},
		})
		if !hasHint(hints, "没有一条通过检测条件") {
			t.Fatalf("hints = %v", hints)
		}
	})

	t.Run("检测了但无结论", func(t *testing.T) {
		hints := passiveHints(passiveDiagnostics{
			Running: true,
			Counts:  passiveTrafficCounts{Total: 10, NoFinding: 10},
			Stats:   passive.Stats{Submitted: 10, Inspected: 10},
		})
		if !hasHint(hints, "检测已执行但无结论") {
			t.Fatalf("hints = %v", hints)
		}
	})

	t.Run("证书过期", func(t *testing.T) {
		hints := passiveHints(passiveDiagnostics{
			Running: true,
			Counts:  passiveTrafficCounts{Total: 1, SkippedStatic: 1},
			CA:      passiveCAView{Exists: true, DaysLeft: -1},
		})
		if !hasHint(hints, "已过期") {
			t.Fatalf("hints = %v", hints)
		}
	})

	t.Run("上限与默认提示", func(t *testing.T) {
		hints := passiveHints(passiveDiagnostics{
			Running: true,
			Counts:  passiveTrafficCounts{Total: 1, SkippedStatic: 1},
			Stats:   passive.Stats{Submitted: 1},
			CA:      passiveCAView{Exists: true, DaysLeft: 3000},
		})
		if len(hints) > 6 {
			t.Fatalf("hints 数量 = %d, 应封顶 6 条", len(hints))
		}
		if !hasHint(hints, "根证书") {
			t.Fatalf("hints = %v, 应始终包含证书信任提示", hints)
		}
	})
}

func hasHint(hints []string, sub string) bool {
	for _, h := range hints {
		if contains(h, sub) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}

// TestPassiveCAInfoOnEmptyDir 锁定：证书未生成时也必须返回可用的路径信息，
// 而不是让界面显示一片空白。
func TestPassiveCAInfoOnEmptyDir(t *testing.T) {
	dir := t.TempDir()
	view := passiveCAInfo(dir)

	if view.CertPath == "" || view.Dir != dir {
		t.Fatalf("ca view = %+v", view)
	}
	if !view.Exists {
		t.Fatalf("LoadOrCreateCA 应已生成证书文件: %+v", view)
	}
	if view.Fingerprint == "" || view.NotAfter == "" {
		t.Fatalf("证书信息不完整: %+v", view)
	}
	if view.DaysLeft <= 0 {
		t.Fatalf("DaysLeft = %d, 新证书应远未过期", view.DaysLeft)
	}
	if view.NotBefore == "" || view.NotAfter == "" {
		t.Fatalf("证书有效期缺失: %+v", view)
	}
}
