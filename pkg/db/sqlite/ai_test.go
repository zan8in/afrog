package sqlite

import (
	"testing"
	"time"
)

// 免费额度必须真的会拦住：达到上限后不放行，且不影响其他月份。
func TestTryUseAIQuota_EnforcesMonthlyLimit(t *testing.T) {
	withScanTaskFixture(t)

	month := AIMonthKey(time.Now())
	if len(month) != 7 {
		t.Fatalf("月份键格式不对: %q", month)
	}

	for i := 1; i <= 3; i++ {
		used, allowed, err := TryUseAIQuota(month, 3)
		if err != nil {
			t.Fatalf("第 %d 次占用失败: %v", i, err)
		}
		if !allowed || used != i {
			t.Fatalf("第 %d 次：used=%d allowed=%v，期望 used=%d allowed=true", i, used, allowed, i)
		}
	}

	used, allowed, err := TryUseAIQuota(month, 3)
	if err != nil {
		t.Fatalf("额度耗尽时不应报错: %v", err)
	}
	if allowed || used != 3 {
		t.Fatalf("超出上限仍被放行：used=%d allowed=%v", used, allowed)
	}

	// limit<=0 表示会员不限次：照常放行，但依然计数（界面要显示用量）。
	used, allowed, err = TryUseAIQuota(month, 0)
	if err != nil || !allowed || used != 4 {
		t.Fatalf("不限次场景：used=%d allowed=%v err=%v", used, allowed, err)
	}

	// 换个月份重新从 0 开始。
	used, allowed, err = TryUseAIQuota("2000-01", 3)
	if err != nil || !allowed || used != 1 {
		t.Fatalf("跨月计数应独立：used=%d allowed=%v err=%v", used, allowed, err)
	}

	got, err := AIUsage(month)
	if err != nil || got != 4 {
		t.Fatalf("AIUsage=%d err=%v，期望 4", got, err)
	}
	if n, err := AIUsage("1999-12"); err != nil || n != 0 {
		t.Fatalf("没有记录的月份应返回 0：n=%d err=%v", n, err)
	}
}

func TestAICache_RoundTripAndMiss(t *testing.T) {
	withScanTaskFixture(t)

	if _, ok, err := GetAICache("missing"); err != nil || ok {
		t.Fatalf("空库不该命中：ok=%v err=%v", ok, err)
	}

	if err := PutAICache("k1", "## 结论\n真实漏洞", "test-model"); err != nil {
		t.Fatalf("写缓存失败: %v", err)
	}
	content, ok, err := GetAICache("k1")
	if err != nil || !ok || content != "## 结论\n真实漏洞" {
		t.Fatalf("缓存回读失败：content=%q ok=%v err=%v", content, ok, err)
	}

	// 空内容不入缓存：否则崩在模型返回空串时会缓存一份空结论。
	if err := PutAICache("k2", "   ", "test-model"); err != nil {
		t.Fatalf("空内容写入不应报错: %v", err)
	}
	if _, ok, _ := GetAICache("k2"); ok {
		t.Fatal("空内容不该产生缓存")
	}
}

// 研判证据要取到该命中的原始请求/响应；查不到时返回 nil 而不是错误。
func TestSelectHitEvidence(t *testing.T) {
	withScanTaskFixture(t)

	resultJSON := `[{"fulltarget":"http://a.example/1","request":"GET / HTTP/1.1\nHost: a.example","response":"HTTP/1.1 200 OK\n\nok"}]`
	_, err := dbx.Exec(
		`INSERT INTO result(id, taskid, vulid, vulname, target, fulltarget, severity, poc, result, created, fingerprint, extractor)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '')`,
		9001, "t-ai", "poc-ai", "AI 测试 PoC", "http://a.example", "http://a.example/1", "High",
		`{"Id":"poc-ai","Info":{"Name":"AI 测试 PoC","Severity":"high"}}`,
		resultJSON, "2026-10-01 10:00:00")
	if err != nil {
		t.Fatalf("插入命中失败: %v", err)
	}

	ev, err := SelectHitEvidence("", "poc-ai", "http://a.example", "http://a.example/1")
	if err != nil {
		t.Fatalf("SelectHitEvidence: %v", err)
	}
	if ev == nil {
		t.Fatal("应取到证据")
	}
	if ev.VulName != "AI 测试 PoC" || ev.Severity != "HIGH" {
		t.Fatalf("元信息不对: %+v", ev)
	}
	if ev.Request == "" || ev.Response == "" {
		t.Fatalf("未取到原始请求/响应: %+v", ev)
	}
	if ev.Poc == "" {
		t.Fatal("应带回 PoC 元信息原文")
	}

	none, err := SelectHitEvidence("", "not-exist", "http://a.example", "")
	if err != nil {
		t.Fatalf("查不到时不该报错: %v", err)
	}
	if none != nil {
		t.Fatalf("查不到时应返回 nil，实际 %+v", none)
	}
}

// 摘要数据要：按任务收敛、按严重级别排序、带上人工状态与任务元信息。
func TestSelectSummaryData(t *testing.T) {
	withScanTaskFixture(t)

	// t-sum：critical 命中 2 次（同一条目）、high 1 条（已标误报）、low 1 条
	insertResult(t, dbx, 11, "t-sum", "poc-a", "http://a.example", "http://a.example/1", "critical", "2026-10-01 10:00:00")
	insertResult(t, dbx, 12, "t-sum", "poc-a", "http://a.example", "http://a.example/1", "critical", "2026-10-01 10:01:00")
	insertResult(t, dbx, 13, "t-sum", "poc-b", "http://a.example", "http://a.example/2", "high", "2026-10-01 10:02:00")
	insertResult(t, dbx, 14, "t-sum", "poc-c", "http://b.example", "http://b.example", "low", "2026-10-01 10:03:00")
	// 另一个任务的命中不能混进来
	insertResult(t, dbx, 15, "t-other", "poc-d", "http://c.example", "http://c.example", "critical", "2026-10-01 11:00:00")

	if err := UpsertLedgerStatus("poc-b", "http://a.example", "http://a.example/2", "false_positive", strPtr("")); err != nil {
		t.Fatalf("写入台账状态失败: %v", err)
	}
	if err := UpsertScanTask(sampleScanTask("t-sum", "2026-10-01 10:00:00")); err != nil {
		t.Fatalf("写入任务快照失败: %v", err)
	}

	data, err := SelectSummaryData("t-sum", "", "")
	if err != nil {
		t.Fatalf("SelectSummaryData: %v", err)
	}
	if data.Scope != "task" || data.TaskID != "t-sum" {
		t.Fatalf("范围不对: %+v", data)
	}
	if data.TaskName != "客户A每日巡检" || data.TaskSource != "schedule" {
		t.Fatalf("任务元信息不对: name=%q source=%q", data.TaskName, data.TaskSource)
	}
	if data.HitRows != 4 {
		t.Fatalf("原始命中记录 = %d，期望 4", data.HitRows)
	}
	dist := data.SeverityDist
	if dist["CRITICAL"] != 1 || dist["HIGH"] != 1 || dist["LOW"] != 1 || len(dist) != 3 {
		t.Fatalf("严重级别分布不对: %+v", dist)
	}
	if len(data.Findings) != 3 {
		t.Fatalf("条目数 = %d，期望 3（另一个任务的不该出现）: %+v", len(data.Findings), data.Findings)
	}
	if data.Findings[0].Severity != "CRITICAL" || data.Findings[0].HitCount != 2 {
		t.Fatalf("排序或聚合不对: %+v", data.Findings[0])
	}
	if data.Findings[1].Status != "false_positive" {
		t.Fatalf("人工状态未带上: %+v", data.Findings[1])
	}
	for _, f := range data.Findings {
		if f.VulID == "poc-d" {
			t.Fatal("跨任务命中泄漏进了单任务摘要")
		}
	}

	// 无任务 ID：按筛选汇总，范围要如实标记为 filter
	filtered, err := SelectSummaryData("", "", "poc-d")
	if err != nil {
		t.Fatalf("按筛选汇总失败: %v", err)
	}
	if filtered.Scope != "filter" || len(filtered.Findings) != 1 || filtered.Findings[0].VulID != "poc-d" {
		t.Fatalf("筛选汇总不对: %+v", filtered)
	}

	// 空结果不应报错（由调用方决定怎么提示）
	empty, err := SelectSummaryData("", "", "nothing-matches")
	if err != nil {
		t.Fatalf("空结果不该报错: %v", err)
	}
	if len(empty.Findings) != 0 || empty.HitRows != 0 {
		t.Fatalf("空结果应为空: %+v", empty)
	}
}
