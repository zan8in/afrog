package config

import (
	"fmt"
	"testing"

	sliceutil "github.com/zan8in/pins/slice"
)

// activeTargetNum 与 pkg/runner.ActiveTarget 取值一致（-99）：表示该目标已通过协议校验。
// 这里单独写一份是为了让 pkg/config 不必反向依赖 pkg/runner。
const activeTargetNum = -99

func TestTargetSet_BasicSemantics(t *testing.T) {
	var ts TargetSet

	if got := ts.Num("missing"); got != 0 {
		t.Fatalf("未命中的项应返回 0，实际 %d", got)
	}
	// 与 SafeSlice 一致：对不存在的项 SetNum/UpdateNum/ResetNum 都是空操作
	ts.SetNum("missing", 7)
	ts.UpdateNum("missing", 1)
	ts.ResetNum("missing")
	if ts.Len() != 0 {
		t.Fatalf("空集合长度应为 0，实际 %d", ts.Len())
	}

	for _, target := range []string{"http://a.example", "http://b.example", "10.0.0.1"} {
		ts.Append(target)
	}
	if ts.Len() != 3 {
		t.Fatalf("Len = %d，期望 3", ts.Len())
	}
	if got := ts.List(); len(got) != 3 || got[0] != "http://a.example" || got[2] != "10.0.0.1" {
		t.Fatalf("List 应保持插入顺序：%v", got)
	}

	// 状态计数：SetNum 覆盖、UpdateNum 累加
	ts.SetNum("http://a.example", activeTargetNum)
	if got := ts.Num("http://a.example"); got != activeTargetNum {
		t.Fatalf("SetNum 后应读到 %d，实际 %d", activeTargetNum, got)
	}
	ts.UpdateNum("http://b.example", 1)
	ts.UpdateNum("http://b.example", 1)
	if got := ts.Num("http://b.example"); got != 2 {
		t.Fatalf("UpdateNum 应累加，实际 %d", got)
	}
	ts.ResetNum("http://b.example")
	if got := ts.Num("http://b.example"); got != 0 {
		t.Fatalf("ResetNum 后应为 0，实际 %d", got)
	}

	// Key / Get / Update 的下标语义
	if idx := ts.Key("http://b.example"); idx != 1 {
		t.Fatalf("Key = %d，期望 1", idx)
	}
	if idx := ts.Key("not-exist"); idx != -1 {
		t.Fatalf("未命中的 Key 应为 -1，实际 %d", idx)
	}
	if v := ts.Get(2); v != "10.0.0.1" {
		t.Fatalf("Get(2) = %v", v)
	}
	ts.Update(2, "http://c.example")
	if ts.Num("10.0.0.1") != 0 || ts.Key("10.0.0.1") != -1 {
		t.Fatal("Update 后旧值不应再能被查到")
	}
	if idx := ts.Key("http://c.example"); idx != 2 {
		t.Fatalf("Update 后应能按新值查到下标 2，实际 %d", idx)
	}

	// Iter 逐个吐出全部值
	seen := 0
	for range ts.Iter() {
		seen++
	}
	if seen != 3 {
		t.Fatalf("Iter 产出 %d 项，期望 3", seen)
	}
}

// 重复目标要按「首次出现」生效，这与原先线性扫描的语义一致。
func TestTargetSet_DuplicateKeepsFirstMatch(t *testing.T) {
	var ts TargetSet
	ts.Append("http://dup.example")
	ts.Append("http://dup.example")

	if ts.Len() != 2 {
		t.Fatalf("重复值都应保留在列表里，Len = %d", ts.Len())
	}
	if idx := ts.Key("http://dup.example"); idx != 0 {
		t.Fatalf("Key 应指向首次出现的下标 0，实际 %d", idx)
	}
	ts.UpdateNum("http://dup.example", 5)
	if got := ts.Num("http://dup.example"); got != 5 {
		t.Fatalf("Num = %d，期望 5", got)
	}
	// 只应改到首项，重复项保持原样
	if ts.items[1].num != 0 {
		t.Fatalf("重复项不应被 UpdateNum 改动，实际 num=%d", ts.items[1].num)
	}
}

// 与 zan8in/pins 的 SafeSlice 做同序列对比：换实现不能改变任何可观察行为。
// 原来的 O(n) 实现保留在这里当基准，避免以后又把索引去掉。
func TestTargetSet_ParityWithSafeSlice(t *testing.T) {
	var ts TargetSet
	var ss sliceutil.SafeSlice

	ops := []struct {
		kind string
		item string
		num  int
		idx  int
	}{
		{"append", "http://a.example", 0, 0},
		{"append", "http://b.example", 0, 0},
		{"set", "http://a.example", ActiveTargetState, 0},
		{"append", "http://a.example", 0, 0},
		{"update", "http://a.example", 0, 0},
		{"add", "http://b.example", 2, 0},
		{"reset", "http://b.example", 0, 0},
		{"set", "missing", 9, 0},
		{"add", "missing", 1, 0},
	}
	for _, op := range ops {
		switch op.kind {
		case "append":
			ts.Append(op.item)
			ss.Append(op.item)
		case "set":
			ts.SetNum(op.item, op.num)
			ss.SetNum(op.item, op.num)
		case "add":
			ts.UpdateNum(op.item, op.num)
			ss.UpdateNum(op.item, op.num)
		case "reset":
			ts.ResetNum(op.item)
			ss.ResetNum(op.item)
		case "update":
			ts.Update(0, op.item)
			ss.Update(0, op.item)
		}
	}

	if ts.Len() != ss.Len() {
		t.Fatalf("Len 不一致：TargetSet=%d SafeSlice=%d", ts.Len(), ss.Len())
	}
	for _, item := range []string{"http://a.example", "http://b.example", "missing", "http://c.example"} {
		if got, want := ts.Num(item), ss.Num(item); got != want {
			t.Fatalf("Num(%q) 不一致：TargetSet=%d SafeSlice=%d", item, got, want)
		}
		if got, want := ts.Key(item), ss.Key(item); got != want {
			t.Fatalf("Key(%q) 不一致：TargetSet=%d SafeSlice=%d", item, got, want)
		}
	}
	got, want := ts.List(), ss.List()
	if len(got) != len(want) {
		t.Fatalf("List 长度不一致：%d vs %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("List[%d] 不一致：%v vs %v", i, got[i], want[i])
		}
	}
}

// ActiveTargetState 与 pkg/runner 的 ActiveTarget 取值一致（-99）：
// 这里单独定义是为了让 pkg/config 不必反向依赖 pkg/runner。
const ActiveTargetState = -99

func buildTargetSet(n int) TargetSet {
	var ts TargetSet
	for i := 0; i < n; i++ {
		ts.Append(fmt.Sprintf("http://host-%d.example", i))
	}
	return ts
}

func buildSafeSlice(n int) sliceutil.SafeSlice {
	var ss sliceutil.SafeSlice
	for i := 0; i < n; i++ {
		ss.Append(fmt.Sprintf("http://host-%d.example", i))
	}
	return ss
}

const targetSetBenchSize = 5000

// 扫描热路径的核心查询：5000 资产规模下单次查找的成本。
func BenchmarkTargetSetNum(b *testing.B) {
	ts := buildTargetSet(targetSetBenchSize)
	probe := fmt.Sprintf("http://host-%d.example", targetSetBenchSize/2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ts.Num(probe)
	}
}

func BenchmarkSafeSliceNum(b *testing.B) {
	ss := buildSafeSlice(targetSetBenchSize)
	probe := fmt.Sprintf("http://host-%d.example", targetSetBenchSize/2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ss.Num(probe)
	}
}

// 最坏情况：查询一个不存在的目标（原先要扫完整个列表）。
func BenchmarkTargetSetNumMissing(b *testing.B) {
	ts := buildTargetSet(targetSetBenchSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ts.Num("http://not-in-list.example")
	}
}

func BenchmarkSafeSliceNumMissing(b *testing.B) {
	ss := buildSafeSlice(targetSetBenchSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ss.Num("http://not-in-list.example")
	}
}
