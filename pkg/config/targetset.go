package config

import "sync"

// targetItem 是目标集合里的一项：value 是目标本身，num 是它的状态计数
// （协议校验通过时记为 ActiveTarget，扫描出错时累加错误次数）。
type targetItem struct {
	num   int
	value any
}

// TargetSet 是「目标 → 状态计数」的并发安全集合。
//
// 语义与 github.com/zan8in/pins/slice 的 SafeSlice 完全一致：保持插入顺序、
// 重复值以首次出现为准、未命中返回 0、SetNum/UpdateNum/ResetNum 只更新已存在的项。
// 区别只在于 Num / SetNum / UpdateNum / Key / Update 从 O(n) 线性扫描换成了 O(1) 索引查找。
//
// 为什么必须换：Checker.Check 的粒度是「每个目标 × 每个 PoC」，其内部 checkURL
// 每次都会对 Targets 做 1~2 次查找（见 pkg/runner/checker.go）。5000 资产 × 数百 PoC
// 就是数百万次查找，每次都要线性扫过整个目标列表、并且抢同一把 RWMutex：
// 退化成 O(目标数 × 扫描数) 之后，CPU 会被打满、worker 之间互相争锁。
type TargetSet struct {
	mu    sync.RWMutex
	items []targetItem
	// index 记录某个 value 首次出现的位置（与线性扫描的「首个匹配」语义一致）。
	index map[any]int
}

func (ts *TargetSet) Append(item any) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.index == nil {
		ts.index = make(map[any]int)
	}
	if _, ok := ts.index[item]; !ok {
		ts.index[item] = len(ts.items)
	}
	ts.items = append(ts.items, targetItem{value: item})
}

func (ts *TargetSet) Len() int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	return len(ts.items)
}

// idxLocked 返回 value 首次出现的位置，不存在返回 -1。调用方必须持有锁。
func (ts *TargetSet) idxLocked(item any) int {
	if i, ok := ts.index[item]; ok {
		return i
	}
	return -1
}

func (ts *TargetSet) Key(item any) int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	return ts.idxLocked(item)
}

func (ts *TargetSet) Get(index int) any {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	return ts.items[index].value
}

// Update 按下标替换值，同时维护索引：旧值的下标要释放，新值若尚未出现过则登记。
func (ts *TargetSet) Update(index int, item any) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.index == nil {
		ts.index = make(map[any]int)
	}
	if old := ts.items[index].value; old != item {
		if i, ok := ts.index[old]; ok && i == index {
			delete(ts.index, old)
		}
		if _, ok := ts.index[item]; !ok {
			ts.index[item] = index
		}
	}
	ts.items[index].value = item
}

func (ts *TargetSet) List() []any {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	r := make([]any, 0, len(ts.items))
	for _, v := range ts.items {
		r = append(r, v.value)
	}
	return r
}

// Iter 逐个吐出目标；遍历期间持有写锁，保证不会与 Append/Update 交错。
func (ts *TargetSet) Iter() chan any {
	ts.mu.Lock()

	out := make(chan any)

	go func() {
		defer close(out)
		defer ts.mu.Unlock()

		for _, item := range ts.items {
			out <- item.value
		}
	}()

	return out
}

func (ts *TargetSet) Num(item any) int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if i := ts.idxLocked(item); i >= 0 {
		return ts.items[i].num
	}
	return 0
}

func (ts *TargetSet) UpdateNum(item any, num int) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if i := ts.idxLocked(item); i >= 0 {
		ts.items[i].num += num
	}
}

func (ts *TargetSet) ResetNum(item any) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if i := ts.idxLocked(item); i >= 0 {
		ts.items[i].num = 0
	}
}

func (ts *TargetSet) SetNum(item any, num int) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if i := ts.idxLocked(item); i >= 0 {
		ts.items[i].num = num
	}
}
