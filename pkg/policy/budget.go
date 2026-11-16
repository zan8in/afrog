package policy

import (
	"errors"
	"sync"
	"time"
)

// ErrBudgetExceeded 表示当前会话的请求额度已经用完。
var ErrBudgetExceeded = errors.New("policy: budget exceeded")

// Budget 是「空闲会话」的运行期预算计数器（线程安全）。
//
// 它与 Policy 分离：Policy 是可复用的配置，预算是一次会话的消耗状态。
//
// 会话边界由空闲时长界定：只要还有消耗额度的调用成功，空闲窗口就顺延；连续
// Duration 没有这样的调用，即判定会话结束，下一次调用自动开一个新会话、把请求
// 额度补满。长驻进程（Web 服务、`afrog mcp -listen`）因此既不会跑够一段时间就
// 整体失效，也不必为了恢复额度去重启——它空闲下来自己就重置了。
//
// 不产生网络请求的动作（读库、查证据、校验草稿）按 n<=0 调用：它们既不扣额度，
// 也不受任何预算限制，因此查证据永远不会被「额度」挡住。
type Budget struct {
	mu sync.Mutex
	// left 是当前会话剩余请求数；limit 是开新会话时补满到的值。
	left  int
	limit int
	// unbound 为真表示不限请求数。
	unbound bool
	// window 是空闲时长；deadline 是空闲到期时间，超过即判定会话结束。
	window    time.Duration
	deadline  time.Time
	hasWindow bool
}

// NewBudget 按策略里的预算创建一个会话计数器。
func NewBudget(limits Limits, now time.Time) *Budget {
	b := &Budget{}
	if limits.Requests <= 0 {
		b.unbound = true
	} else {
		b.left = limits.Requests
		b.limit = limits.Requests
	}
	if d := limits.Duration.Duration(); d > 0 {
		b.window = d
		b.deadline = now.Add(d)
		b.hasWindow = true
	}
	return b
}

// Take 申请 n 次请求额度。
//
// n <= 0 表示该动作不产生网络请求（读库、查证据、校验草稿）：直接放行，既不扣
// 额度也不顺延空闲窗口——否则 Agent 光靠轮询只读结果就能让额度永不重置。
//
// n > 0 时：若空闲已超时，先判定上个会话结束并开新会话（额度补满），再扣减；
// 额度不足返回 ErrBudgetExceeded，且不扣减、不顺延窗口。
func (b *Budget) Take(n int) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if n <= 0 {
		return nil
	}

	now := time.Now()
	if b.idleExpired(now) {
		// 空闲超时：上个会话已结束，这里开新会话。
		b.left = b.limit
	}
	if b.unbound {
		b.touch(now)
		return nil
	}
	if n > b.left {
		return ErrBudgetExceeded
	}
	b.left -= n
	b.touch(now)
	return nil
}

// Remaining 返回当前会话剩余请求数；-1 表示不限。
//
// 空闲已超时会立刻反映成「新会话的满额度」，避免控制台在两次调用之间显示一个
// 已经作废的 0。
func (b *Budget) Remaining() int {
	if b == nil {
		return -1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.unbound {
		return -1
	}
	if b.idleExpired(time.Now()) {
		return b.limit
	}
	return b.left
}

// Deadline 返回空闲到期时间；零值表示不限时。
func (b *Budget) Deadline() time.Time {
	if b == nil {
		return time.Time{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.deadline
}

// idleExpired 判断空闲窗口是否已经过期；没有时间预算时永不过期。
func (b *Budget) idleExpired(now time.Time) bool {
	return b.hasWindow && !now.Before(b.deadline)
}

// touch 把空闲窗口顺延到 now+window；没有时间预算时是空操作。
func (b *Budget) touch(now time.Time) {
	if b.hasWindow {
		b.deadline = now.Add(b.window)
	}
}
