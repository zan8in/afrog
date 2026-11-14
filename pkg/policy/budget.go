package policy

import (
	"errors"
	"sync"
	"time"
)

// ErrBudgetExceeded 表示本次会话的请求数或时间预算已经用完。
var ErrBudgetExceeded = errors.New("policy: budget exceeded")

// Budget 是单次会话的运行期预算计数器（线程安全）。
//
// 它与 Policy 分离：Policy 是可复用的配置，预算是一次会话的消耗状态。
type Budget struct {
	mu       sync.Mutex
	left     int
	unbound  bool
	deadline time.Time
	hasLimit bool
}

// NewBudget 按策略里的预算创建一个会话计数器。
func NewBudget(limits Limits, now time.Time) *Budget {
	b := &Budget{}
	if limits.Requests <= 0 {
		b.unbound = true
	} else {
		b.left = limits.Requests
	}
	if d := limits.Duration.Duration(); d > 0 {
		b.deadline = now.Add(d)
		b.hasLimit = true
	}
	return b
}

// Take 申请 n 次请求额度；超限时返回 ErrBudgetExceeded 且不扣减。
//
// n == 0 表示该动作不产生网络请求（读库、查证据、校验草稿）：只校验时间预算，
// 不消耗请求额度。把它当成 1 会让 Agent 光靠读结果就把会话额度耗光。
func (b *Budget) Take(n int) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.hasLimit && !time.Now().Before(b.deadline) {
		return ErrBudgetExceeded
	}
	if n <= 0 || b.unbound {
		return nil
	}
	if n > b.left {
		return ErrBudgetExceeded
	}
	b.left -= n
	return nil
}

// Remaining 返回剩余请求数；-1 表示不限。
func (b *Budget) Remaining() int {
	if b == nil {
		return -1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.unbound {
		return -1
	}
	return b.left
}

// Deadline 返回预算截止时间；零值表示不限时。
func (b *Budget) Deadline() time.Time {
	if b == nil {
		return time.Time{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.deadline
}
