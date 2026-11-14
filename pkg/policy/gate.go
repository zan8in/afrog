package policy

import (
	"errors"
	"fmt"
)

// ErrDenied 表示动作被策略拒绝（区别于预算耗尽）。调用方可用 errors.Is 区分二者，
// 例如 REST 把前者映射成 403、后者映射成 429。
var ErrDenied = errors.New("policy denied")

// Gate 把「策略判定 + 预算扣减 + 审计」收在一处，供 MCP、REST 等工具面共用。
//
// 它是无状态协调者：Policy 是可复用配置，Budget 是一次会话的消耗状态，
// Auditor 是落盘流。判定顺序固定为 策略 → 预算 → 审计，拒绝必须带结构化原因，
// 避免调用方把「没被允许」误当成「没做」。
type Gate struct {
	policy  *Policy
	budget  *Budget
	auditor *Auditor
}

// NewGate 组装一个门控。policy 为空时退回只读默认；budget / auditor 可为 nil
// （分别表示不限额、不记录）。
func NewGate(p *Policy, b *Budget, a *Auditor) *Gate {
	if p == nil {
		p = Default()
	}
	return &Gate{policy: p, budget: b, auditor: a}
}

// Policy 返回底层策略，供需要读取 mode / audit 等字段的调用方使用。
func (g *Gate) Policy() *Policy {
	if g == nil || g.policy == nil {
		return Default()
	}
	return g.policy
}

// Budget 返回底层预算计数器；可能为 nil（表示不限额）。
func (g *Gate) Budget() *Budget {
	if g == nil {
		return nil
	}
	return g.budget
}

// Take 执行策略判定 + 预算扣减 + 审计。任一项不通过都返回带原因的错误：
// 策略拒绝返回包装了 ErrDenied 的错误，预算耗尽返回 ErrBudgetExceeded。
func (g *Gate) Take(a Action, requests int) error {
	if g == nil {
		return nil
	}
	v := g.Policy().Evaluate(a)
	if !v.Allow {
		g.audit(a, false, v.Rule, v.Reason)
		return fmt.Errorf("%w action %q: %s", ErrDenied, a.Name, v.Reason)
	}
	if err := g.budget.Take(requests); err != nil {
		g.audit(a, false, "budget", err.Error())
		return err
	}
	// 审计放在扣减之后，记录的才是真正可用的剩余额度。
	g.audit(a, true, v.Rule, v.Reason)
	return nil
}

func (g *Gate) audit(a Action, allow bool, rule, reason string) {
	if g.auditor == nil || !g.Policy().Audit {
		return
	}
	_ = g.auditor.Record(Record{
		Action:     a.Name,
		Target:     a.Target,
		Allow:      allow,
		Rule:       rule,
		Reason:     reason,
		BudgetLeft: g.budget.Remaining(),
	})
}
