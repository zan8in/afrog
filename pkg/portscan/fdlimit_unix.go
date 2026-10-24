//go:build unix

package portscan

import (
	"errors"
	"syscall"
)

// fdReserve 是从进程 fd 上限里留给扫描之外用途的余量：报告文件、日志、web 监听、
// DNS/TLS 连接等。不预留的话，扫描把 fd 吃满会让这些操作跟着一起失败。
const fdReserve = 128

// minScanBudget 是预算被压到极低时的地板。fd 上限小到连这个都放不下时，与其把
// 并发收敛到接近 1（扫描退化成不可用），不如保住一个能跑通的量级，让运行时的
// EMFILE 退让去兜底。
const minScanBudget = 32

// maxFDSanity 是「这不算限制」的判定阈值，同时是提升软上限时的目标封顶。
// 超过它（例如 Linux 的 RLIM_INFINITY）说明系统没有实际约束，提升到这么大的值
// 反而会让预算计算失去意义。
const maxFDSanity = 1 << 20

// fdScanBudget 返回本进程保留 fdReserve 余量后还能同时用于扫描的探测数。
// 返回 0 表示拿不到限制或没有实质限制，调用方应保持用户配置的并发。
func fdScanBudget() int {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 0
	}
	cur := int64(lim.Cur)
	// RLIM_INFINITY 转成 int64 是负数；0 与超大值同理，都视为没有限制。
	if cur <= 0 || cur > maxFDSanity {
		return 0
	}
	budget := int(cur) - fdReserve
	if budget < minScanBudget {
		budget = minScanBudget
	}
	return budget
}

// raiseFDLimit 尝试把软上限提到硬上限（nmap 的做法），提不动就静默返回，
// 由预算收敛兜底。返回新的软上限与是否发生了提升。
func raiseFDLimit() (uint64, bool) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 0, false
	}
	if lim.Cur >= lim.Max {
		return lim.Cur, false
	}
	target := lim.Max
	if target > maxFDSanity {
		target = maxFDSanity
	}
	if target <= lim.Cur {
		return lim.Cur, false
	}
	lim.Cur = target
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 0, false
	}
	return target, true
}

// isFDExhausted 判断错误是否为本机 fd 耗尽，而不是目标行为。
func isFDExhausted(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE)
}

// fdAdvice 给出 Unix 下的处置建议：fd 耗尽的根因是软上限太低，先抬 ulimit 再降并发。
func fdAdvice() string { return "raise ulimit -n or lower -prate" }
