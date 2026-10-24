//go:build unix

package portscan

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

// TestIsFDExhaustedUnix 覆盖真实错误形态：net.OpError -> os.SyscallError -> errno。
// EMFILE/ENFILE 必须被识别成本机 fd 耗尽，而超时、连接拒绝等目标信号不能。
func TestIsFDExhaustedUnix(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"裸 EMFILE", syscall.EMFILE, true},
		{"裸 ENFILE", syscall.ENFILE, true},
		{
			"net.OpError 包裹 EMFILE",
			&net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("socket", syscall.EMFILE)},
			true,
		},
		{"超时不是 fd 耗尽", &net.OpError{Op: "dial", Net: "tcp", Err: fakeTimeoutErr{}}, false},
		{"连接拒绝不是 fd 耗尽", errConnRefused, false},
		{"无关错误", errors.New("no route to host"), false},
	}

	for _, c := range cases {
		if got := isFDExhausted(c.err); got != c.want {
			t.Errorf("%s: isFDExhausted = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestFDScanBudgetWithinSoftLimit 验证预算不会超过软上限，且留出了保留余量。
func TestFDScanBudgetWithinSoftLimit(t *testing.T) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Skipf("Getrlimit: %v", err)
	}
	budget := fdScanBudget()
	if budget == 0 {
		// 拿不到限制或无实质限制（RLIM_INFINITY）时返回 0，调用方保持用户配置。
		return
	}
	if int64(budget) > int64(lim.Cur) {
		t.Fatalf("budget = %d, exceeds soft limit %d", budget, lim.Cur)
	}
	if budget < minScanBudget {
		t.Fatalf("budget = %d, below floor %d", budget, minScanBudget)
	}
}

func TestFDAdviceNonEmpty(t *testing.T) {
	if fdAdvice() == "" {
		t.Fatal("fdAdvice returned empty string")
	}
}
