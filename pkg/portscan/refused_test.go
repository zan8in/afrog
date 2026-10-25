package portscan

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// fakeTimeoutErr 模拟 net.Error 形态的超时错误，用于验证超时不会
// 被误判成连接拒绝。
type fakeTimeoutErr struct{}

func (fakeTimeoutErr) Error() string   { return "dial tcp 10.0.0.1:3306: i/o timeout" }
func (fakeTimeoutErr) Timeout() bool   { return true }
func (fakeTimeoutErr) Temporary() bool { return false }

func TestIsConnRefused(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil 不算拒绝", nil, false},
		{"裸 errno", errConnRefused, true},
		// 真实形态：net.OpError -> os.SyscallError -> errno
		{
			"net.OpError 包裹 errno",
			&net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errConnRefused)},
			true,
		},
		{"超时不是拒绝", &net.OpError{Op: "dial", Net: "tcp", Err: fakeTimeoutErr{}}, false},
		{"无关错误不算拒绝", errors.New("no route to host"), false},
	}

	for _, c := range cases {
		if got := isConnRefused(c.err); got != c.want {
			t.Errorf("%s: isConnRefused = %v, want %v", c.name, got, c.want)
		}
	}
}

// 端口状态必须真正落地：默认只上报 open；打开 ReportStates（-ps-states）后，
// closed / filtered 才随结果输出，且两者不得被合并成同一状态。
func TestPortStateReporting(t *testing.T) {
	// 取一个确定关闭的回环端口：监听后立即关闭，之后的 connect 会拿到 RST，
	// 因此走的是 closed（而非 filtered）分支。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("atoi: %v", err)
	}
	_ = ln.Close()

	// collect 跑一次探测或直接上报给定状态，返回收集到的结果。
	collect := func(report bool, state PortState, probe bool) []*ScanResult {
		var got []*ScanResult
		s := &Scanner{options: &Options{
			Timeout:      300 * time.Millisecond,
			Retries:      0,
			ReportStates: report,
			OnResult:     func(r *ScanResult) { got = append(got, r) },
		}}
		if probe {
			s.scanTarget(context.Background(), "127.0.0.1", port)
		} else {
			s.maybeReportState("127.0.0.1", port, state)
		}
		return got
	}

	// 默认（ReportStates=false）：非开放端口不上报，避免淹没开放端口行。
	if got := collect(false, PortStateClosed, true); len(got) != 0 {
		t.Fatalf("closed reported without ReportStates: got %d results, want 0", len(got))
	}

	// 打开后：RST 判定的 closed 必须上报，且状态正确。
	got := collect(true, PortStateClosed, true)
	if len(got) != 1 {
		t.Fatalf("closed reported with ReportStates: got %d results, want 1", len(got))
	}
	if got[0].State != PortStateClosed {
		t.Fatalf("state = %v, want %v", got[0].State, PortStateClosed)
	}

	// filtered 必须保持独立状态，不能被并入 closed。
	fgot := collect(true, PortStateFiltered, false)
	if len(fgot) != 1 || fgot[0].State != PortStateFiltered {
		t.Fatalf("filtered result = %+v, want a single PortStateFiltered", fgot)
	}

	// 关闭开关时 filtered 也不上报，但计数仍要累计，供阶段汇总行使用。
	s := &Scanner{options: &Options{Timeout: 300 * time.Millisecond, Retries: 0}}
	s.maybeReportState("127.0.0.1", port, PortStateFiltered)
	if atomic.LoadUint64(&s.filteredCount) != 1 {
		t.Fatalf("filteredCount = %d, want 1", atomic.LoadUint64(&s.filteredCount))
	}
	s.scanTarget(context.Background(), "127.0.0.1", port)
	if atomic.LoadUint64(&s.closedCount) != 1 {
		t.Fatalf("closedCount = %d, want 1", atomic.LoadUint64(&s.closedCount))
	}
	if atomic.LoadUint64(&s.resultsCount) != 0 {
		t.Fatalf("resultsCount = %d, want 0 (non-open must not count as open)", atomic.LoadUint64(&s.resultsCount))
	}
}
