package portscan

import (
	"errors"
	"net"
	"os"
	"testing"
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
