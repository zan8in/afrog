//go:build windows

package portscan

import "golang.org/x/sys/windows"

// errConnRefused 是 Windows 平台真实的连接拒绝错误码（WSA 10061）。
// 不能用 syscall.ECONNREFUSED：那个值在 Windows 上只是 Go 为兼容 posix 常量而
// 发明的偏移值，与网络栈实际返回的 errno 不相等。
const errConnRefused = windows.WSAECONNREFUSED
