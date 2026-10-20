//go:build !windows

package portscan

import "syscall"

// errConnRefused 是 Unix 平台的连接拒绝错误码。
const errConnRefused = syscall.ECONNREFUSED
