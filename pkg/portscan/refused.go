package portscan

import (
	"errors"
	"strings"
)

// isConnRefused 判断 err 是否为 TCP "连接被拒绝"（收到 RST）：这说明主机在线、
// 端口关闭，是"存活"信号而非网络异常。
//
// errno 判定依赖平台常量（见 refused_unix.go / refused_windows.go）：Windows 上
// 真实错误码是 WSA 的 10061，与 Go 的 syscall.ECONNREFUSED 不相等，直接比较会永久
// 漏判。英文文案兜底只用于代理等不透传 errno 的场景，非英文系统上不可靠，不能当主判据。
func isConnRefused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errConnRefused) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "refused")
}
