//go:build darwin

package portscan

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// defaultGateway 通过 `route -n get default` 读取默认网关。macOS 没有 /proc，
// 系统路由表只能靠 route/netstat 命令读取；这条命令只跑一次、耗时几十毫秒。
func defaultGateway() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/sbin/route", "-n", "get", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "gateway:") {
			continue
		}
		gw := strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		// 去除可能的 %scope（链路本地地址后缀）。
		if i := strings.IndexByte(gw, '%'); i >= 0 {
			gw = gw[:i]
		}
		if gw != "" && gw != "0.0.0.0" {
			return gw
		}
	}
	return ""
}
