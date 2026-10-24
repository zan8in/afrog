//go:build linux

package portscan

import (
	"os"
	"strconv"
	"strings"
)

// defaultGateway 从 /proc/net/route 读默认路由的网关地址。
// 格式：Iface Destination Gateway Flags ...，默认路由的 Destination 为 00000000，
// Gateway 是 8 位十六进制的小端序 IPv4。
func defaultGateway() string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		if ip := parseHexIPv4(f[2]); ip != "" {
			return ip
		}
	}
	return ""
}

func parseHexIPv4(s string) string {
	if len(s) != 8 {
		return ""
	}
	b := make([]int, 4)
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return ""
		}
		b[i] = int(v)
	}
	// 小端序：最低有效字节在前。
	return strconv.Itoa(b[3]) + "." + strconv.Itoa(b[2]) + "." + strconv.Itoa(b[1]) + "." + strconv.Itoa(b[0])
}
