//go:build windows

package portscan

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// defaultGateway 通过 `route print -4` 的 Active Routes 表读取默认网关。
func defaultGateway() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "route", "print", "-4").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		// Network Destination / Netmask / Gateway / Interface / Metric
		if len(f) < 3 || f[0] != "0.0.0.0" || f[1] != "0.0.0.0" {
			continue
		}
		if gw := strings.TrimSpace(f[2]); gw != "" && gw != "On-link" {
			return gw
		}
	}
	return ""
}
