package config

import (
	"testing"

	"github.com/zan8in/afrog/v3/pkg/portscan"
)

// -1 是 flag 的默认哨兵，表示「自动」；>= 0 是用户显式给定（0 = 不限速）。
// 未指定速率且未选固定档位时，运行时走 AutoRate（按链路与端口数推导）。
func TestResolvePortScanRates(t *testing.T) {
	cases := []struct {
		name     string
		opt      Options
		wantG    int
		wantH    int
		wantAuto bool
	}{
		{
			name:     "未指定档位时走自动速率",
			opt:      Options{PSCPS: -1, PSCPSHost: -1},
			wantG:    portscan.DefaultGlobalCPS,
			wantH:    portscan.DefaultPerHostCPS,
			wantAuto: true,
		},
		{
			name:  "polite 档",
			opt:   Options{Polite: true, PSCPS: -1, PSCPSHost: -1},
			wantG: portscan.PresetPoliteGlobalCPS,
			wantH: portscan.PresetPolitePerHostCPS,
		},
		{
			name:  "balanced 档",
			opt:   Options{Balanced: true, PSCPS: -1, PSCPSHost: -1},
			wantG: portscan.PresetBalancedGlobalCPS,
			wantH: portscan.PresetBalancedPerHostCPS,
		},
		{
			name:  "aggressive 显式取消上限",
			opt:   Options{Aggressive: true, PSCPS: -1, PSCPSHost: -1},
			wantG: 0,
			wantH: 0,
		},
		{
			name:  "只显式指定全局速率时单目标仍取默认",
			opt:   Options{PSCPS: 500, PSCPSHost: -1},
			wantG: 500,
			wantH: portscan.DefaultPerHostCPS,
		},
		{
			name:  "显式 0 表示不限速",
			opt:   Options{PSCPS: 0, PSCPSHost: 0},
			wantG: 0,
			wantH: 0,
		},
		{
			name:  "显式值优先于档位",
			opt:   Options{Polite: true, PSCPS: 50, PSCPSHost: 5},
			wantG: 50,
			wantH: 5,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opt := tc.opt
			opt.ResolvePortScanRates()
			if opt.PSCPS != tc.wantG {
				t.Errorf("PSCPS = %d, want %d", opt.PSCPS, tc.wantG)
			}
			if opt.PSCPSHost != tc.wantH {
				t.Errorf("PSCPSHost = %d, want %d", opt.PSCPSHost, tc.wantH)
			}
			if opt.PSAutoRate != tc.wantAuto {
				t.Errorf("PSAutoRate = %v, want %v", opt.PSAutoRate, tc.wantAuto)
			}
		})
	}
}

// ResolvePortScanRates 可能被重复调用（CLI 校验 + SDK 预构造）；第二次不能把
// 已经落定的 AutoRate 翻成 false。
func TestResolvePortScanRatesIdempotentAutoRate(t *testing.T) {
	opt := Options{PSCPS: -1, PSCPSHost: -1}
	opt.ResolvePortScanRates()
	if !opt.PSAutoRate {
		t.Fatal("first resolve should enable auto rate")
	}
	opt.ResolvePortScanRates()
	if !opt.PSAutoRate {
		t.Fatal("second resolve must keep auto rate enabled")
	}
}
