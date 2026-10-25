package config

import "testing"

// resolveRequestLimitMode 是默认值改造的核心：-auto-req-limit 默认开启后，
// 必须能区分「用户显式指定的 -rlt 0」与「没设置过 -rlt」，否则默认的自适应
// 会被 -rlt 的零值误当成「不限速」，或反之把用户的不限速覆盖掉。
func TestResolveRequestLimitMode(t *testing.T) {
	defaults := func() *Options {
		return &Options{AutoReqLimit: true, RateLimit: 150, Concurrency: 25}
	}

	tests := []struct {
		name     string
		opt      *Options
		setFlags []string
		wantRlt  int
		wantAuto bool
		wantErr  bool
	}{
		{
			name:     "default enables adaptive",
			opt:      defaults(),
			wantRlt:  15,
			wantAuto: true,
		},
		{
			name:     "default without rate limit falls back to 150",
			opt:      &Options{AutoReqLimit: true, RateLimit: 0, Concurrency: 25},
			wantRlt:  15,
			wantAuto: true,
		},
		{
			name:     "high concurrency derives a more conservative start rate",
			opt:      &Options{AutoReqLimit: true, RateLimit: 150, Concurrency: 100},
			wantRlt:  8,
			wantAuto: true,
		},
		{
			name:     "explicit fixed rate wins over the new default",
			opt:      &Options{AutoReqLimit: true, ReqLimitPerTarget: 12, RateLimit: 150, Concurrency: 25},
			setFlags: []string{"req-limit-per-target"},
			wantRlt:  12,
			wantAuto: false,
		},
		{
			name:     "explicit zero rate means no limit",
			opt:      defaults(),
			setFlags: []string{"req-limit-per-target"},
			wantRlt:  0,
			wantAuto: false,
		},
		{
			name:     "explicit adaptive flag keeps adaptive on",
			opt:      defaults(),
			setFlags: []string{"auto-req-limit"},
			wantRlt:  15,
			wantAuto: true,
		},
		{
			name:     "explicitly disabling adaptive means no limit",
			opt:      &Options{AutoReqLimit: false, RateLimit: 150, Concurrency: 25},
			setFlags: []string{"auto-req-limit"},
			wantRlt:  0,
			wantAuto: false,
		},
		{
			name:     "explicit rate conflicts with explicit adaptive",
			opt:      &Options{AutoReqLimit: true, ReqLimitPerTarget: 12},
			setFlags: []string{"req-limit-per-target", "auto-req-limit"},
			wantErr:  true,
		},
		{
			name:     "polite preset",
			opt:      &Options{AutoReqLimit: true, Polite: true},
			wantRlt:  5,
			wantAuto: false,
		},
		{
			name:     "balanced preset",
			opt:      &Options{AutoReqLimit: true, Balanced: true},
			wantRlt:  15,
			wantAuto: false,
		},
		{
			name:     "aggressive preset",
			opt:      &Options{AutoReqLimit: true, Aggressive: true},
			wantRlt:  50,
			wantAuto: false,
		},
		{
			name:    "two presets conflict",
			opt:     &Options{AutoReqLimit: true, Polite: true, Balanced: true},
			wantErr: true,
		},
		{
			name:     "preset conflicts with explicit rate",
			opt:      &Options{AutoReqLimit: true, Polite: true},
			setFlags: []string{"req-limit-per-target"},
			wantErr:  true,
		},
		{
			name:    "negative rate rejected",
			opt:     &Options{AutoReqLimit: true, ReqLimitPerTarget: -1},
			wantErr: true,
		},
		{
			name:     "nil setFlags does not panic",
			opt:      defaults(),
			setFlags: nil,
			wantRlt:  15,
			wantAuto: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := tt.opt
			if tt.setFlags != nil {
				opt.setFlags = make(map[string]bool, len(tt.setFlags))
				for _, f := range tt.setFlags {
					opt.setFlags[f] = true
				}
			}
			err := opt.resolveRequestLimitMode()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got rlt=%d auto=%v", opt.ReqLimitPerTarget, opt.AutoReqLimit)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveRequestLimitMode: %v", err)
			}
			if opt.ReqLimitPerTarget != tt.wantRlt {
				t.Fatalf("ReqLimitPerTarget = %d, want %d", opt.ReqLimitPerTarget, tt.wantRlt)
			}
			if opt.AutoReqLimit != tt.wantAuto {
				t.Fatalf("AutoReqLimit = %v, want %v", opt.AutoReqLimit, tt.wantAuto)
			}
		})
	}
}
