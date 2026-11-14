package config

import (
	"os"
	"path/filepath"
	"testing"
)

// observe.max_rows 用指针区分「没配」与「显式配 0」：前者沿用默认值，后者表示不限。
func TestLoadConfigReadOnlyObserveMaxRows(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want *int
	}{
		{name: "未配置", yaml: "server: ':16868'\n", want: nil},
		{name: "显式 0", yaml: "observe:\n  max_rows: 0\n", want: intPtr(0)},
		{name: "自定义", yaml: "observe:\n  max_rows: 5000\n", want: intPtr(5000)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "afrog-config.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			cfg, err := LoadConfigReadOnly(path)
			if err != nil {
				t.Fatalf("LoadConfigReadOnly: %v", err)
			}
			switch {
			case tc.want == nil && cfg.Observe.MaxRows != nil:
				t.Fatalf("MaxRows = %d, want nil", *cfg.Observe.MaxRows)
			case tc.want != nil && (cfg.Observe.MaxRows == nil || *cfg.Observe.MaxRows != *tc.want):
				t.Fatalf("MaxRows = %v, want %d", cfg.Observe.MaxRows, *tc.want)
			}
		})
	}
}

func intPtr(v int) *int { return &v }
