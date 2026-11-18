package executor

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func TestBuildArgs(t *testing.T) {
	tests := []struct {
		name    string
		spec    *Spec
		want    []string
		wantErr bool
	}{
		{
			name: "single target",
			spec: &Spec{Targets: []string{"http://a.example"}},
			want: []string{"-t", "http://a.example", "-auto-req-limit=false", "-json-stream", "-disable-output-html"},
		},
		{
			name: "target whitespace trimmed",
			spec: &Spec{Targets: []string{"  http://a.example  ", "", "   "}},
			want: []string{"-t", "http://a.example", "-auto-req-limit=false", "-json-stream", "-disable-output-html"},
		},
		{
			name: "poc file severity search",
			spec: &Spec{
				Targets:  []string{"http://a.example"},
				PocFile:  "/tmp/custom.yaml",
				Search:   "tomcat",
				Severity: "high,critical",
			},
			want: []string{
				"-t", "http://a.example",
				"-P", "/tmp/custom.yaml",
				"-s", "tomcat",
				"-S", "high,critical",
				"-auto-req-limit=false",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			name: "append pocs",
			spec: &Spec{
				Targets:    []string{"http://a.example"},
				AppendPocs: []string{"/home/u/.config/afrog/pocs-curated", " /home/u/.config/afrog/pocs-my ", ""},
			},
			want: []string{
				"-t", "http://a.example",
				"-ap", "/home/u/.config/afrog/pocs-curated",
				"-ap", "/home/u/.config/afrog/pocs-my",
				"-auto-req-limit=false",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			name: "performance options",
			spec: &Spec{
				Targets:        []string{"http://a.example"},
				Concurrency:    20,
				RateLimit:      100,
				TimeoutSeconds: 15,
				Retries:        2,
				MaxHostError:   5,
				Smart:          true,
			},
			want: []string{
				"-t", "http://a.example",
				"-c", "20",
				"-rl", "100",
				"-timeout", "15",
				"-retries", "2",
				"-mhe", "5",
				"-smart",
				"-auto-req-limit=false",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			name: "network options",
			spec: &Spec{
				Targets: []string{"http://a.example"},
				Proxy:   "http://127.0.0.1:8080",
				Headers: []string{"X-A: 1", " Cookie: a=b ", ""},
			},
			want: []string{
				"-t", "http://a.example",
				"-auto-req-limit=false",
				"-proxy", "http://127.0.0.1:8080",
				"-H", "X-A: 1",
				"-H", "Cookie: a=b",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			name: "port scan and web probe",
			spec: &Spec{
				Targets:           []string{"http://a.example"},
				PortScan:          boolPtr(true),
				Ports:             "80,443",
				SkipHostDiscovery: boolPtr(true),
				WebFingerprint:    boolPtr(true),
				WebFavicon:        boolPtr(false),
			},
			want: []string{
				"-t", "http://a.example",
				"-auto-req-limit=false",
				"-ps",
				"-p", "80,443",
				"-Pn",
				"-w",
				"-w-favicon=false",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			name: "port scan reporting non-open states",
			spec: &Spec{
				Targets:      []string{"http://a.example"},
				PortScan:     boolPtr(true),
				Ports:        "80,443",
				ReportStates: boolPtr(true),
			},
			want: []string{
				"-t", "http://a.example",
				"-auto-req-limit=false",
				"-ps",
				"-p", "80,443",
				"-ps-states",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			name: "web probe tuning",
			spec: &Spec{
				Targets:         []string{"http://a.example"},
				WebFingerprint:  boolPtr(true),
				WebProbeTimeout: 20,
				WebFavicon:      boolPtr(true),
			},
			want: []string{
				"-t", "http://a.example",
				"-auto-req-limit=false",
				"-w",
				"-w-timeout", "20",
				"-w-favicon",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			// 未设置 favicon（nil）时省略 flag，交回子进程默认值（开启），
			// 避免把默认开启的能力静默关掉。
			name: "web probe favicon unset defers to default",
			spec: &Spec{
				Targets:        []string{"http://a.example"},
				WebFingerprint: boolPtr(true),
			},
			want: []string{
				"-t", "http://a.example",
				"-auto-req-limit=false",
				"-w",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			// 显式关闭 Web 探测（Web 控制台取消勾选）必须下发 -w=false：CLI 的 -w
			// 默认开启，省略 flag 等于开启，所以关掉必须显式表达。
			name: "web probe explicitly disabled",
			spec: &Spec{
				Targets:        []string{"http://a.example"},
				WebFingerprint: boolPtr(false),
			},
			want: []string{
				"-t", "http://a.example",
				"-auto-req-limit=false",
				"-w=false",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			name: "oob adapter",
			spec: &Spec{
				Targets:    []string{"http://a.example"},
				EnableOOB:  true,
				OOBAdapter: "dnslogcn",
				OOBKey:     "ignored-no-flag",
				OOBDomain:  "ignored-no-flag",
			},
			want: []string{
				"-t", "http://a.example",
				"-auto-req-limit=false",
				"-oob", "dnslogcn",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			name: "oob enabled without adapter emits nothing",
			spec: &Spec{
				Targets:   []string{"http://a.example"},
				EnableOOB: true,
			},
			want: []string{"-t", "http://a.example", "-auto-req-limit=false", "-json-stream", "-disable-output-html"},
		},
		{
			name: "port scan without custom ports",
			spec: &Spec{
				Targets:  []string{"http://a.example"},
				PortScan: boolPtr(true),
			},
			want: []string{
				"-t", "http://a.example",
				"-auto-req-limit=false",
				"-ps",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			// 前置阶段开关是三态：未设置（nil）省略 flag，交回子进程默认值（关闭）；
			// 只有显式 false 才下发 -ps=false / -Pn=false，用于覆盖配置文件里的开启。
			name: "pre-scan switches explicitly disabled",
			spec: &Spec{
				Targets:           []string{"http://a.example"},
				PortScan:          boolPtr(false),
				SkipHostDiscovery: boolPtr(false),
			},
			want: []string{
				"-t", "http://a.example",
				"-auto-req-limit=false",
				"-ps=false",
				"-Pn=false",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			// 未设置（nil）时省略全部前置阶段 flag，交回子进程默认值。
			name: "pre-scan switches unset defer to default",
			spec: &Spec{
				Targets: []string{"http://a.example"},
			},
			want: []string{
				"-t", "http://a.example",
				"-auto-req-limit=false",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			name: "explicit per-target limit",
			spec: &Spec{
				Targets:           []string{"http://a.example"},
				ReqLimitPerTarget: 25,
			},
			want: []string{
				"-t", "http://a.example",
				"-rlt", "25",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			name: "explicit adaptive limit",
			spec: &Spec{
				Targets:      []string{"http://a.example"},
				AutoReqLimit: true,
			},
			want: []string{
				"-t", "http://a.example",
				"-auto-req-limit",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			name: "explicit polite preset",
			spec: &Spec{
				Targets: []string{"http://a.example"},
				Polite:  true,
			},
			want: []string{
				"-t", "http://a.example",
				"-polite",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			name: "explicit balanced preset",
			spec: &Spec{
				Targets:  []string{"http://a.example"},
				Balanced: true,
			},
			want: []string{
				"-t", "http://a.example",
				"-balanced",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			name: "explicit aggressive preset",
			spec: &Spec{
				Targets:    []string{"http://a.example"},
				Aggressive: true,
			},
			want: []string{
				"-t", "http://a.example",
				"-aggressive",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			name: "gating level and dry run",
			spec: &Spec{
				Targets:     []string{"http://a.example"},
				GatingLevel: "aggressive",
				DryRun:      true,
			},
			want: []string{
				"-t", "http://a.example",
				"-auto-req-limit=false",
				"-gating-level", "aggressive",
				"-dry-run",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			// 执行器只做 trim，不校验档位取值：取值归一由 CLI 侧负责（off→off，非法→safe）。
			// 这里只钉住「带空白的档位会被清理后再下发」，避免把归一逻辑在两个地方各写一遍。
			name: "gating level whitespace trimmed",
			spec: &Spec{
				Targets:     []string{"http://a.example"},
				GatingLevel: "  balanced  ",
			},
			want: []string{
				"-t", "http://a.example",
				"-auto-req-limit=false",
				"-gating-level", "balanced",
				"-json-stream",
				"-disable-output-html",
			},
		},
		{
			name:    "no targets",
			spec:    &Spec{},
			wantErr: true,
		},
		{
			name:    "nil spec",
			spec:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, cleanup, err := buildArgs("task-1", tt.spec)
			defer cleanup()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got args %v", args)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildArgs: %v", err)
			}
			if !reflect.DeepEqual(args, tt.want) {
				t.Fatalf("args mismatch\n got: %v\nwant: %v", args, tt.want)
			}
		})
	}
}

func TestBuildArgs_MultipleTargetsUsesFile(t *testing.T) {
	spec := &Spec{Targets: []string{"http://a.example", "http://b.example", "http://c.example"}}
	args, cleanup, err := buildArgs("task-multi", spec)
	defer cleanup()
	if err != nil {
		t.Fatalf("buildArgs: %v", err)
	}
	if len(args) != 5 || args[0] != "-T" || args[2] != "-auto-req-limit=false" || args[3] != "-json-stream" || args[4] != "-disable-output-html" {
		t.Fatalf("unexpected args: %v", args)
	}
	path := args[1]
	if base := filepath.Base(path); !strings.HasPrefix(base, "afrog-targets-task-multi-") {
		t.Fatalf("targets file prefix unexpected: %s", base)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read targets file: %v", err)
	}
	if got, want := string(data), "http://a.example\nhttp://b.example\nhttp://c.example\n"; got != want {
		t.Fatalf("targets file content\n got: %q\nwant: %q", got, want)
	}

	// cleanup 后临时文件应被删除。
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("targets file should be removed, stat err = %v", err)
	}
}

// -json-stream 必须始终存在，否则执行器拿不到事件流。
// -disable-output-html 同样必须始终存在，避免子进程往工作目录丢 HTML 报告。
func TestBuildArgs_AlwaysIncludesJSONStream(t *testing.T) {
	specs := []*Spec{
		{Targets: []string{"http://a.example"}},
		{Targets: []string{"http://a.example", "http://b.example"}},
		{Targets: []string{"http://a.example"}, PortScan: boolPtr(true), EnableOOB: true, WebFingerprint: boolPtr(true)},
	}
	for i, spec := range specs {
		args, cleanup, err := buildArgs("t", spec)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if !slices.Contains(args, "-json-stream") {
			t.Fatalf("case %d: -json-stream missing: %v", i, args)
		}
		if !slices.Contains(args, "-disable-output-html") {
			t.Fatalf("case %d: -disable-output-html missing: %v", i, args)
		}
		cleanup()
	}
}

// CLI 的 -auto-req-limit 现在默认开启，Web 端「未选择任何档位」必须显式关闭它，
// 否则 Web 控制台里选「不限速」会静默变成开启自适应。
func TestBuildArgs_DefaultDisablesAutoReqLimit(t *testing.T) {
	args, cleanup, err := buildArgs("t", &Spec{Targets: []string{"http://a.example"}})
	defer cleanup()
	if err != nil {
		t.Fatalf("buildArgs: %v", err)
	}
	if !slices.Contains(args, "-auto-req-limit=false") {
		t.Fatalf("expected -auto-req-limit=false, got %v", args)
	}
	if slices.Contains(args, "-auto-req-limit") {
		t.Fatalf("should not enable adaptive limit by default: %v", args)
	}
}
