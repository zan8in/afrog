package executor

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

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
			want: []string{"-t", "http://a.example", "-json-stream", "-disable-output-html"},
		},
		{
			name: "target whitespace trimmed",
			spec: &Spec{Targets: []string{"  http://a.example  ", "", "   "}},
			want: []string{"-t", "http://a.example", "-json-stream", "-disable-output-html"},
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
				PortScan:          true,
				Ports:             "80,443",
				SkipHostDiscovery: true,
				WebFingerprint:    true,
			},
			want: []string{
				"-t", "http://a.example",
				"-ps",
				"-p", "80,443",
				"-Pn",
				"-w",
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
			want: []string{"-t", "http://a.example", "-json-stream", "-disable-output-html"},
		},
		{
			name: "port scan without custom ports",
			spec: &Spec{
				Targets:  []string{"http://a.example"},
				PortScan: true,
			},
			want: []string{
				"-t", "http://a.example",
				"-ps",
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
	if len(args) != 4 || args[0] != "-T" || args[2] != "-json-stream" || args[3] != "-disable-output-html" {
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
		{Targets: []string{"http://a.example"}, PortScan: true, EnableOOB: true, WebFingerprint: true},
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
