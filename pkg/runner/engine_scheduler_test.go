package runner

import (
	"testing"

	"github.com/zan8in/afrog/v3/pkg/poc"
	"gopkg.in/yaml.v2"
)

func TestNextRoundRobinCursor_RotatesActiveCursors(t *testing.T) {
	cursors := []stagePocCursor{
		{poc: poc.Poc{Id: "a"}},
		{poc: poc.Poc{Id: "b"}},
		{poc: poc.Poc{Id: "c"}},
	}

	start := 0
	got := make([]string, 0, 4)
	for i := 0; i < 4; i++ {
		idx, next, ok := nextRoundRobinCursor(cursors, start)
		if !ok {
			t.Fatalf("expected active cursor at step %d", i)
		}
		got = append(got, cursors[idx].poc.Id)
		start = next
	}

	want := []string{"a", "b", "c", "a"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected round-robin order: got=%v want=%v", got, want)
		}
	}
}

func TestNextRoundRobinCursor_SkipsDoneCursors(t *testing.T) {
	cursors := []stagePocCursor{
		{poc: poc.Poc{Id: "a"}, done: true},
		{poc: poc.Poc{Id: "b"}},
		{poc: poc.Poc{Id: "c"}, done: true},
	}

	idx, next, ok := nextRoundRobinCursor(cursors, 0)
	if !ok {
		t.Fatal("expected one active cursor")
	}
	if cursors[idx].poc.Id != "b" {
		t.Fatalf("expected cursor b, got %s", cursors[idx].poc.Id)
	}
	if next != 2 {
		t.Fatalf("expected next start to be 2, got %d", next)
	}
}

func TestHeavyWorkerLimit(t *testing.T) {
	cases := []struct {
		concurrency int
		want        int
	}{
		{1, 0},
		{8, 1},
		{25, 2},
		{48, 3},
		{100, 4},
	}

	for _, tc := range cases {
		if got := heavyWorkerLimit(tc.concurrency); got != tc.want {
			t.Fatalf("heavyWorkerLimit(%d)=%d want=%d", tc.concurrency, got, tc.want)
		}
	}
}

func TestBruteKeyClass(t *testing.T) {
	authLike, pathLike := bruteKeyClass([]string{"username", "password"})
	if !authLike || pathLike {
		t.Fatalf("expected username/password to be auth-like only, got auth=%v path=%v", authLike, pathLike)
	}

	authLike, pathLike = bruteKeyClass([]string{"p"})
	if authLike || !pathLike {
		t.Fatalf("expected p to be path-like only, got auth=%v path=%v", authLike, pathLike)
	}
}

func TestIsHeavyPoc(t *testing.T) {
	tests := []struct {
		name string
		p    poc.Poc
		want bool
	}{
		{
			name: "id weak-login",
			p:    poc.Poc{Id: "mysql-weak-login"},
			want: true,
		},
		{
			name: "tag brute",
			p:    poc.Poc{Id: "demo", Info: poc.Info{Tags: "test,brute"}},
			want: false,
		},
		{
			name: "small brute path enumeration",
			p: poc.Poc{
				Id: "demo",
				Rules: poc.RuleMapSlice{
					{
						Key: "r0",
						Value: poc.Rule{
							Brute: yaml.MapSlice{
								{Key: "continue", Value: false},
								{Key: "p", Value: []string{"/", "/login", "/admin"}},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "large brute combination",
			p: poc.Poc{
				Id: "demo",
				Rules: poc.RuleMapSlice{
					{
						Key: "r0",
						Value: poc.Rule{
							Brute: yaml.MapSlice{
								{Key: "user", Value: []string{"u1", "u2", "u3", "u4", "u5", "u6", "u7", "u8"}},
								{Key: "pass", Value: []string{"p1", "p2", "p3", "p4", "p5"}},
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "sniper path brute stays light",
			p: poc.Poc{
				Id: "demo",
				Rules: poc.RuleMapSlice{
					{
						Key: "r0",
						Value: poc.Rule{
							Brute: yaml.MapSlice{
								{Key: "mode", Value: "sniper"},
								{Key: "continue", Value: false},
								{Key: "path", Value: []string{"/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h", "/i", "/j", "/k", "/l"}},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "auth-like brute stays heavy",
			p: poc.Poc{
				Id: "demo",
				Rules: poc.RuleMapSlice{
					{
						Key: "r0",
						Value: poc.Rule{
							Brute: yaml.MapSlice{
								{Key: "username", Value: []string{"admin", "root"}},
								{Key: "password", Value: []string{"admin", "123456"}},
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "normal poc",
			p:    poc.Poc{Id: "demo", Info: poc.Info{Tags: "cms,test"}},
			want: false,
		},
	}

	for _, tt := range tests {
		if got := isHeavyPoc(tt.p); got != tt.want {
			t.Fatalf("%s: isHeavyPoc()=%v want=%v", tt.name, got, tt.want)
		}
	}
}
