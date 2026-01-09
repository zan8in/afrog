package runner

import (
	"sync"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/fingerprint"
)

func TestOpenPortsCollector_ConcurrentAdd(t *testing.T) {
	c := newOpenPortsCollector()

	const goroutines = 50
	const perG = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(worker int) {
			defer wg.Done()
			host := "h" + string(rune('a'+(worker%10)))
			for p := 0; p < perG; p++ {
				c.Add(host, p)
			}
		}(i)
	}
	wg.Wait()

	snap := c.Snapshot()
	total := 0
	for _, ports := range snap {
		total += len(ports)
	}
	if total != goroutines*perG {
		t.Fatalf("expected %d collected ports, got %d", goroutines*perG, total)
	}
}

func TestFingerprintKeyFromTarget(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://example.com", "example.com:443"},
		{"https://example.com/", "example.com:443"},
		{"http://example.com", "example.com:80"},
		{"http://example.com:8080", "example.com:8080"},
		{"https://example.com:80", "example.com:80"},
		{"", ""},
		{"not a url", ""},
	}
	for _, tt := range tests {
		if got := fingerprint.KeyFromTarget(tt.in); got != tt.want {
			t.Fatalf("fingerprint.KeyFromTarget(%q)=%q want=%q", tt.in, got, tt.want)
		}
	}
}
