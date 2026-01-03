package runner

import (
	"sync"
	"testing"
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

