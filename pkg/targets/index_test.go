package targets

import (
	"testing"
)

func TestTargetIndex_BuildTargetIndex(t *testing.T) {
	seeds := []string{
		" https://Example.com:443/a?b=1#c ",
		"https://example.com/a?b=1",
		"example.com",
		"EXAMPLE.com.",
		"example.com:80",
		"example.com:080",
		"192.168.0.0/30",
		"192.168.1.1-192.168.1.3",
		"example.com/path?q=1",
		"[2001:db8::1]:443",
		"2001:db8::1",
	}

	idx := BuildTargetIndex(seeds)

	if got, want := len(idx.URLs), 2; got != want {
		t.Fatalf("URLs len mismatch: got=%d want=%d URLs=%v", got, want, idx.URLs)
	}
	if got, want := len(idx.Hosts), 2; got != want {
		t.Fatalf("Hosts len mismatch: got=%d want=%d Hosts=%v", got, want, idx.Hosts)
	}
	if got, want := len(idx.HostPorts), 2; got != want {
		t.Fatalf("HostPorts len mismatch: got=%d want=%d HostPorts=%v", got, want, idx.HostPorts)
	}
	if got, want := len(idx.Expandable), 2; got != want {
		t.Fatalf("Expandable len mismatch: got=%d want=%d Expandable=%v", got, want, idx.Expandable)
	}
	if got, want := len(idx.AllCanonicalKeys), 8; got != want {
		t.Fatalf("AllCanonicalKeys len mismatch: got=%d want=%d keys=%v", got, want, idx.AllCanonicalKeys)
	}

	assertContains(t, idx.URLs, "https://Example.com:443/a?b=1#c")
	assertContains(t, idx.URLs, "http://example.com/path?q=1")

	assertContains(t, idx.Hosts, "example.com")
	assertContains(t, idx.Hosts, "2001:db8::1")

	assertContains(t, idx.HostPorts, "example.com:80")
	assertContains(t, idx.HostPorts, "[2001:db8::1]:443")

	assertContains(t, idx.Expandable, "192.168.0.0/30")
	assertContains(t, idx.Expandable, "192.168.1.1-192.168.1.3")

	preScan := idx.PreScanTargets()
	if got, want := len(preScan), 4; got != want {
		t.Fatalf("PreScanTargets len mismatch: got=%d want=%d targets=%v", got, want, preScan)
	}
	if preScan[0] != "192.168.0.0/30" || preScan[1] != "192.168.1.1-192.168.1.3" || preScan[2] != "example.com" || preScan[3] != "2001:db8::1" {
		t.Fatalf("PreScanTargets order mismatch: %v", preScan)
	}

	netTargets := idx.NetTargets()
	if got, want := len(netTargets), 4; got != want {
		t.Fatalf("NetTargets len mismatch: got=%d want=%d targets=%v", got, want, netTargets)
	}
	if netTargets[0] != "example.com" || netTargets[1] != "2001:db8::1" || netTargets[2] != "example.com:80" || netTargets[3] != "[2001:db8::1]:443" {
		t.Fatalf("NetTargets order mismatch: %v", netTargets)
	}
}

func TestTargetIndex_Add_InvalidInputs(t *testing.T) {
	idx := NewTargetIndex()
	if idx.Add("") {
		t.Fatalf("expected Add(\"\") to return false")
	}
	if idx.Add("   ") {
		t.Fatalf("expected Add(\"   \") to return false")
	}
	if idx.Add("example.com:abc") {
		t.Fatalf("expected Add(\"example.com:abc\") to return false")
	}
	if idx.Add("http://") {
		t.Fatalf("expected Add(\"http://\") to return false")
	}
}

func assertContains(t *testing.T, haystack []string, needle string) {
	t.Helper()
	for _, v := range haystack {
		if v == needle {
			return
		}
	}
	t.Fatalf("missing %q in %v", needle, haystack)
}
