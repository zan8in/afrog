package afrog

import (
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestSDKPortscanCallbackAndCollection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	pocPath, err := filepath.Abs("./pocs/afrog-pocs")
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}

	opts := NewSDKOptions()
	opts.Targets = []string{"127.0.0.1"}
	opts.PocFile = pocPath
	opts.Search = "__no_such_poc__"
	opts.PortScan = true
	opts.PSPorts = portStr
	opts.PSSkipDiscovery = true
	opts.PSTimeout = 200
	opts.PSRateLimit = 0
	opts.PSRetries = 0

	sc, err := NewSDKScanner(opts)
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	t.Cleanup(sc.Close)

	got := make(chan struct{}, 1)
	sc.OnPort = func(host string, p int) {
		if host == "127.0.0.1" && p == port {
			select {
			case got <- struct{}{}:
			default:
			}
		}
	}

	done := make(chan error, 1)
	go func() { done <- sc.Run() }()

	select {
	case <-got:
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		t.Fatalf("portscan callback not called")
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for portscan callback")
	}

	open := sc.GetOpenPorts()
	ports, ok := open["127.0.0.1"]
	if !ok {
		t.Fatalf("expected open ports for 127.0.0.1, got: %v", open)
	}
	found := false
	for _, p := range ports {
		if p == port {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected port %d in %v", port, ports)
	}
}

func TestSDKPortscanAsyncChannel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	pocPath, err := filepath.Abs("./pocs/afrog-pocs")
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}

	opts := NewSDKOptions()
	opts.Targets = []string{"127.0.0.1"}
	opts.PocFile = pocPath
	opts.Search = "__no_such_poc__"
	opts.PortScan = true
	opts.PSPorts = portStr
	opts.PSSkipDiscovery = true
	opts.PSTimeout = 200
	opts.PSRateLimit = 0
	opts.PSRetries = 0

	sc, err := NewSDKScanner(opts)
	if err != nil {
		t.Fatalf("NewSDKScanner: %v", err)
	}
	t.Cleanup(sc.Close)

	if sc.PortChan == nil {
		t.Fatalf("expected PortChan to be initialized when PortScan is enabled")
	}

	found := make(chan struct{}, 1)
	go func() {
		for r := range sc.PortChan {
			if r.Host == "127.0.0.1" && r.Port == port {
				select {
				case found <- struct{}{}:
				default:
				}
				return
			}
		}
	}()

	if err := sc.RunAsync(); err != nil {
		t.Fatalf("RunAsync: %v", err)
	}

	select {
	case <-found:
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for portscan async channel result")
	}
}
