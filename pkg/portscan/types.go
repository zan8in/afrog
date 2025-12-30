package portscan

// PortState represents the state of a port
type PortState int

const (
	PortStateOpen PortState = iota
	PortStateClosed
	PortStateFiltered
	PortStateUnknown
)

func (s PortState) String() string {
	switch s {
	case PortStateOpen:
		return "open"
	case PortStateClosed:
		return "closed"
	case PortStateFiltered:
		return "filtered"
	default:
		return "unknown"
	}
}

// ScanResult holds the result of a single port scan
type ScanResult struct {
	Host        string
	Port        int
	State       PortState
	Service     string
	Version     string
	Banner      string
	Fingerprint *ServiceFingerprint
}

// ServiceFingerprint represents detected service details
type ServiceFingerprint struct {
	Name    string
	Version string
	Extras  map[string]string
}

// ScanMode defines the scanning strategy
type ScanMode int

const (
	ScanModeAuto ScanMode = iota // Automatically switch based on network
	ScanModeConnect              // TCP Connect Scan (Syscall: connect)
	ScanModeSyn                  // TCP SYN Scan (Raw sockets) - Requires root
)
