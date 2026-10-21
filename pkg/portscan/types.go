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
	Host  string
	Port  int
	State PortState

	// ServiceInfo 是端口指纹识别的结果，内嵌后字段可直接访问（res.Service 等）。
	ServiceInfo
}

// ScanMode defines the scanning strategy
type ScanMode int

const (
	ScanModeAuto    ScanMode = iota // Automatically switch based on network
	ScanModeConnect                 // TCP Connect Scan (Syscall: connect)
	ScanModeSyn                     // TCP SYN Scan (Raw sockets) - Requires root
)
