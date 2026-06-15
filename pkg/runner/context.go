package runner

import "github.com/zan8in/afrog/v3/pkg/config"

// ScanContext holds runtime state and callbacks for an active scan.
// It separates runtime concerns from pure configuration (config.Options).
type ScanContext struct {
	// Callbacks
	OnPhaseProgress  func(phase string, status string, finished int64, total int64, percent int)
	OnPortScanResult func(host string, port int)
	OnHostDiscovered func(host string)
	OnScanInfoUpdate func(info config.ScanInfoUpdate)
	OnPedmLog        func(line string)
}
