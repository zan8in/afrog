package runner

import "fmt"

// ErrorSeverity classifies the impact of an error during scanning.
type ErrorSeverity int

const (
	// SevSuppressed: expected and ignorable (e.g. CEL variable fallback)
	SevSuppressed ErrorSeverity = iota
	// SevRetryable: transient, may succeed on retry
	SevRetryable
	// SevFatal: unrecoverable, should abort current unit of work
	SevFatal
)

// ScanError wraps an error with severity classification.
type ScanError struct {
	Err      error
	Severity ErrorSeverity
	Context  string
}

func (e *ScanError) Error() string {
	if e.Context != "" {
		return fmt.Sprintf("[%s] %v", e.Context, e.Err)
	}
	return e.Err.Error()
}

func (e *ScanError) Unwrap() error { return e.Err }

// NewScanError creates a classified scan error.
func NewScanError(sev ErrorSeverity, ctx string, err error) error {
	if err == nil {
		return nil
	}
	return &ScanError{Err: err, Severity: sev, Context: ctx}
}
