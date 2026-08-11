package sdk

import "errors"

// Sentinel errors returned by the SDK. Callers should match them with
// errors.Is rather than comparing error strings.
var (
	// ErrNoTargets is returned when no scan target was configured.
	ErrNoTargets = errors.New("afrog/sdk: no targets available")

	// ErrNoPocs is returned when no PoC is executable, either because the
	// configured paths matched nothing or because every PoC was filtered out.
	ErrNoPocs = errors.New("afrog/sdk: no pocs available")

	// ErrPocPathNotFound is returned when a PoC path resolves to no
	// .yaml/.yml file.
	ErrPocPathNotFound = errors.New("afrog/sdk: poc path not found")

	// ErrAlreadyRunning is returned when a scan is already in progress.
	ErrAlreadyRunning = errors.New("afrog/sdk: scan is already running")

	// ErrAlreadyFinished is returned when a finished scanner is reused. A
	// scanner is single-use; create a new one to scan again.
	ErrAlreadyFinished = errors.New("afrog/sdk: scan has already finished")

	// ErrClosed is returned when the scanner has been closed.
	ErrClosed = errors.New("afrog/sdk: scanner is closed")

	// ErrNotStarted is returned by Wait when the scan was never started.
	ErrNotStarted = errors.New("afrog/sdk: scan has not been started")

	// ErrInvalidOptions is returned when the option combination is invalid.
	ErrInvalidOptions = errors.New("afrog/sdk: invalid options")

	// ErrWebhookTokenRequired is returned when a webhook notifier is enabled
	// without a token.
	ErrWebhookTokenRequired = errors.New("afrog/sdk: webhook token is required")
)

// CuratedMountError reports that the optional curated PoC source could not be
// mounted. It is never fatal: the scan proceeds without that source.
type CuratedMountError struct {
	Err error
}

func (e *CuratedMountError) Error() string {
	return "afrog/sdk: curated mount failed: " + e.Err.Error()
}

func (e *CuratedMountError) Unwrap() error { return e.Err }
