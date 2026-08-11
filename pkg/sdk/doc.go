/*
Package sdk is the Go API of the afrog vulnerability scanner.

# Getting started

A scan is built from functional options and driven by a context:

	scanner, err := sdk.New(ctx,
		sdk.WithTargets("https://example.com"),
		sdk.WithPocPaths("./pocs/afrog-pocs"),
	)
	if err != nil {
		return err
	}
	defer scanner.Close()

	if err := scanner.Execute(ctx); err != nil {
		return err
	}
	for _, r := range scanner.Results() {
		fmt.Println(r.PocID, r.FullTarget)
	}

# Synchronous and asynchronous execution

Execute runs the scan and returns when it finishes. For asynchronous use, Start
returns immediately and completion is observed with Wait or Done:

	if err := scanner.Start(ctx); err != nil {
		return err
	}
	for {
		select {
		case <-ticker.C:
			log.Printf("%.1f%%", scanner.Progress())
		case <-scanner.Done():
			return scanner.Err()
		}
	}

A Scanner is single-use. Once a scan finishes, Start and Execute return
[ErrAlreadyFinished]; create a new Scanner to scan again.

# PoC input

WithPocPaths accepts a single file, a directory searched recursively, or a glob
pattern, and may be repeated:

	sdk.WithPocPaths("a.yaml", "./pocs", "./extra/*.yaml")

Paths are merged with the built-in PoCs. WithPocPathsOnly restricts the scan to
the listed paths. Pocs reports what was loaded and PocDiagnostics reports what
was skipped and why, so a malformed or deprecated PoC is visible to the caller
instead of only being printed to a console.

# Results

Results returns [Result] values. Each carries the complete request and response
of every step in [Exchange], as readable strings rather than protobuf byte
slices, so the whole structure can be passed straight to encoding/json.

Use WithRequestResponse(false) to drop the raw exchanges and WithMaxStoredResults
to cap accumulation on large scans. Neither affects handlers or streams, which
always observe every finding.

# Handlers and streams

Results can be consumed in two ways. Handlers are callbacks registered at
construction time:

	sdk.WithResultHandler(func(r sdk.Result) { ... })
	sdk.WithFailureHandler(func(f sdk.Failure) { ... })

Handlers are invoked concurrently from scan workers, so they must synchronise
their own state.

Streams are channels obtained from ResultStream, PortStream, HostStream,
WebProbeStream, ProgressStream and ScanInfoStream. A stream publishes nothing
until it is first subscribed to, so an unused stream costs nothing and cannot
stall the scan. Once subscribed it must be consumed: sends block when the
buffer fills, because silently discarding a finding is not an acceptable
failure mode for a scanner. Every stream is closed when the scan finishes, so
a range loop always terminates.

# Errors

Failures are reported with sentinel errors and matched using errors.Is:

	if errors.Is(err, sdk.ErrPocPathNotFound) { ... }

# Output

The SDK writes nothing to stdout or stderr. Use Info to obtain the scan summary
as a struct, or WithVerbose to opt into printing it.

# Resource management

Close stops the scan, waits for the scan goroutine to exit and releases every
background goroutine, including the out-of-band poll loop. Always defer it.

# Concurrency

A Scanner is safe for concurrent use. Running several scanners concurrently in
one process is not: the HTTP client, the rate limiter and the protocol probe
cache are process-global, so concurrent scanners overwrite each other's proxy,
timeout and rate-limit settings. Scan batches sequentially, or isolate them in
separate processes.
*/
package sdk
