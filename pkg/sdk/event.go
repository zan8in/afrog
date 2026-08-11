package sdk

import (
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/fingerprint"
	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/utils"
)

// Result is a single finding.
//
// It is the SDK's stable, JSON-serialisable view of a scan result. Raw request
// and response messages are plain strings rather than protobuf []byte fields,
// so encoding/json emits readable text instead of base64.
type Result struct {
	PocID       string   `json:"poc_id"`
	PocName     string   `json:"poc_name,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Author      string   `json:"author,omitempty"`
	Description string   `json:"description,omitempty"`
	Reference   []string `json:"reference,omitempty"`
	Tags        []string `json:"tags,omitempty"`

	CveID       string  `json:"cve_id,omitempty"`
	CweID       string  `json:"cwe_id,omitempty"`
	CvssScore   float64 `json:"cvss_score,omitempty"`
	CvssMetrics string  `json:"cvss_metrics,omitempty"`

	// Target is the seed target; FullTarget is the URL that actually matched.
	Target     string `json:"target"`
	FullTarget string `json:"full_target,omitempty"`

	// Extractors holds the key/value pairs produced by the PoC's extractors.
	Extractors map[string]string `json:"extractors,omitempty"`

	// Fingerprints holds matched fingerprints, for fingerprint results.
	Fingerprints []Fingerprint `json:"fingerprints,omitempty"`

	// Exchanges holds the request/response round trips in execution order. A
	// multi-step PoC produces several. It is empty when request/response
	// capture is disabled via WithRequestResponse(false).
	Exchanges []Exchange `json:"exchanges,omitempty"`

	FoundAt time.Time `json:"found_at"`
}

// Fingerprint is a matched fingerprint.
type Fingerprint struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Severity string `json:"severity,omitempty"`
	Tags     string `json:"tags,omitempty"`
}

// Exchange is one request/response round trip.
type Exchange struct {
	// Request is the raw request message, including the request line, headers
	// and body.
	Request string `json:"request,omitempty"`
	// Response is the raw response message, including the status line, headers
	// and body.
	Response string `json:"response,omitempty"`

	Method          string            `json:"method,omitempty"`
	URL             string            `json:"url,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	RequestBody     string            `json:"request_body,omitempty"`
	StatusCode      int               `json:"status_code,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
	ContentType     string            `json:"content_type,omitempty"`
	LatencyMs       int64             `json:"latency_ms,omitempty"`

	// Matched reports whether this step matched.
	Matched bool `json:"matched"`

	// BodyTruncated reports that ResponseBody was cut at the MaxRespBodySize
	// limit and is therefore not the complete server response.
	BodyTruncated bool `json:"body_truncated,omitempty"`

	// BruteTruncated reports that a brute-force PoC stopped early because it
	// reached BruteMaxRequests.
	BruteTruncated bool `json:"brute_truncated,omitempty"`
	// BruteRequests is the number of brute-force requests actually sent.
	BruteRequests int `json:"brute_requests,omitempty"`
}

// PortEvent reports an open port found during port pre-scanning.
type PortEvent struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// HostEvent reports a live host found during host discovery.
type HostEvent struct {
	Host string `json:"host"`
}

// WebProbeEvent reports the metadata of a probed web service.
type WebProbeEvent struct {
	URL       string `json:"url"`
	Title     string `json:"title,omitempty"`
	Server    string `json:"server,omitempty"`
	PoweredBy string `json:"powered_by,omitempty"`
}

// Phase names reported through PhaseProgress.
const (
	PhaseHostDiscovery = "host_discovery"
	PhasePortScan      = "portscan"
	PhaseWebProbe      = "webprobe"
	PhaseVuln          = "vuln"
)

// PhaseProgress reports the progress of one scan phase.
type PhaseProgress struct {
	// Phase is one of the Phase* constants.
	Phase string `json:"phase"`
	// Status is "running", "completed" or "interrupted".
	Status   string `json:"status"`
	Finished int64  `json:"finished"`
	Total    int64  `json:"total"`
	Percent  int    `json:"percent"`
}

// ScanInfo summarises the scan.
type ScanInfo struct {
	TotalTargets int      `json:"total_targets"`
	TotalPocs    int      `json:"total_pocs"`
	TotalScans   int      `json:"total_scans"`
	Targets      []string `json:"targets,omitempty"`
	OOBEnabled   bool     `json:"oob_enabled"`
	OOBStatus    string   `json:"oob_status,omitempty"`
}

// Failure reports that a single PoC execution failed. A failure never aborts
// the scan; it is surfaced so that callers can observe request errors,
// expression errors and recovered panics instead of losing them silently.
type Failure struct {
	Target string `json:"target"`
	PocID  string `json:"poc_id"`
	Err    error  `json:"-"`
}

func (f Failure) Error() string {
	if f.Err == nil {
		return ""
	}
	return f.Err.Error()
}

func (f Failure) Unwrap() error { return f.Err }

// Stats holds scan counters. Snapshots are returned by Scanner.Stats.
type Stats struct {
	StartTime      time.Time `json:"start_time"`
	EndTime        time.Time `json:"end_time"`
	TotalTargets   int       `json:"total_targets"`
	TotalPocs      int       `json:"total_pocs"`
	TotalScans     int       `json:"total_scans"`
	CompletedScans int64     `json:"completed_scans"`
	FoundVulns     int64     `json:"found_vulns"`
}

// Duration returns the scan duration, measured to now while still running.
func (s Stats) Duration() time.Duration {
	if s.EndTime.IsZero() {
		return time.Since(s.StartTime)
	}
	return s.EndTime.Sub(s.StartTime)
}

// DefaultRedactedHeaders lists the headers that WithRedactedHeaders masks when
// called without arguments. They are the ones that routinely carry
// credentials.
var DefaultRedactedHeaders = []string{
	"authorization",
	"proxy-authorization",
	"cookie",
	"set-cookie",
	"x-api-key",
	"x-auth-token",
	"x-csrf-token",
}

// redactedValue replaces a masked header value.
const redactedValue = "[REDACTED]"

// redactExchange masks credential-bearing headers in both the structured maps
// and the raw messages.
//
// The raw request and response are the whole point of Exchange, so redaction
// is opt-in: enabling it trades debuggability for the guarantee that results
// can be logged or persisted without leaking credentials.
func redactExchange(ex *Exchange, names map[string]struct{}) {
	if len(names) == 0 {
		return
	}
	redactHeaderMap(ex.RequestHeaders, names)
	redactHeaderMap(ex.ResponseHeaders, names)
	ex.Request = redactRawMessage(ex.Request, names)
	ex.Response = redactRawMessage(ex.Response, names)
}

func redactHeaderMap(headers map[string]string, names map[string]struct{}) {
	for k := range headers {
		if _, ok := names[strings.ToLower(k)]; ok {
			headers[k] = redactedValue
		}
	}
}

// redactRawMessage masks header lines in a raw HTTP message, stopping at the
// blank line that separates headers from the body.
func redactRawMessage(raw string, names map[string]struct{}) string {
	if raw == "" {
		return raw
	}
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		if trimmed == "" {
			break // end of headers
		}
		colon := strings.IndexByte(trimmed, ':')
		if colon <= 0 {
			continue
		}
		if _, ok := names[strings.ToLower(strings.TrimSpace(trimmed[:colon]))]; !ok {
			continue
		}
		suffix := ""
		if strings.HasSuffix(line, "\r") {
			suffix = "\r"
		}
		lines[i] = trimmed[:colon] + ": " + redactedValue + suffix
	}
	return strings.Join(lines, "\n")
}

// newResult converts an internal result into the SDK view. When includeRR is
// false the raw exchanges are dropped, which keeps memory bounded on large
// scans.
func newResult(r *result.Result, includeRR bool, foundAt time.Time) Result {
	out := Result{
		Target:     r.Target,
		FullTarget: r.FullTarget,
		FoundAt:    foundAt,
	}
	if strings.TrimSpace(out.FullTarget) == "" {
		out.FullTarget = out.Target
	}

	if pi := r.PocInfo; pi != nil {
		out.PocID = pi.Id
		out.PocName = pi.Info.Name
		out.Severity = pi.Info.Severity
		out.Author = pi.Info.Author
		out.Description = pi.Info.Description
		out.Reference = append([]string(nil), pi.Info.Reference...)
		out.Tags = splitAndTrim(pi.Info.Tags)
		out.CveID = pi.Info.Classification.CveId
		out.CweID = pi.Info.Classification.CweId
		out.CvssScore = pi.Info.Classification.CvssScore
		out.CvssMetrics = pi.Info.Classification.CvssMetrics
	}

	if len(r.Extractor) > 0 {
		out.Extractors = make(map[string]string, len(r.Extractor))
		for _, item := range r.Extractor {
			key, ok := item.Key.(string)
			if !ok {
				continue
			}
			if v, ok := item.Value.(string); ok {
				out.Extractors[key] = utils.Str2UTF8(v)
			}
		}
	}

	if hits, ok := r.FingerResult.([]fingerprint.Hit); ok {
		for _, h := range hits {
			out.Fingerprints = append(out.Fingerprints, Fingerprint{
				ID:       h.ID,
				Name:     h.Name,
				Severity: h.Severity,
				Tags:     h.Tags,
			})
		}
	}

	if includeRR {
		for _, pr := range r.AllPocResult {
			if pr == nil {
				continue
			}
			out.Exchanges = append(out.Exchanges, newExchange(pr))
		}
	}

	return out
}

// newResultRedacted is newResult with credential-bearing headers masked.
func newResultRedacted(r *result.Result, includeRR bool, foundAt time.Time, redact map[string]struct{}) Result {
	out := newResult(r, includeRR, foundAt)
	for i := range out.Exchanges {
		redactExchange(&out.Exchanges[i], redact)
	}
	return out
}

func newExchange(pr *result.PocResult) Exchange {
	ex := Exchange{
		Matched:        pr.IsVul,
		BodyTruncated:  pr.BodyTruncated,
		BruteTruncated: pr.BruteTruncated,
		BruteRequests:  pr.BruteRequests,
	}

	if req := pr.ResultRequest; req != nil {
		ex.Request = utils.Str2UTF8(string(req.GetRaw()))
		ex.Method = req.GetMethod()
		ex.RequestHeaders = copyStringMap(req.GetHeaders())
		ex.RequestBody = utils.Str2UTF8(string(req.GetBody()))
		ex.URL = protoURL(req.GetUrl())
	}

	if resp := pr.ResultResponse; resp != nil {
		ex.Response = utils.Str2UTF8(string(resp.GetRaw()))
		ex.StatusCode = int(resp.GetStatus())
		ex.ResponseHeaders = copyStringMap(resp.GetHeaders())
		ex.ResponseBody = utils.Str2UTF8(string(resp.GetBody()))
		ex.ContentType = resp.GetContentType()
		ex.LatencyMs = resp.GetLatency()
		if ex.URL == "" {
			ex.URL = protoURL(resp.GetUrl())
		}
	}

	return ex
}

func protoURL(u *proto.UrlType) string {
	if u == nil {
		return ""
	}
	scheme, host := u.GetScheme(), u.GetHost()
	if scheme == "" && host == "" {
		return ""
	}
	out := scheme + "://" + host + u.GetPath()
	if q := u.GetQuery(); q != "" {
		out += "?" + q
	}
	if f := u.GetFragment(); f != "" {
		out += "#" + f
	}
	return out
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func splitAndTrim(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}
