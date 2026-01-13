package report

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/afrog/v3/pkg/result"
	fileutil "github.com/zan8in/pins/file"
	timeutil "github.com/zan8in/pins/time"
)

type Report struct {
	sync.RWMutex
	Result     *result.Result
	of         *os.File
	ReportFile string
	Template   TemplateStyle
}

type WebProbeEntry struct {
	Number    string
	URL       string
	Title     string
	Server    string
	PoweredBy string
}

type TemplateStyle int

const (
	DefaultTemplate TemplateStyle = iota
	MinimalTemplate
)

const OutputDirectory = "./reports"

// fileName: the name of the report file
// template: the name of the template
func NewReport(fileName string, template TemplateStyle) (*Report, error) {
	r := &Report{
		Result:   &result.Result{},
		Template: template,
	}

	if err := r.check(fileName); err != nil {
		return nil, err
	}

	return r, nil
}

func (report *Report) check(fileName string) error {
	if len(fileName) == 0 {
		if !fileutil.FolderExists(OutputDirectory) {
			fileutil.CreateFolder(OutputDirectory)
		}
		fileName = filepath.Join(OutputDirectory, timeutil.Format(timeutil.Format_1)+".html")
		report.ReportFile = fileName
	}

	suffix := path.Ext(fileName)
	if suffix != ".html" && suffix != ".htm" {
		return fmt.Errorf("please change the file extension of the output to .html or .htm. Unable to create output file")
	}

	_, err := os.Stat(fileName)
	if os.IsNotExist(err) {
		file, err := os.Create(fileName)
		if err != nil {
			return fmt.Errorf("unable to create output file: %v", err)
		}
		file.Close()
		time.Sleep(100 * time.Millisecond)

		report.ReportFile = fileName

		return os.Remove(fileName)

	}

	report.ReportFile = fileName

	return nil
}

func (report *Report) SetResult(result *result.Result) {
	report.Lock()
	defer report.Unlock()

	report.Result = result
}

func (report *Report) Append(number string) error {
	return report.Write(report.html(number))
}

func (report *Report) AppendWebProbe(lines []string) error {
	return report.Write(report.webProbeHtml(lines))
}

func (report *Report) AppendWebProbeEntries(entries []WebProbeEntry) error {
	return report.Write(report.webProbeEntriesHtml(entries))
}

func (report *Report) Write(data string) error {
	if len(data) == 0 {
		return nil
	}

	report.Lock()
	defer report.Unlock()

	flag := os.O_WRONLY | os.O_CREATE
	if report.of == nil {
		flag |= os.O_TRUNC
	} else {
		flag |= os.O_APPEND
	}

	f, err := os.OpenFile(report.ReportFile, flag, 0666)
	if err != nil {
		return err
	}
	defer f.Close()

	if report.of == nil {
		report.of = f
		header := report.header()
		if len(header) > 0 {
			wbuf := bufio.NewWriterSize(f, len(header))
			wbuf.WriteString(header)
			wbuf.Flush()
		}
	}

	wbuf := bufio.NewWriterSize(f, len(data))
	wbuf.WriteString(data)
	wbuf.Flush()

	return nil
}

func (report *Report) header() string {
	switch report.Template {
	case DefaultTemplate:
		return defaultHeader()
	case MinimalTemplate:
		return minimalHeader()
	}
	return ""
}

func (report *Report) html(number string) string {
	switch report.Template {
	case DefaultTemplate:
		return report.defaultHmtl(number)
	case MinimalTemplate:
		return report.minimalHtml(number)
	}
	return ""
}

func (report *Report) webProbeHtml(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	switch report.Template {
	case DefaultTemplate:
		return report.webProbeDefaultHtml(lines)
	case MinimalTemplate:
		return report.webProbeMinimalHtml(lines)
	}
	return ""
}

func (report *Report) webProbeEntriesHtml(entries []WebProbeEntry) string {
	if len(entries) == 0 {
		return ""
	}
	switch report.Template {
	case DefaultTemplate:
		return report.webProbeDefaultHtmlEntries(entries)
	case MinimalTemplate:
		lines := make([]string, 0, len(entries))
		for _, e := range entries {
			line := strings.TrimSpace(e.Number)
			if line == "" {
				continue
			}
			urlStr := strings.TrimSpace(e.URL)
			if urlStr == "" {
				continue
			}
			extinfo := ""
			if t := strings.TrimSpace(e.Title); t != "" {
				extinfo += "[" + t + "]"
			}
			serverOrPowered := ""
			if s := strings.TrimSpace(e.Server); s != "" {
				serverOrPowered = s
			}
			if p := strings.TrimSpace(e.PoweredBy); p != "" {
				if serverOrPowered == "" {
					serverOrPowered = p
				} else {
					serverOrPowered += "," + p
				}
			}
			if serverOrPowered != "" {
				extinfo += "[" + serverOrPowered + "]"
			}
			if extinfo == "" {
				lines = append(lines, fmt.Sprintf("%s %s", line, urlStr))
			} else {
				lines = append(lines, fmt.Sprintf("%s %s %s", line, urlStr, extinfo))
			}
		}
		return report.webProbeMinimalHtml(lines)
	}
	return ""
}

func (report *Report) webProbeDefaultHtml(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<table>
	<thead onclick="$(this).next('tbody').toggle()" style="background:#DDE2DE">
		<td class="vuln">webprobe</td>
		<td class="security info">INFO</td>
		<td class="url">webprobe</td>
	</thead><tbody>`)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		b.WriteString(`<tr><td colspan="3" style="background: #223B46; color: #DDE2DE; border-top:1px solid #60786F"><xmp>`)
		b.WriteString(xssfilter(line))
		b.WriteString(`</xmp></td></tr>`)
	}
	b.WriteString(`</tbody></table>`)
	return b.String()
}

func (report *Report) webProbeMinimalHtml(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	body := strings.Join(lines, "\n")
	body = xssfilter(body)
	return fmt.Sprintf(`<div class="vuln-item">
		<div class="vuln-header" onclick="toggleDetails(this)">
			<span class="vuln-id">WP</span>
			<span class="vuln-name">webprobe</span>
			<span class="severity info">INFO</span>
			<span class="target">webprobe</span>
			<span class="toggle-icon">▼</span>
		</div>
		<div class="vuln-details">
			<div class="info-section">
				<h4>WebProbe</h4>
				<pre class="code-block">%s</pre>
			</div>
		</div>
	</div>`, body)
}

func (report *Report) webProbeDefaultHtmlEntries(entries []WebProbeEntry) string {
	if len(entries) == 0 {
		return ""
	}
	isSafeHref := func(s string) bool {
		s = strings.TrimSpace(strings.ToLower(s))
		return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
	}
	escapeAttr := func(s string) string {
		s = xssfilter(s)
		s = strings.ReplaceAll(s, `"`, "%22")
		return s
	}
	var b strings.Builder
	b.WriteString(`<table class="webprobe-table">
	<thead onclick="$(this).next('tbody').toggle()" style="background:#DDE2DE">
		<td class="vuln">webprobe</td>
		<td class="security info">INFO</td>
		<td class="url">count: `)
	b.WriteString(fmt.Sprintf("%d", len(entries)))
	b.WriteString(`</td>
	</thead><tbody><tr><td colspan="3" class="webprobe-td"><div class="webprobe-list">`)
	for _, e := range entries {
		no := strings.TrimSpace(e.Number)
		urlStr := strings.TrimSpace(e.URL)
		if urlStr == "" {
			continue
		}
		title := strings.TrimSpace(e.Title)
		server := strings.TrimSpace(e.Server)
		powered := strings.TrimSpace(e.PoweredBy)
		serverOrPowered := strings.TrimSpace(strings.Trim(strings.Join([]string{server, powered}, ","), ","))
		if server == "" || powered == "" {
			if server == "" {
				serverOrPowered = powered
			} else {
				serverOrPowered = server
			}
		}

		b.WriteString(`<div class="webprobe-item">`)
		if no != "" {
			b.WriteString(`<span class="webprobe-no">`)
			b.WriteString(xssfilter(no))
			b.WriteString(`</span>`)
		}
		if isSafeHref(urlStr) {
			b.WriteString(`<a class="webprobe-url" href="`)
			b.WriteString(escapeAttr(urlStr))
			b.WriteString(`" target="_blank">`)
			b.WriteString(xssfilter(urlStr))
			b.WriteString(`</a>`)
		} else {
			b.WriteString(`<span class="webprobe-url">`)
			b.WriteString(xssfilter(urlStr))
			b.WriteString(`</span>`)
		}
		if title != "" || serverOrPowered != "" {
			b.WriteString(`<span class="webprobe-badges">`)
			if title != "" {
				b.WriteString(`<span class="webprobe-badge webprobe-title">`)
				b.WriteString(xssfilter(title))
				b.WriteString(`</span>`)
			}
			if serverOrPowered != "" {
				b.WriteString(`<span class="webprobe-badge webprobe-server">`)
				b.WriteString(xssfilter(serverOrPowered))
				b.WriteString(`</span>`)
			}
			b.WriteString(`</span>`)
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div></td></tr></tbody></table>`)
	return b.String()
}
