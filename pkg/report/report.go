package report

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
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
	Number string
	URL    string
	Title  string
	// Fingerprint 是 Web 指纹识别出的技术栈摘要（如 "PHP 8.1, ThinkPHP 6.0"），无命中时为空。
	// 它与 Server / PoweredBy 并列展示，互不覆盖。
	Fingerprint string
	// Confidence 是技术栈命中的最高可信度（certain/probable），无命中时为空。
	Confidence string
	// Technologies 是命中的技术名（不含 WAF/CDN），供报告做分布汇总。
	// Fingerprint 是给人看的拼接串，无法可靠地拆回名字，故单独留一份结构化数据。
	Technologies []string
	Server       string
	PoweredBy    string
	// Redirects 是初始 URL 之后每一次跳转的落点，末位即最终 URL；无跳转时为空。
	Redirects []string
	// FaviconHash 是 favicon 的 mmh3 哈希，未抓取 favicon 时为空。
	FaviconHash string
	// TLS 是 https 目标的证书摘要，非 https 或握手失败时为空。
	TLS *WebProbeTLS
	// WAF 是命中的 WAF/CDN 名称，未识别时为空。
	WAF string
}

// WebProbeTLS 是 https 目标的证书摘要，供报告展示。
type WebProbeTLS struct {
	Subject  string
	Issuer   string
	NotAfter string
}

// webProbeTLSDesc 把证书摘要渲染成一行，如 "example.com · Let's Encrypt · expires 2026-01-01"。
func webProbeTLSDesc(t *WebProbeTLS) string {
	if t == nil {
		return ""
	}
	parts := make([]string, 0, 3)
	for _, s := range []string{t.Subject, t.Issuer} {
		if s = strings.TrimSpace(s); s != "" {
			parts = append(parts, s)
		}
	}
	if exp := strings.TrimSpace(t.NotAfter); exp != "" {
		parts = append(parts, "expires "+exp)
	}
	return strings.Join(parts, " · ")
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
		name, err := createUniqueReportName(OutputDirectory, ".html")
		if err != nil {
			return err
		}
		report.ReportFile = name
		return nil
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

		// 这里只是探测目录可写，文件本身留给后续 Write 创建。清理失败（并发下
		// 可能已被别的进程删掉）不该让整个扫描退出，所以忽略错误。
		_ = os.Remove(fileName)

		return nil
	}

	report.ReportFile = fileName

	return nil
}

// createUniqueReportName 在 dir 下为本次扫描独占一个报告文件名。
//
// 默认报告名是秒级精度的时间戳（MMDD-HHMMSS），同一秒内并发启动的多个 afrog
// 进程会算出同一个名字：彼此覆盖内容，先删的一方还会让另一方拿到 ENOENT。
// 这里用 O_EXCL 原子抢占占位文件，冲突时追加自增序号，既保证跨进程唯一，
// 又让无冲突（绝大多数）情况下的文件名保持原样。
//
// 返回的占位文件已被删除，实际文件由后续 Write 创建。
func createUniqueReportName(dir, ext string) (string, error) {
	base := timeutil.Format(timeutil.Format_1)
	for i := 0; i < 1000; i++ {
		name := base + ext
		if i > 0 {
			name = fmt.Sprintf("%s-%d%s", base, i, ext)
		}
		fileName := filepath.Join(dir, name)

		file, err := os.OpenFile(fileName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0666)
		if err != nil {
			if os.IsExist(err) {
				continue
			}
			return "", fmt.Errorf("unable to create output file: %v", err)
		}
		file.Close()
		_ = os.Remove(fileName)
		return fileName, nil
	}
	return "", fmt.Errorf("unable to create output file: too many reports share the name %q", base)
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
		lines := make([]string, 0, len(entries)+1)
		// 汇总行放在最前，minimal 模板同样先给全貌。
		if summary := summarizeWebProbe(entries).text(); summary != "" {
			lines = append(lines, "summary "+summary)
		}
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
			if fp := strings.TrimSpace(e.Fingerprint); fp != "" {
				if c := strings.TrimSpace(e.Confidence); c != "" {
					fp += " · " + c
				}
				extinfo += "[" + fp + "]"
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
			if w := strings.TrimSpace(e.WAF); w != "" {
				extinfo += "[waf: " + w + "]"
			}
			if len(e.Redirects) > 0 {
				extinfo += "[-> " + strings.Join(e.Redirects, " -> ") + "]"
			}
			if e.TLS != nil {
				extinfo += "[tls: " + webProbeTLSDesc(e.TLS) + "]"
			}
			if h := strings.TrimSpace(e.FaviconHash); h != "" {
				extinfo += "[favicon: " + h + "]"
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

// webProbeAggregate 是整批 Web 资产的分布汇总。
//
// 逐个资产的结果行回答「这个 URL 是什么」；汇总回答「这批目标整体是什么」——
// 扫网段时，真正能支撑决策的是分布：多少站挂着同一款中间件、多少站前面有 WAF、
// 证书都是谁签的。
type webProbeAggregate struct {
	assets  int
	https   int
	techs   map[string]int
	servers map[string]int
	wafs    map[string]int
	issuers map[string]int
}

// webAggregateTop 限制汇总里每一类最多列出多少项，避免网段扫描时刷屏。
const webAggregateTop = 8

func summarizeWebProbe(entries []WebProbeEntry) webProbeAggregate {
	agg := webProbeAggregate{
		assets:  len(entries),
		techs:   make(map[string]int),
		servers: make(map[string]int),
		wafs:    make(map[string]int),
		issuers: make(map[string]int),
	}
	for _, e := range entries {
		if p := webServerProduct(e.Server); p != "" {
			agg.servers[p]++
		}
		if w := strings.TrimSpace(e.WAF); w != "" {
			agg.wafs[w]++
		}
		if e.TLS != nil {
			agg.https++
			if iss := strings.TrimSpace(e.TLS.Issuer); iss != "" {
				agg.issuers[iss]++
			}
		}
		for _, t := range e.Technologies {
			if t = strings.TrimSpace(t); t != "" {
				agg.techs[t]++
			}
		}
	}
	return agg
}

// webServerProduct 从 Server 响应头里取出产品名（去掉版本号），用于聚合分组。
func webServerProduct(server string) string {
	server = strings.ToLower(strings.TrimSpace(server))
	if server == "" {
		return ""
	}
	if i := strings.IndexAny(server, "/ "); i > 0 {
		server = server[:i]
	}
	return strings.TrimSpace(server)
}

type webCountItem struct {
	name  string
	count int
}

// topCounts 把计数表按「次数降序、同次数按名称升序」排序后取前 top 项。
func topCounts(counts map[string]int, top int) []webCountItem {
	items := make([]webCountItem, 0, len(counts))
	for name, count := range counts {
		items = append(items, webCountItem{name: name, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].name < items[j].name
	})
	if top > 0 && len(items) > top {
		items = items[:top]
	}
	return items
}

// html 渲染默认模板的汇总区块；没有任何可汇总信息时返回空串。
func (agg webProbeAggregate) html() string {
	if agg.assets == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="webprobe-summary"><div class="webprobe-summary-row"><span class="webprobe-summary-label">assets</span><span class="webprobe-badges">`)
	b.WriteString(`<span class="webprobe-badge webprobe-summary-assets">`)
	b.WriteString(xssfilter(fmt.Sprintf("%d 个", agg.assets)))
	b.WriteString(`</span>`)
	if agg.https > 0 {
		b.WriteString(`<span class="webprobe-badge">`)
		b.WriteString(xssfilter(fmt.Sprintf("https ×%d", agg.https)))
		b.WriteString(`</span>`)
	}
	b.WriteString(`</span></div>`)

	addRow := func(label string, counts map[string]int, badgeClass string) {
		items := topCounts(counts, webAggregateTop)
		if len(items) == 0 {
			return
		}
		b.WriteString(`<div class="webprobe-summary-row"><span class="webprobe-summary-label">`)
		b.WriteString(xssfilter(label))
		b.WriteString(`</span><span class="webprobe-badges">`)
		for _, it := range items {
			b.WriteString(`<span class="webprobe-badge`)
			if badgeClass != "" {
				b.WriteString(" " + badgeClass)
			}
			b.WriteString(`">`)
			b.WriteString(xssfilter(fmt.Sprintf("%s ×%d", it.name, it.count)))
			b.WriteString(`</span>`)
		}
		b.WriteString(`</span></div>`)
	}
	addRow("tech", agg.techs, "webprobe-fingerprint")
	addRow("server", agg.servers, "")
	addRow("waf", agg.wafs, "webprobe-waf")
	addRow("tls", agg.issuers, "webprobe-tls")
	b.WriteString(`</div>`)
	return b.String()
}

// text 渲染汇总的单行纯文本版本，供 minimal 模板使用。
func (agg webProbeAggregate) text() string {
	if agg.assets == 0 {
		return ""
	}
	parts := []string{fmt.Sprintf("assets=%d", agg.assets)}
	if agg.https > 0 {
		parts = append(parts, fmt.Sprintf("https=%d", agg.https))
	}
	appendCounts := func(label string, counts map[string]int) {
		items := topCounts(counts, webAggregateTop)
		if len(items) == 0 {
			return
		}
		rendered := make([]string, 0, len(items))
		for _, it := range items {
			rendered = append(rendered, fmt.Sprintf("%s(%d)", it.name, it.count))
		}
		parts = append(parts, label+": "+strings.Join(rendered, ", "))
	}
	appendCounts("tech", agg.techs)
	appendCounts("server", agg.servers)
	appendCounts("waf", agg.wafs)
	appendCounts("tls", agg.issuers)
	return strings.Join(parts, " | ")
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
	</thead><tbody><tr><td colspan="3" class="webprobe-td">`)
	// 汇总区块放在资产清单之前：先给全貌，再看逐个条目。
	b.WriteString(summarizeWebProbe(entries).html())
	b.WriteString(`<div class="webprobe-list">`)
	for _, e := range entries {
		no := strings.TrimSpace(e.Number)
		urlStr := strings.TrimSpace(e.URL)
		if urlStr == "" {
			continue
		}
		title := strings.TrimSpace(e.Title)
		fingerprint := strings.TrimSpace(e.Fingerprint)
		if fingerprint != "" {
			if c := strings.TrimSpace(e.Confidence); c != "" {
				fingerprint += " · " + c
			}
		}
		server := strings.TrimSpace(e.Server)
		powered := strings.TrimSpace(e.PoweredBy)
		waf := strings.TrimSpace(e.WAF)
		tlsDesc := webProbeTLSDesc(e.TLS)
		favicon := strings.TrimSpace(e.FaviconHash)
		redirectDesc := strings.Join(e.Redirects, " → ")

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
		if title != "" || fingerprint != "" || server != "" || powered != "" || waf != "" || tlsDesc != "" || favicon != "" || redirectDesc != "" {
			b.WriteString(`<span class="webprobe-badges">`)
			if title != "" {
				b.WriteString(`<span class="webprobe-badge webprobe-title">`)
				b.WriteString(xssfilter(title))
				b.WriteString(`</span>`)
			}
			// 指纹徽标单独一颗：技术栈是信息收集阶段的主要产物，
			// 早先它与 Server/X-Powered-By 被并成一个字段，命中框架后中间件信息就消失了。
			if fingerprint != "" {
				b.WriteString(`<span class="webprobe-badge webprobe-fingerprint">`)
				b.WriteString(xssfilter(fingerprint))
				b.WriteString(`</span>`)
			}
			if server != "" {
				b.WriteString(`<span class="webprobe-badge webprobe-server">`)
				b.WriteString(xssfilter(server))
				b.WriteString(`</span>`)
			}
			if powered != "" {
				b.WriteString(`<span class="webprobe-badge webprobe-powered">`)
				b.WriteString(xssfilter(powered))
				b.WriteString(`</span>`)
			}
			// WAF/CDN 与站点技术栈分开：前面挡了什么决定了后续能打成什么。
			if waf != "" {
				b.WriteString(`<span class="webprobe-badge webprobe-waf">`)
				b.WriteString(xssfilter("waf: " + waf))
				b.WriteString(`</span>`)
			}
			if redirectDesc != "" {
				b.WriteString(`<span class="webprobe-badge webprobe-redirect">`)
				b.WriteString(xssfilter("→ " + redirectDesc))
				b.WriteString(`</span>`)
			}
			if tlsDesc != "" {
				b.WriteString(`<span class="webprobe-badge webprobe-tls">`)
				b.WriteString(xssfilter("tls: " + tlsDesc))
				b.WriteString(`</span>`)
			}
			if favicon != "" {
				b.WriteString(`<span class="webprobe-badge webprobe-favicon">`)
				b.WriteString(xssfilter("favicon: " + favicon))
				b.WriteString(`</span>`)
			}
			b.WriteString(`</span>`)
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div></td></tr></tbody></table>`)
	return b.String()
}
