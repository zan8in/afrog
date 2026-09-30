package webreport

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
)

// HTMLOptions 控制 HTML 报告的呈现方式。
type HTMLOptions struct {
	// AutoPrint 为 true 时页面加载后自动唤起打印对话框，供「导出 PDF」使用。
	AutoPrint bool
}

type htmlView struct {
	Doc       Document
	GenAt     string
	Total     int
	AutoPrint bool
	Watermark bool
	BrandLine string
	SubLines  []string
	Filter    string
}

// RenderHTML 生成自包含（无外部 CSS/JS 依赖）的 HTML 报告。
// 样式全部内联，便于离线查看、邮件附件与浏览器打印为 PDF。
func RenderHTML(doc Document, opts HTMLOptions) ([]byte, error) {
	view := htmlView{
		Doc:       doc,
		GenAt:     doc.Meta.GeneratedAt.Format("2006-01-02 15:04:05"),
		Total:     doc.Total(),
		AutoPrint: opts.AutoPrint,
		Watermark: doc.Brand.Watermark,
	}
	view.BrandLine = brandLine(doc.Brand)
	view.SubLines = subLines(doc.Meta)
	view.Filter = filterLine(doc.Meta)

	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, view); err != nil {
		return nil, fmt.Errorf("render html report: %w", err)
	}
	return buf.Bytes(), nil
}

func brandLine(b Brand) string {
	product := strings.TrimSpace(b.Product)
	if product == "" {
		product = "afrog"
	}
	if v := strings.TrimSpace(b.Version); v != "" {
		product += " v" + v
	}
	if site := strings.TrimSpace(b.Site); site != "" {
		return product + " · " + site
	}
	return product
}

func subLines(m Meta) []string {
	out := make([]string, 0, 4)
	if v := strings.TrimSpace(m.Subject); v != "" {
		out = append(out, "对象："+v)
	}
	if v := strings.TrimSpace(m.ProjectName); v != "" {
		out = append(out, "项目："+v)
	}
	if len(m.TaskIDs) == 1 {
		out = append(out, "任务："+m.TaskIDs[0])
	} else if len(m.TaskIDs) > 1 {
		out = append(out, fmt.Sprintf("任务：%d 个（%s …）", len(m.TaskIDs), m.TaskIDs[0]))
	}
	if len(m.Targets) > 0 {
		head := m.Targets
		if len(head) > 5 {
			head = head[:5]
		}
		line := "目标：" + strings.Join(head, "、")
		if len(m.Targets) > 5 {
			line += fmt.Sprintf(" 等 %d 个", len(m.Targets))
		}
		out = append(out, line)
	}
	return out
}

func filterLine(m Meta) string {
	var parts []string
	if len(m.Severities) > 0 {
		parts = append(parts, "严重级别 "+strings.Join(m.Severities, "/"))
	}
	if kw := strings.TrimSpace(m.Keyword); kw != "" {
		parts = append(parts, "关键字「"+kw+"」")
	}
	if len(parts) == 0 {
		return ""
	}
	line := "筛选条件：" + strings.Join(parts, "，")
	if note := strings.TrimSpace(m.ScopeNote); note != "" {
		line += "（" + note + "）"
	}
	return line
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"sevClass": func(s string) string { return "sev-" + SeverityLabel(s) },
	"isEmpty":  func(s string) bool { return strings.TrimSpace(s) == "" },
	"add":      func(a, b int) int { return a + b },
}).Parse(htmlReportTemplate))

const htmlReportTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ .Doc.Meta.Title }}{{ if .Doc.Meta.Subject }} - {{ .Doc.Meta.Subject }}{{ end }}</title>
<style>
:root {
  --fg: #16181d;
  --fg-muted: #5c6370;
  --border: #e2e5ea;
  --bg-soft: #f7f8fa;
  --critical: #b91c1c;
  --high: #ea580c;
  --medium: #d97706;
  --low: #0284c7;
  --info: #64748b;
  --unknown: #64748b;
  --brand: #0f766e;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  padding: 24px;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
  font-size: 13px;
  line-height: 1.6;
  color: var(--fg);
  background: #fff;
}
.wrap { max-width: 1080px; margin: 0 auto; }

/* ---------- 顶部工具栏（不打印） ---------- */
.toolbar {
  position: sticky; top: 0; z-index: 20;
  display: flex; align-items: center; gap: 8px;
  margin: -24px -24px 20px; padding: 10px 24px;
  background: rgba(255,255,255,.92);
  border-bottom: 1px solid var(--border);
  backdrop-filter: blur(6px);
}
.toolbar .spacer { flex: 1; }
.toolbar button {
  font: inherit; cursor: pointer; border-radius: 6px; padding: 6px 12px;
  border: 1px solid var(--border); background: #fff; color: var(--fg);
}
.toolbar button.primary { background: var(--brand); border-color: var(--brand); color: #fff; }

/* ---------- 页眉 ---------- */
.report-head { border-bottom: 2px solid var(--fg); padding-bottom: 12px; margin-bottom: 18px; }
.report-head h1 { margin: 0 0 6px; font-size: 22px; line-height: 1.3; }
.report-head .brand { font-size: 12px; color: var(--fg-muted); letter-spacing: .04em; text-transform: uppercase; }
.report-head .subs { margin-top: 8px; color: var(--fg-muted); font-size: 12px; display: flex; flex-wrap: wrap; gap: 4px 16px; }
.report-head .filter { margin-top: 6px; font-size: 12px; color: var(--fg-muted); }

.notice {
  margin: 0 0 16px; padding: 8px 12px; font-size: 12px;
  border: 1px solid #f0d9a8; background: #fdf6e6; color: #7a5b0f; border-radius: 6px;
}

/* ---------- 概览 ---------- */
.section { margin-top: 24px; }
.section > h2 {
  font-size: 15px; margin: 0 0 10px; padding-bottom: 6px;
  border-bottom: 1px solid var(--border);
}
.cards { display: flex; flex-wrap: wrap; gap: 8px; }
.card {
  flex: 1 1 120px; min-width: 108px; padding: 10px 12px;
  border: 1px solid var(--border); border-radius: 8px; background: var(--bg-soft);
}
.card .k { font-size: 11px; color: var(--fg-muted); text-transform: uppercase; letter-spacing: .04em; }
.card .v { font-size: 20px; font-weight: 600; margin-top: 2px; }

/* ---------- 表格 ---------- */
table { width: 100%; border-collapse: collapse; }
th, td { border: 1px solid var(--border); padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: var(--bg-soft); font-weight: 600; font-size: 12px; white-space: nowrap; }
td.num, th.num { text-align: right; white-space: nowrap; }
td.mono, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.nowrap { white-space: nowrap; }
.wrap-any { word-break: break-all; }

/* ---------- 严重级别 ---------- */
.sev { font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: .03em; }
.sev-critical { color: var(--critical); }
.sev-high { color: var(--high); }
.sev-medium { color: var(--medium); }
.sev-low { color: var(--low); }
.sev-info { color: var(--info); }
.sev-unknown { color: var(--unknown); }
.pill { display: inline-block; padding: 1px 7px; border-radius: 999px; border: 1px solid currentColor; font-size: 11px; }

/* ---------- 明细 ---------- */
.finding { border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; margin-bottom: 12px; }
.finding-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px; }
.finding-head .idx { font-weight: 600; color: var(--fg-muted); }
.finding-head .name { font-weight: 600; font-size: 14px; }
.finding-meta { margin-top: 6px; font-size: 12px; color: var(--fg-muted); display: flex; flex-wrap: wrap; gap: 4px 16px; }
.block { margin-top: 10px; }
.block > h4 { margin: 0 0 4px; font-size: 12px; color: var(--fg-muted); font-weight: 600; }
pre {
  margin: 0; padding: 8px 10px; background: var(--bg-soft);
  border: 1px solid var(--border); border-radius: 6px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 11.5px; line-height: 1.5;
  white-space: pre-wrap; word-break: break-word;
  max-height: 320px; overflow: auto;
}
ul.refs { margin: 0; padding-left: 18px; }
ul.refs li { word-break: break-all; }
.evidence { margin-top: 8px; border-top: 1px dashed var(--border); padding-top: 8px; }
.evidence .ev-head { font-size: 12px; color: var(--fg-muted); margin-bottom: 4px; }

.report-foot {
  margin-top: 28px; padding-top: 10px; border-top: 1px solid var(--border);
  font-size: 11px; color: var(--fg-muted); display: flex; justify-content: space-between; gap: 12px;
}

/* ---------- 打印 ---------- */
@page { size: A4; margin: 12mm 10mm; }
@media print {
  body { padding: 0; font-size: 11pt; }
  .no-print { display: none !important; }
  .wrap { max-width: none; }
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .finding, tr, .card { page-break-inside: avoid; break-inside: avoid; }
  .finding { break-inside: auto; page-break-inside: auto; }
  pre { max-height: none; overflow: visible; }
  .section > h2 { page-break-after: avoid; }
  .report-foot { position: fixed; bottom: 0; left: 0; right: 0; border-top: 1px solid #ccc; background: #fff; }
  .watermark {
    position: fixed; top: 42%; left: 0; right: 0; text-align: center;
    font-size: 64pt; font-weight: 700; color: rgba(15,118,110,.06);
    transform: rotate(-18deg); z-index: 0; pointer-events: none;
  }
  body > .wrap { position: relative; z-index: 1; }
}
</style>
</head>
<body>
{{ if .Watermark }}<div class="watermark">{{ .BrandLine }}</div>{{ end }}

<div class="no-print toolbar">
  <strong>{{ .BrandLine }}</strong>
  <span class="spacer"></span>
  <button class="primary" onclick="window.print()">打印 / 另存为 PDF</button>
  <button onclick="window.close()">关闭</button>
</div>

<div class="wrap">
  <header class="report-head">
    <div class="brand">{{ .BrandLine }}</div>
    <h1>{{ .Doc.Meta.Title }}{{ if .Doc.Meta.Subject }} · {{ .Doc.Meta.Subject }}{{ end }}</h1>
    <div class="subs">
      {{ range .SubLines }}<span>{{ . }}</span>{{ end }}
      <span>生成时间：{{ .GenAt }}</span>
    </div>
    {{ if .Filter }}<div class="filter">{{ .Filter }}</div>{{ end }}
  </header>

  {{ if .Doc.Truncated }}
    <div class="notice">结果集较大，本报告仅收录最近的部分命中，请缩小筛选范围后重新导出以获得完整报告。</div>
  {{ end }}

  <section class="section">
    <h2>概览</h2>
    <div class="cards">
      <div class="card">
        <div class="k">漏洞条目</div>
        <div class="v">{{ .Total }}</div>
      </div>
      <div class="card">
        <div class="k">原始命中</div>
        <div class="v">{{ .Doc.RawHits }}</div>
      </div>
      {{ range .Doc.Counts }}
        <div class="card">
          <div class="k"><span class="{{ sevClass .Severity }}">{{ .Severity }}</span></div>
          <div class="v">{{ .Count }}</div>
        </div>
      {{ end }}
    </div>
  </section>

  <section class="section">
    <h2>漏洞清单</h2>
    {{ if not .Doc.Findings }}
      <p style="color:var(--fg-muted)">没有符合条件的命中记录。</p>
    {{ else }}
    <table>
      <thead>
        <tr>
          <th class="num">#</th>
          <th>严重级别</th>
          <th>PoC</th>
          <th>目标</th>
          <th class="num">命中次数</th>
          <th class="nowrap">首次发现</th>
        </tr>
      </thead>
      <tbody>
        {{ range $i, $f := .Doc.Findings }}
        <tr>
          <td class="num">{{ add $i 1 }}</td>
          <td class="nowrap"><span class="sev {{ sevClass $f.Severity }}">{{ $f.Severity }}</span></td>
          <td>
            <div class="mono wrap-any">{{ $f.VulID }}</div>
            {{ if $f.VulName }}<div style="color:var(--fg-muted)">{{ $f.VulName }}</div>{{ end }}
          </td>
          <td class="wrap-any">
            {{ $f.Target }}
            {{ if and $f.FullTarget (ne $f.FullTarget $f.Target) }}<div class="mono" style="color:var(--fg-muted);font-size:11px">{{ $f.FullTarget }}</div>{{ end }}
          </td>
          <td class="num">{{ $f.HitCount }}</td>
          <td class="nowrap">{{ $f.FirstSeen }}</td>
        </tr>
        {{ end }}
      </tbody>
    </table>
    {{ end }}
  </section>

  {{ if .Doc.Findings }}
  <section class="section">
    <h2>漏洞明细</h2>
    {{ range $i, $f := .Doc.Findings }}
    <div class="finding">
      <div class="finding-head">
        <span class="idx">#{{ add $i 1 }}</span>
        <span class="pill {{ sevClass $f.Severity }}">{{ $f.Severity }}</span>
        <span class="name">{{ if $f.VulName }}{{ $f.VulName }}{{ else }}{{ $f.VulID }}{{ end }}</span>
      </div>
      <div class="finding-meta">
        <span class="mono">{{ $f.VulID }}</span>
        <span>目标：{{ $f.FullTarget }}{{ if not $f.FullTarget }}{{ $f.Target }}{{ end }}</span>
        <span>命中 {{ $f.HitCount }} 次</span>
        {{ if $f.FirstSeen }}<span>首次发现：{{ $f.FirstSeen }}</span>{{ end }}
      </div>

      {{ if not (isEmpty $f.Description) }}
        <div class="block"><h4>漏洞描述</h4><pre>{{ $f.Description }}</pre></div>
      {{ end }}
      {{ if not (isEmpty $f.Affected) }}
        <div class="block"><h4>影响版本</h4><pre>{{ $f.Affected }}</pre></div>
      {{ end }}
      {{ if not (isEmpty $f.Solutions) }}
        <div class="block"><h4>解决方案</h4><pre>{{ $f.Solutions }}</pre></div>
      {{ end }}
      {{ if $f.References }}
        <div class="block">
          <h4>参考资料</h4>
          <ul class="refs">{{ range $f.References }}<li>{{ . }}</li>{{ end }}</ul>
        </div>
      {{ end }}

      {{ if $f.Evidences }}
        <div class="block">
          <h4>请求响应证据</h4>
          {{ range $j, $ev := $f.Evidences }}
            {{ if or $ev.Request $ev.Response }}
            <div class="evidence">
              <div class="ev-head">
                证据 {{ add $j 1 }}
                {{ if $ev.FullTarget }}· <span class="mono">{{ $ev.FullTarget }}</span>{{ end }}
                {{ if $ev.Latency }}· {{ $ev.Latency }} ms{{ end }}
              </div>
              {{ if $ev.Request }}<pre>{{ $ev.Request }}</pre>{{ end }}
              {{ if $ev.Response }}<pre style="margin-top:6px">{{ $ev.Response }}</pre>{{ end }}
            </div>
            {{ end }}
          {{ end }}
        </div>
      {{ end }}
    </div>
    {{ end }}
  </section>
  {{ end }}

  <footer class="report-foot">
    <span>{{ .BrandLine }}</span>
    <span>生成时间：{{ .GenAt }}</span>
  </footer>
</div>

{{ if .AutoPrint }}
<script>window.addEventListener('load', function () { setTimeout(function () { window.print(); }, 400); });</script>
{{ end }}
</body>
</html>
`
