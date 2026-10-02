package webreport

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/xuri/excelize/v2"
	"github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/poc"
)

func sampleRows() []db.ResultData {
	return []db.ResultData{
		{
			ID: 3, TaskID: "20260928-00002-ab12cd", VulID: "webprobe", VulName: "webprobe",
			Target: "http://scanme.nmap.org", FullTarget: "http://scanme.nmap.org",
			Severity: "INFO", Created: "2026-09-28 14:30:00",
			ResultList: []db.PocResult{{FullTarget: "http://scanme.nmap.org", Request: "GET / HTTP/1.1", Response: "HTTP/1.1 200 OK", Other: db.Other{Latency: 42}}},
		},
		{
			ID: 2, TaskID: "20260928-00002-ab12cd", VulID: "directory-listing", VulName: "目录浏览",
			Target: "http://scanme.nmap.org", FullTarget: "http://scanme.nmap.org/icons/",
			Severity: "MEDIUM", Created: "2026-09-28 14:29:00",
			PocInfo: poc.Poc{Info: poc.Info{
				Name:        "目录浏览",
				Description: "目标开启了目录浏览",
				Solutions:   "关闭目录浏览",
				Reference:   []string{"https://example.com/a"},
			}},
		},
		// 同 PoC + 同目标再次命中：应聚合为同一条，HitCount 累加。
		{
			ID: 1, TaskID: "20260928-00002-ab12cd", VulID: "directory-listing", VulName: "目录浏览",
			Target: "http://scanme.nmap.org", FullTarget: "http://scanme.nmap.org/icons/",
			Severity: "MEDIUM", Created: "2026-09-28 14:20:00",
		},
	}
}

func sampleDoc() Document {
	meta := Meta{
		Title:       "扫描报告",
		Subject:     "Nmap 复测",
		ProjectName: "Nmap",
		TaskIDs:     []string{"20260928-00002-ab12cd"},
		Targets:     []string{"scanme.nmap.org"},
		GeneratedAt: time.Date(2026, 9, 28, 15, 0, 0, 0, time.UTC),
	}
	brand := Brand{Product: "afrog", Site: "afrog.zan8in.com", Watermark: true}
	return Build(meta, brand, sampleRows(), false)
}

func TestBuildAggregatesByPoCAndTarget(t *testing.T) {
	doc := sampleDoc()

	if doc.Total() != 2 {
		t.Fatalf("findings = %d, want 2", doc.Total())
	}
	if doc.RawHits != 3 {
		t.Fatalf("raw hits = %d, want 3", doc.RawHits)
	}

	// 严重级别高的排在前面：medium 在 info 之前。
	if doc.Findings[0].Severity != "medium" {
		t.Fatalf("first severity = %q, want medium", doc.Findings[0].Severity)
	}
	// 聚合与首次发现取更早的时间。
	if got := doc.Findings[0].HitCount; got != 2 {
		t.Fatalf("hit count = %d, want 2", got)
	}
	if got := doc.Findings[0].FirstSeen; got != "2026-09-28 14:20:00" {
		t.Fatalf("first seen = %q", got)
	}
	if doc.Findings[0].Solutions != "关闭目录浏览" {
		t.Fatalf("solutions = %q", doc.Findings[0].Solutions)
	}

	if len(doc.Counts) != 2 || doc.Counts[0].Severity != "medium" || doc.Counts[1].Severity != "info" {
		t.Fatalf("counts = %+v", doc.Counts)
	}
}

func TestRenderHTMLEscapesAndMarksPrint(t *testing.T) {
	doc := sampleDoc()
	doc.Findings[0].Target = `<script>alert(1)</script>`

	out, err := RenderHTML(doc, HTMLOptions{AutoPrint: true})
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	html := string(out)

	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatal("target was not escaped")
	}
	if !strings.Contains(html, "window.print()") {
		t.Fatal("autoprint script missing")
	}
	if !strings.Contains(html, "afrog · afrog.zan8in.com") {
		t.Fatal("brand line missing")
	}
	if !strings.Contains(html, "漏洞清单") || !strings.Contains(html, "漏洞明细") {
		t.Fatal("report sections missing")
	}
	if !strings.Contains(html, "@page") {
		t.Fatal("print css missing")
	}
}

func TestRenderHTMLEmptyFindings(t *testing.T) {
	doc := Build(Meta{Title: "扫描报告"}, Brand{}, nil, false)
	out, err := RenderHTML(doc, HTMLOptions{})
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	if !strings.Contains(string(out), "没有符合条件的命中记录") {
		t.Fatal("empty state missing")
	}
}

func TestRenderXLSXProducesReadableWorkbook(t *testing.T) {
	out, err := RenderXLSX(sampleDoc())
	if err != nil {
		t.Fatalf("RenderXLSX: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatalf("xlsx is not a zip: %v", err)
	}

	names := make(map[string]bool, len(zr.File))
	for _, f := range zr.File {
		names[f.Name] = true
	}
	for _, want := range []string{"[Content_Types].xml", "xl/workbook.xml", "xl/sharedStrings.xml"} {
		if !names[want] {
			t.Fatalf("xlsx missing %s (have %d entries)", want, len(zr.File))
		}
	}

	// 用 excelize 回读，确认三张工作表都在且内容可读。
	book, err := excelize.OpenReader(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("reopen xlsx: %v", err)
	}
	defer book.Close()

	for _, want := range []string{sheetSummary, sheetFindings, sheetEvidence} {
		if idx, err := book.GetSheetIndex(want); err != nil || idx < 0 {
			t.Fatalf("sheet %q missing (err=%v)", want, err)
		}
	}

	// 默认工作表是摘要页，且不应残留 excelize 自带的空 Sheet1。
	if got := book.GetSheetName(book.GetActiveSheetIndex()); got != sheetSummary {
		t.Fatalf("active sheet = %q, want %q", got, sheetSummary)
	}
	if idx, _ := book.GetSheetIndex("Sheet1"); idx >= 0 {
		t.Fatal("stray default sheet Sheet1 was not removed")
	}

	vulID, err := book.GetCellValue(sheetFindings, "C2")
	if err != nil {
		t.Fatalf("read findings cell: %v", err)
	}
	if vulID != "directory-listing" {
		t.Fatalf("first finding row PoC = %q, want directory-listing", vulID)
	}
}

func TestRenderMarkdownListsFindings(t *testing.T) {
	out := string(RenderMarkdown(sampleDoc()))

	if !strings.Contains(out, "# 扫描报告 · Nmap 复测") {
		t.Fatal("title missing")
	}
	if !strings.Contains(out, "| critical |") && !strings.Contains(out, "| medium | 1 |") {
		t.Fatal("severity table missing")
	}
	if !strings.Contains(out, "目录浏览") {
		t.Fatal("finding missing")
	}
	if !strings.Contains(out, "```http") {
		t.Fatal("evidence code block missing")
	}
}

func TestFileNameSanitizesSubject(t *testing.T) {
	meta := Meta{Subject: "Nmap 复测/生产", Title: "扫描报告", GeneratedAt: time.Date(2026, 9, 28, 15, 4, 5, 0, time.UTC)}
	got := FileName(meta, "xlsx")
	if strings.ContainsAny(got, `/\`) {
		t.Fatalf("file name contains separator: %q", got)
	}
	if !strings.HasSuffix(got, ".xlsx") {
		t.Fatalf("file name ext = %q", got)
	}
	if !strings.Contains(got, "Nmap") {
		t.Fatalf("file name lost subject: %q", got)
	}
}

// 远程派发回填的命中要带出来源节点：同一条命中重复命中同一节点时节点去重，
// 本机命中（未回填）不带节点。
func TestBuildCollectsSourceNodes(t *testing.T) {
	rows := sampleRows()
	// 同一条聚合命中（directory-listing）的两行都来自同一节点：应只列一次。
	rows[1].Node = "阿里云"
	rows[2].Node = "阿里云"
	rows = append(rows, db.ResultData{
		ID: 4, TaskID: "20260928-00002-ab12cd", VulID: "nacos-detect", VulName: "nacos",
		Target: "http://a.example", FullTarget: "http://a.example/", Severity: "HIGH",
		Created: "2026-09-28 14:00:00", Node: "节点2",
	})

	doc := Build(Meta{Title: "扫描报告"}, Brand{}, rows, false)
	if !doc.HasNodes() {
		t.Fatal("含远程命中的报告应判定为 HasNodes")
	}

	byVulID := make(map[string]Finding, len(doc.Findings))
	for _, f := range doc.Findings {
		byVulID[f.VulID] = f
	}
	if got := byVulID["directory-listing"].NodeLabel(); got != "阿里云" {
		t.Fatalf("directory-listing 的来源节点 = %q, want 阿里云", got)
	}
	if got := byVulID["nacos-detect"].NodeLabel(); got != "节点2" {
		t.Fatalf("nacos-detect 的来源节点 = %q, want 节点2", got)
	}
	if got := byVulID["webprobe"].NodeLabel(); got != "" {
		t.Fatalf("本机命中不该有来源节点，实际 %q", got)
	}
}

// 纯本机扫描的报告不该多出「来源节点」这一列。
func TestRenderersSkipNodeColumnWhenAllLocal(t *testing.T) {
	doc := Build(Meta{Title: "扫描报告"}, Brand{}, sampleRows(), false)
	if doc.HasNodes() {
		t.Fatal("纯本机报告不该判定为 HasNodes")
	}
	if md := string(RenderMarkdown(doc)); strings.Contains(md, "来源节点") {
		t.Fatal("纯本机报告的 Markdown 不该出现来源节点")
	}
	out, err := RenderHTML(doc, HTMLOptions{})
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	if strings.Contains(string(out), "来源节点") {
		t.Fatal("纯本机报告的 HTML 不该出现来源节点")
	}
}

// 含远程命中的报告：Markdown / HTML / XLSX 三种产物都要标出来源节点。
func TestRenderersIncludeSourceNode(t *testing.T) {
	rows := sampleRows()
	rows[0].Node = "阿里云" // webprobe 那条

	doc := Build(Meta{Title: "扫描报告"}, Brand{}, rows, false)

	md := string(RenderMarkdown(doc))
	if !strings.Contains(md, "来源节点") || !strings.Contains(md, "来源节点：阿里云") {
		t.Fatalf("Markdown 缺少来源节点：\n%s", md)
	}

	out, err := RenderHTML(doc, HTMLOptions{})
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	if !strings.Contains(string(out), "来源节点：阿里云") {
		t.Fatal("HTML 缺少来源节点")
	}

	xls, err := RenderXLSX(doc)
	if err != nil {
		t.Fatalf("RenderXLSX: %v", err)
	}
	book, err := excelize.OpenReader(bytes.NewReader(xls))
	if err != nil {
		t.Fatalf("reopen xlsx: %v", err)
	}
	defer book.Close()

	// 插在「完整目标」之后：F=完整目标，G=来源节点，H=命中次数，I=首次发现。
	if got, _ := book.GetCellValue(sheetFindings, "G1"); got != "来源节点" {
		t.Fatalf("G1 = %q, want 来源节点", got)
	}
	if got, _ := book.GetCellValue(sheetFindings, "H1"); got != "命中次数" {
		t.Fatalf("H1 = %q, want 命中次数", got)
	}
	if got, _ := book.GetCellValue(sheetFindings, "I1"); got != "首次发现" {
		t.Fatalf("I1 = %q, want 首次发现", got)
	}
}
