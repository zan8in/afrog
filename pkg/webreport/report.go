// Package webreport 把扫描结果渲染成可交付的报告（HTML / XLSX / Markdown）。
//
// 设计约定：
//   - 报告是「给人看的」，因此命中按 PoC + 目标 + 完整目标聚合，附命中次数，
//     而不是把 result 表的每一行原样铺开。
//   - 渲染层不碰数据库，只接收已聚合好的 Document，便于单测与复用。
package webreport

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/db"
)

// severityOrder 是严重级别的展示顺序（高 → 低）；unknown 兜底放最后。
var severityOrder = []string{"critical", "high", "medium", "low", "info", "unknown"}

var severityRank = func() map[string]int {
	m := make(map[string]int, len(severityOrder))
	for i, s := range severityOrder {
		m[s] = len(severityOrder) - i
	}
	return m
}()

// maxEvidencesPerFinding 限制单条命中保留的请求/响应证据条数。
// 同一 PoC 打同一目标可能命中多次，报告里不需要全部铺开。
const maxEvidencesPerFinding = 10

// Brand 是报告的品牌与水印信息。
type Brand struct {
	// Product 是产品名，出现在页眉页脚与 XLSX 页眉中。
	Product string
	// Version 是产品版本号，可选。
	Version string
	// Site 是站点域名，作为水印的一部分。
	Site string
	// Watermark 由调用方按会员身份决定：免费版 Markdown 不带水印。
	Watermark bool
}

// Meta 是报告头部的元信息。
type Meta struct {
	// Title 是报告主标题，如「扫描报告」。
	Title string
	// Subject 是副标题，如任务名或项目名。
	Subject string
	// ProjectName 仅在项目报告中出现。
	ProjectName string
	// TaskIDs 是报告覆盖的任务；项目报告可能包含多个。
	TaskIDs []string
	// Targets 是扫描目标（任务报告来自任务快照）。
	Targets []string
	// Severities / Keyword 记录本次导出实际生效的筛选条件。
	Severities  []string
	Keyword     string
	GeneratedAt time.Time
	// ScopeNote 用于说明范围（如「仅导出当前筛选结果」）。
	ScopeNote string
}

// SeverityCount 是单个严重级别的条目数。
type SeverityCount struct {
	Severity string
	Count    int
}

// Evidence 是一条命中的请求/响应证据。
type Evidence struct {
	FullTarget string
	Request    string
	Response   string
	Latency    int64
}

// Finding 是报告中的一条命中（按 PoC + 目标 + 完整目标聚合）。
type Finding struct {
	VulID       string
	VulName     string
	Severity    string
	Target      string
	FullTarget  string
	FirstSeen   string
	Description string
	Affected    string
	Solutions   string
	References  []string
	// HitCount 是该聚合单元在 result 表里的原始命中行数。
	HitCount int
	// Nodes 是这条命中的来源执行节点（去重，按出现顺序）。
	// 纯本机扫描为空；同一命中在多台节点上都出现时会有多个。
	Nodes     []string
	Evidences []Evidence
}

// NodeLabel 把来源节点拼成展示串；本机命中为空串。
func (f Finding) NodeLabel() string { return strings.Join(f.Nodes, "、") }

// Document 是待渲染的完整报告。
type Document struct {
	Meta  Meta
	Brand Brand
	// Findings 是聚合后的条目数。
	Findings []Finding
	// RawHits 是聚合前的原始命中行数。
	RawHits int
	Counts  []SeverityCount
	// Truncated 表示结果集触达了导出行数上限，报告并不完整。
	Truncated bool
}

// Counts 求和，便于模板里直接展示总数。
func (d Document) Total() int { return len(d.Findings) }

// HasNodes 表示报告里至少有一条命中来自远程执行节点。
// 渲染层用它决定要不要输出「来源节点」这一列：纯本机扫描的报告不该多一列空白。
func (d Document) HasNodes() bool {
	for _, f := range d.Findings {
		if len(f.Nodes) > 0 {
			return true
		}
	}
	return false
}

// Build 把数据库行聚合为报告文档。
func Build(meta Meta, brand Brand, rows []db.ResultData, truncated bool) Document {
	if strings.TrimSpace(brand.Product) == "" {
		brand.Product = "afrog"
	}
	if meta.GeneratedAt.IsZero() {
		meta.GeneratedAt = time.Now()
	}
	if strings.TrimSpace(meta.Title) == "" {
		meta.Title = "扫描报告"
	}

	doc := Document{
		Meta:      meta,
		Brand:     brand,
		RawHits:   len(rows),
		Findings:  make([]Finding, 0, len(rows)),
		Truncated: truncated,
	}

	index := make(map[string]int, len(rows))
	for _, row := range rows {
		severity := strings.ToLower(strings.TrimSpace(row.Severity))
		if severity == "" {
			severity = "unknown"
		}
		key := strings.Join([]string{row.VulID, row.Target, row.FullTarget}, "\x00")

		pos, ok := index[key]
		if !ok {
			pos = len(doc.Findings)
			index[key] = pos
			doc.Findings = append(doc.Findings, Finding{
				VulID:      row.VulID,
				VulName:    row.VulName,
				Severity:   severity,
				Target:     row.Target,
				FullTarget: row.FullTarget,
				FirstSeen:  row.Created,
			})
		}

		f := &doc.Findings[pos]
		f.HitCount++
		// result 按 id DESC 返回，逐行取更早的时间即为「首次发现」。
		if row.Created != "" && (f.FirstSeen == "" || row.Created < f.FirstSeen) {
			f.FirstSeen = row.Created
		}
		if node := strings.TrimSpace(row.Node); node != "" && !slices.Contains(f.Nodes, node) {
			f.Nodes = append(f.Nodes, node)
		}
		applyPocInfo(f, row)
		if len(f.Evidences) < maxEvidencesPerFinding {
			appendEvidences(f, row)
		}
	}

	sortFindings(doc.Findings)
	doc.Counts = countSeverities(doc.Findings)
	return doc
}

// applyPocInfo 用首个带 PocInfo 的行补齐漏洞描述类字段。
func applyPocInfo(f *Finding, row db.ResultData) {
	if f.Description != "" || row.PocInfo.Info.Name == "" {
		return
	}
	info := row.PocInfo.Info
	if name := strings.TrimSpace(f.VulName); name == "" {
		f.VulName = info.Name
	}
	f.Description = strings.TrimSpace(info.Description)
	f.Affected = strings.TrimSpace(info.Affected)
	f.Solutions = strings.TrimSpace(info.Solutions)
	if len(info.Reference) > 0 {
		f.References = append(f.References, info.Reference...)
	}
}

// appendEvidences 把一行的请求/响应展开为证据条目。
func appendEvidences(f *Finding, row db.ResultData) {
	if len(row.ResultList) == 0 {
		// 没有展开请求响应时至少记录命中目标本身，保证明细不为空。
		if strings.TrimSpace(row.FullTarget) != "" {
			f.Evidences = append(f.Evidences, Evidence{FullTarget: row.FullTarget})
		}
		return
	}
	for _, pr := range row.ResultList {
		if len(f.Evidences) >= maxEvidencesPerFinding {
			return
		}
		target := pr.FullTarget
		if strings.TrimSpace(target) == "" {
			target = row.FullTarget
		}
		f.Evidences = append(f.Evidences, Evidence{
			FullTarget: target,
			Request:    pr.Request,
			Response:   pr.Response,
			Latency:    pr.Other.Latency,
		})
	}
}

func sortFindings(items []Finding) {
	sort.SliceStable(items, func(i, j int) bool {
		wi, wj := severityRank[items[i].Severity], severityRank[items[j].Severity]
		if wi != wj {
			return wi > wj
		}
		if items[i].VulID != items[j].VulID {
			return items[i].VulID < items[j].VulID
		}
		if items[i].Target != items[j].Target {
			return items[i].Target < items[j].Target
		}
		return items[i].FullTarget < items[j].FullTarget
	})
}

// countSeverities 按固定顺序输出各级别数量，只保留有命中的级别。
func countSeverities(items []Finding) []SeverityCount {
	bucket := make(map[string]int, len(severityOrder))
	for _, it := range items {
		bucket[it.Severity]++
	}
	out := make([]SeverityCount, 0, len(bucket))
	for _, s := range severityOrder {
		if n := bucket[s]; n > 0 {
			out = append(out, SeverityCount{Severity: s, Count: n})
		}
	}
	return out
}

// SeverityLabel 返回适合展示的级别名称。
func SeverityLabel(severity string) string {
	s := strings.ToLower(strings.TrimSpace(severity))
	if s == "" {
		return "unknown"
	}
	return s
}

// SafeFileBase 把任意标题清洗为可用作文件名的片段。
func SafeFileBase(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "report"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		case r > 127:
			// 保留中文等多字节字符，文件名可读性更好
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "report"
	}
	if len(out) > 80 {
		out = out[:80]
	}
	return out
}

// FileName 生成导出文件名（不含路径）。
func FileName(meta Meta, ext string) string {
	base := SafeFileBase(meta.Subject)
	if base == "report" {
		base = SafeFileBase(meta.Title)
	}
	stamp := meta.GeneratedAt
	if stamp.IsZero() {
		stamp = time.Now()
	}
	return fmt.Sprintf("afrog-%s-%s.%s", base, stamp.Format("20060102-150405"), ext)
}
