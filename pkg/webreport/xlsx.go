package webreport

import (
	"fmt"
	"strings"

	"github.com/xuri/excelize/v2"
)

// xlsx 单元格文本上限：Excel 单元格最多 32767 字符，
// 这里再收一档，避免请求/响应原文把文件撑得无法打开。
const maxXLSXCellRunes = 8000

const (
	sheetSummary  = "扫描摘要"
	sheetFindings = "漏洞清单"
	sheetEvidence = "证据明细"
)

// xlsxStyles 汇总一次导出用到的全部单元格样式。
type xlsxStyles struct {
	title    int
	label    int
	value    int
	header   int
	cell     int
	cellNum  int
	cellWrap int
	mono     int
	severity map[string]int
}

// RenderXLSX 生成 Excel 报告：摘要 / 漏洞清单 / 证据明细 三张工作表。
func RenderXLSX(doc Document) ([]byte, error) {
	f := excelize.NewFile()
	defer f.Close()

	styles, err := buildXLSXStyles(f)
	if err != nil {
		return nil, err
	}

	if err := writeSummarySheet(f, doc, styles); err != nil {
		return nil, err
	}
	if err := writeFindingsSheet(f, doc, styles); err != nil {
		return nil, err
	}
	if err := writeEvidenceSheet(f, doc, styles); err != nil {
		return nil, err
	}

	// 删除 excelize 默认创建的空工作表，避免导出的文件里多出一个空标签页。
	if idx, err := f.GetSheetIndex("Sheet1"); err == nil && idx >= 0 {
		if err := f.DeleteSheet("Sheet1"); err != nil {
			return nil, err
		}
	}
	if idx, err := f.GetSheetIndex(sheetSummary); err == nil && idx >= 0 {
		f.SetActiveSheet(idx)
	}

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, fmt.Errorf("write xlsx: %w", err)
	}
	return buf.Bytes(), nil
}

func buildXLSXStyles(f *excelize.File) (xlsxStyles, error) {
	var s xlsxStyles
	var err error

	border := []excelize.Border{
		{Type: "left", Color: "D9DCE1", Style: 1},
		{Type: "right", Color: "D9DCE1", Style: 1},
		{Type: "top", Color: "D9DCE1", Style: 1},
		{Type: "bottom", Color: "D9DCE1", Style: 1},
	}

	if s.title, err = f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 15},
	}); err != nil {
		return s, err
	}
	if s.label, err = f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "5C6370"},
	}); err != nil {
		return s, err
	}
	if s.value, err = f.NewStyle(&excelize.Style{}); err != nil {
		return s, err
	}
	if s.header, err = f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"F2F4F7"}},
		Alignment: &excelize.Alignment{Vertical: "center", WrapText: true},
		Border:    border,
	}); err != nil {
		return s, err
	}
	if s.cell, err = f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{Vertical: "top", WrapText: true},
		Border:    border,
	}); err != nil {
		return s, err
	}
	if s.cellNum, err = f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{Vertical: "top", Horizontal: "right"},
		Border:    border,
	}); err != nil {
		return s, err
	}
	if s.cellWrap, err = f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{Vertical: "top", WrapText: true},
		Border:    border,
	}); err != nil {
		return s, err
	}
	if s.mono, err = f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Family: "Consolas"},
		Alignment: &excelize.Alignment{Vertical: "top", WrapText: true},
		Border:    border,
	}); err != nil {
		return s, err
	}

	s.severity = make(map[string]int, len(severityOrder)+1)
	colors := map[string]string{
		"critical": "B91C1C",
		"high":     "EA580C",
		"medium":   "D97706",
		"low":      "0284C7",
		"info":     "64748B",
		"unknown":  "64748B",
	}
	for name, color := range colors {
		id, err := f.NewStyle(&excelize.Style{
			Font:      &excelize.Font{Bold: true, Color: color},
			Alignment: &excelize.Alignment{Vertical: "top", Horizontal: "center"},
			Border:    border,
		})
		if err != nil {
			return s, err
		}
		s.severity[name] = id
	}

	return s, nil
}

func writeSummarySheet(f *excelize.File, doc Document, st xlsxStyles) error {
	const sheet = sheetSummary
	if _, err := f.NewSheet(sheet); err != nil {
		return err
	}

	if err := f.SetCellValue(sheet, "A1", doc.Meta.Title); err != nil {
		return err
	}
	if err := f.SetCellStyle(sheet, "A1", "B1", st.title); err != nil {
		return err
	}
	if err := f.MergeCell(sheet, "A1", "B1"); err != nil {
		return err
	}

	rows := [][2]string{
		{"品牌", brandLine(doc.Brand)},
		{"生成时间", doc.Meta.GeneratedAt.Format("2006-01-02 15:04:05")},
	}
	if doc.Meta.ProjectName != "" {
		rows = append(rows, [2]string{"项目", doc.Meta.ProjectName})
	}
	if doc.Meta.Subject != "" {
		rows = append(rows, [2]string{"对象", doc.Meta.Subject})
	}
	if len(doc.Meta.TaskIDs) == 1 {
		rows = append(rows, [2]string{"任务", doc.Meta.TaskIDs[0]})
	} else if len(doc.Meta.TaskIDs) > 1 {
		rows = append(rows, [2]string{"任务数", fmt.Sprintf("%d", len(doc.Meta.TaskIDs))})
	}
	if len(doc.Meta.Targets) > 0 {
		rows = append(rows, [2]string{"目标数", fmt.Sprintf("%d", len(doc.Meta.Targets))})
	}
	if line := filterLine(doc.Meta); line != "" {
		rows = append(rows, [2]string{"筛选", strings.TrimPrefix(line, "筛选条件：")})
	}
	rows = append(rows,
		[2]string{"漏洞条目", fmt.Sprintf("%d", doc.Total())},
		[2]string{"原始命中", fmt.Sprintf("%d", doc.RawHits)},
	)
	for _, c := range doc.Counts {
		rows = append(rows, [2]string{"  " + c.Severity, fmt.Sprintf("%d", c.Count)})
	}
	if doc.Truncated {
		rows = append(rows, [2]string{"注意", "结果集较大，仅收录部分命中，请缩小范围后重新导出"})
	}

	for i, kv := range rows {
		row := i + 3
		if err := f.SetCellValue(sheet, cellAt(1, row), kv[0]); err != nil {
			return err
		}
		if err := f.SetCellStyle(sheet, cellAt(1, row), cellAt(1, row), st.label); err != nil {
			return err
		}
		if err := f.SetCellValue(sheet, cellAt(2, row), kv[1]); err != nil {
			return err
		}
		if err := f.SetCellStyle(sheet, cellAt(2, row), cellAt(2, row), st.value); err != nil {
			return err
		}
	}

	if err := f.SetColWidth(sheet, "A", "A", 14); err != nil {
		return err
	}
	if err := f.SetColWidth(sheet, "B", "B", 70); err != nil {
		return err
	}
	return setHeaderFooter(f, sheet, doc)
}

func writeFindingsSheet(f *excelize.File, doc Document, st xlsxStyles) error {
	const sheet = sheetFindings
	if _, err := f.NewSheet(sheet); err != nil {
		return err
	}

	// 「来源节点」只在这份报告确实含远程命中时出现：纯本机扫描多一列空白没有意义。
	withNodes := doc.HasNodes()
	headers := []string{"#", "严重级别", "PoC ID", "PoC 名称", "目标", "完整目标"}
	if withNodes {
		headers = append(headers, "来源节点")
	}
	headers = append(headers, "命中次数", "首次发现")
	if err := setHeaderRow(f, sheet, headers, st.header); err != nil {
		return err
	}

	for i, fd := range doc.Findings {
		row := i + 2
		values := []any{
			i + 1,
			fd.Severity,
			fd.VulID,
			fd.VulName,
			fd.Target,
			fd.FullTarget,
		}
		if withNodes {
			values = append(values, fd.NodeLabel())
		}
		values = append(values, fd.HitCount, fd.FirstSeen)
		if err := setRowValues(f, sheet, row, values, st.cell, st.cellNum); err != nil {
			return err
		}
		sevStyle, ok := st.severity[fd.Severity]
		if !ok {
			sevStyle = st.severity["unknown"]
		}
		if err := f.SetCellStyle(sheet, cellAt(2, row), cellAt(2, row), sevStyle); err != nil {
			return err
		}
	}

	widths := map[string]float64{"A": 5, "B": 10, "C": 30, "D": 26, "E": 34, "F": 40}
	if withNodes {
		widths["G"] = 14
		widths["H"] = 10
		widths["I"] = 19
	} else {
		widths["G"] = 10
		widths["H"] = 19
	}
	if err := applyWidths(f, sheet, widths); err != nil {
		return err
	}
	if err := freezeHeader(f, sheet); err != nil {
		return err
	}
	return setHeaderFooter(f, sheet, doc)
}

func writeEvidenceSheet(f *excelize.File, doc Document, st xlsxStyles) error {
	const sheet = sheetEvidence
	if _, err := f.NewSheet(sheet); err != nil {
		return err
	}

	headers := []string{"PoC ID", "严重级别", "目标", "证据序号", "耗时(ms)", "请求原文", "响应原文"}
	if err := setHeaderRow(f, sheet, headers, st.header); err != nil {
		return err
	}

	row := 2
	for _, fd := range doc.Findings {
		for j, ev := range fd.Evidences {
			if ev.Request == "" && ev.Response == "" {
				continue
			}
			values := []any{
				fd.VulID,
				fd.Severity,
				ev.FullTarget,
				j + 1,
				ev.Latency,
				truncateRunes(ev.Request, maxXLSXCellRunes),
				truncateRunes(ev.Response, maxXLSXCellRunes),
			}
			if err := setRowValues(f, sheet, row, values, st.cell, st.cellNum); err != nil {
				return err
			}
			if err := f.SetCellStyle(sheet, cellAt(6, row), cellAt(7, row), st.mono); err != nil {
				return err
			}
			row++
		}
	}

	widths := map[string]float64{"A": 30, "B": 10, "C": 34, "D": 9, "E": 10, "F": 60, "G": 60}
	if err := applyWidths(f, sheet, widths); err != nil {
		return err
	}
	if err := freezeHeader(f, sheet); err != nil {
		return err
	}
	return setHeaderFooter(f, sheet, doc)
}

// setHeaderRow 写入表头并加粗、冻结。
func setHeaderRow(f *excelize.File, sheet string, headers []string, style int) error {
	values := make([]any, len(headers))
	for i, h := range headers {
		values[i] = h
	}
	if err := setRowValues(f, sheet, 1, values, style, style); err != nil {
		return err
	}
	return nil
}

// setRowValues 写一行；数值列使用 numStyle，其余使用 cellStyle。
func setRowValues(f *excelize.File, sheet string, row int, values []any, cellStyle, numStyle int) error {
	for i, v := range values {
		col := i + 1
		cell := cellAt(col, row)
		if err := f.SetCellValue(sheet, cell, v); err != nil {
			return err
		}
		style := cellStyle
		if _, isNum := v.(int); isNum {
			style = numStyle
		}
		if _, isNum := v.(int64); isNum {
			style = numStyle
		}
		if err := f.SetCellStyle(sheet, cell, cell, style); err != nil {
			return err
		}
	}
	return nil
}

func applyWidths(f *excelize.File, sheet string, widths map[string]float64) error {
	for col, w := range widths {
		if err := f.SetColWidth(sheet, col, col, w); err != nil {
			return err
		}
	}
	return nil
}

func freezeHeader(f *excelize.File, sheet string) error {
	return f.SetPanes(sheet, &excelize.Panes{
		Freeze:      true,
		YSplit:      1,
		TopLeftCell: "A2",
		ActivePane:  "bottomLeft",
	})
}

// setHeaderFooter 给每张工作表加上品牌页眉 / 页码页脚，作为会员水印的一部分。
func setHeaderFooter(f *excelize.File, sheet string, doc Document) error {
	header := fmt.Sprintf(`&L&"Arial,Bold"&10%s`, brandLine(doc.Brand))
	footer := `&L&10` + doc.Meta.GeneratedAt.Format("2006-01-02 15:04:05") + `&R&10第 &P / &N 页`
	return f.SetHeaderFooter(sheet, &excelize.HeaderFooterOptions{
		OddHeader:  header,
		OddFooter:  footer,
		EvenHeader: header,
		EvenFooter: footer,
	})
}

func cellAt(col, row int) string {
	name, err := excelize.ColumnNumberToName(col)
	if err != nil {
		return "A1"
	}
	return fmt.Sprintf("%s%d", name, row)
}

func truncateRunes(s string, limit int) string {
	if limit <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return string(r[:limit]) + "\n…（内容过长已截断）"
}
