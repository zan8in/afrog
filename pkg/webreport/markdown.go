package webreport

import (
	"fmt"
	"strings"
)

// RenderMarkdown 生成 Markdown 报告（免费用户可导出）。
func RenderMarkdown(doc Document) []byte {
	var b strings.Builder

	title := doc.Meta.Title
	if doc.Meta.Subject != "" {
		title += " · " + doc.Meta.Subject
	}
	b.WriteString("# " + title + "\n\n")

	if len(doc.Meta.TaskIDs) == 1 {
		fmt.Fprintf(&b, "- 任务：`%s`\n", doc.Meta.TaskIDs[0])
	} else if len(doc.Meta.TaskIDs) > 1 {
		fmt.Fprintf(&b, "- 任务数：%d\n", len(doc.Meta.TaskIDs))
	}
	if doc.Meta.ProjectName != "" {
		fmt.Fprintf(&b, "- 项目：%s\n", doc.Meta.ProjectName)
	}
	if len(doc.Meta.Targets) > 0 {
		fmt.Fprintf(&b, "- 目标数：%d\n", len(doc.Meta.Targets))
	}
	fmt.Fprintf(&b, "- 生成时间：%s\n", doc.Meta.GeneratedAt.Format("2006-01-02 15:04:05"))
	if line := filterLine(doc.Meta); line != "" {
		fmt.Fprintf(&b, "- %s\n", line)
	}
	fmt.Fprintf(&b, "- 漏洞条目：%d（原始命中 %d）\n", doc.Total(), doc.RawHits)
	if doc.Truncated {
		b.WriteString("\n> 结果集较大，本报告仅收录部分命中，请缩小筛选范围后重新导出。\n")
	}

	b.WriteString("\n## 严重级别分布\n\n")
	if len(doc.Counts) == 0 {
		b.WriteString("无\n")
	} else {
		b.WriteString("| 严重级别 | 数量 |\n| --- | ---: |\n")
		for _, c := range doc.Counts {
			fmt.Fprintf(&b, "| %s | %d |\n", c.Severity, c.Count)
		}
	}

	b.WriteString("\n## 漏洞清单\n\n")
	if len(doc.Findings) == 0 {
		b.WriteString("没有符合条件的命中记录。\n")
		return []byte(b.String())
	}

	b.WriteString("| # | 严重级别 | PoC ID | PoC 名称 | 目标 | 命中次数 | 首次发现 |\n")
	b.WriteString("| ---: | --- | --- | --- | --- | ---: | --- |\n")
	for i, fd := range doc.Findings {
		target := fd.FullTarget
		if strings.TrimSpace(target) == "" {
			target = fd.Target
		}
		fmt.Fprintf(&b, "| %d | %s | `%s` | %s | %s | %d | %s |\n",
			i+1, fd.Severity, fd.VulID, escapeMD(fd.VulName), escapeMD(target), fd.HitCount, fd.FirstSeen)
	}

	b.WriteString("\n## 漏洞明细\n")
	for i, fd := range doc.Findings {
		name := fd.VulName
		if name == "" {
			name = fd.VulID
		}
		fmt.Fprintf(&b, "\n### %d. [%s] %s\n\n", i+1, strings.ToUpper(fd.Severity), name)
		fmt.Fprintf(&b, "- PoC：`%s`\n", fd.VulID)
		target := fd.FullTarget
		if strings.TrimSpace(target) == "" {
			target = fd.Target
		}
		fmt.Fprintf(&b, "- 目标：%s\n", target)
		fmt.Fprintf(&b, "- 命中次数：%d\n", fd.HitCount)
		if fd.FirstSeen != "" {
			fmt.Fprintf(&b, "- 首次发现：%s\n", fd.FirstSeen)
		}

		writeMDSection(&b, "漏洞描述", fd.Description)
		writeMDSection(&b, "影响版本", fd.Affected)
		writeMDSection(&b, "解决方案", fd.Solutions)

		if len(fd.References) > 0 {
			b.WriteString("\n**参考资料**\n\n")
			for _, ref := range fd.References {
				fmt.Fprintf(&b, "- %s\n", ref)
			}
		}

		if hasEvidence(fd) {
			b.WriteString("\n**请求响应证据**\n")
			for j, ev := range fd.Evidences {
				if ev.Request == "" && ev.Response == "" {
					continue
				}
				fmt.Fprintf(&b, "\n证据 %d", j+1)
				if ev.FullTarget != "" {
					fmt.Fprintf(&b, "（%s）", ev.FullTarget)
				}
				if ev.Latency > 0 {
					fmt.Fprintf(&b, " · %d ms", ev.Latency)
				}
				b.WriteString("\n\n")
				if ev.Request != "" {
					b.WriteString("请求：\n\n```http\n" + trimForMD(ev.Request) + "\n```\n\n")
				}
				if ev.Response != "" {
					b.WriteString("响应：\n\n```http\n" + trimForMD(ev.Response) + "\n```\n\n")
				}
			}
		}
	}

	b.WriteString("\n---\n\n")
	fmt.Fprintf(&b, "由 %s 生成\n", brandLine(doc.Brand))
	return []byte(b.String())
}

func writeMDSection(b *strings.Builder, title, content string) {
	if strings.TrimSpace(content) == "" {
		return
	}
	fmt.Fprintf(b, "\n**%s**\n\n%s\n", title, strings.TrimSpace(content))
}

func hasEvidence(fd Finding) bool {
	for _, ev := range fd.Evidences {
		if ev.Request != "" || ev.Response != "" {
			return true
		}
	}
	return false
}

// escapeMD 转义表格单元格里会破坏 Markdown 结构的字符。
func escapeMD(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

// trimForMD 限制代码块体积，避免 Markdown 文件过大。
func trimForMD(s string) string {
	const limit = 8000
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return string(r[:limit]) + "\n…（内容过长已截断）"
}
