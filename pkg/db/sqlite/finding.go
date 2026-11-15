package sqlite

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	db2 "github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/finding"
)

// findingGroupedSelect 在台账聚合（vulid, target, fulltarget）之上多取 poc 与代表
// result 主键：Finding 的类目与主体由这两者推导，投影在 Go 侧完成（纯函数、可单测）。
//
// 与 ledgerGroupedSelect 的差别有两点：多一列 poc，以及聚合键带上 project_id。
// project_id 参与 canonical，同一漏洞在不同项目下必须是两条独立结论，若沿用台账的
// MAX(project_id) 会把其中一个项目折叠掉、让另一项目看不到这条命中。
var findingGroupedSelect = `SELECT
	r.vulid AS vulid,
	MAX(r.vulname) AS vulname,
	r.target AS target,
	r.fulltarget AS fulltarget,
	MAX(r.severity) AS severity,
	MIN(r.created) AS first_seen,
	MAX(r.created) AS last_seen,
	COUNT(*) AS hit_count,
	COALESCE(l.status, 'pending') AS status,
	COALESCE(tp.project_id, '') AS project_id,
	MAX(r.poc) AS poc,
	MAX(r.id) AS result_id
  FROM ` + db2.TableName + ` r
  LEFT JOIN vuln_ledger l
	ON l.vulid = r.vulid AND l.target = r.target AND l.fulltarget = r.fulltarget
  LEFT JOIN task_project tp ON tp.taskid = r.taskid
  GROUP BY r.vulid, r.target, r.fulltarget, COALESCE(tp.project_id, '')`

// FindingPage 是 Finding 投影的分页结果。
type FindingPage struct {
	Items    []finding.Finding `json:"items"`
	Total    int64             `json:"total"`
	Page     int               `json:"page"`
	PageSize int               `json:"page_size"`
}

// findingRow 是一条台账聚合行，Finding 投影的输入单元。
type findingRow struct {
	VulID      string `db:"vulid"`
	VulName    string `db:"vulname"`
	Target     string `db:"target"`
	FullTarget string `db:"fulltarget"`
	Severity   string `db:"severity"`
	FirstSeen  string `db:"first_seen"`
	LastSeen   string `db:"last_seen"`
	HitCount   int64  `db:"hit_count"`
	Status     string `db:"status"`
	ProjectID  string `db:"project_id"`
	Poc        string `db:"poc"`
	ResultID   int64  `db:"result_id"`
}

// findingGroup 是一条投影出的结论，附带来源 result 主键（供证据回填）。
type findingGroup struct {
	Finding   finding.Finding
	ResultIDs []int64
}

// pocMeta 是 result.poc 里参与 Finding 推导的字段。
type pocMeta struct {
	CweID  string
	Tags   string
	Author string
	PocID  string
}

// findingKey 用同一套 (主体, 类目) 口径算出一条 Finding 的内容寻址 id。
//
// 投影查询与证据落库的写边都走这里，保证「同一个结论」在读取与写入两边得到同一个 id。
func findingKey(projectID, fullTarget, target, cweID, tags, vulID string) (id, subject, class string) {
	subject = finding.SubjectFor(fullTarget, target)
	class = finding.VulnClass(cweID, tags, vulID)
	id = finding.IDFor(projectID, subject, class)
	return id, subject, class
}

// SelectFindings 把 result / vuln_ledger / task_project / evidence 投影成 Finding 分页。
//
// 聚合口径为类目级（project_id + subject + vuln_class）：同一主体上的同一类漏洞只有
// 一条结论，重复命中累加 hit_count 与 last_seen，与设计稿 §4.5 一致。
func SelectFindings(f LedgerFilter) (*FindingPage, error) {
	if dbx == nil {
		return nil, fmt.Errorf("sqlite not initialized")
	}
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 50
	}
	if f.PageSize > 500 {
		f.PageSize = 500
	}

	where, args := ledgerConditions(f, true)
	query := "SELECT * FROM (" + findingGroupedSelect + ") t"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY t.last_seen DESC"

	var rows []findingRow
	if err := dbx.Select(&rows, query, args...); err != nil {
		return nil, err
	}

	groups := groupFindings(rows)
	fillFindingEvidence(groups)
	items := make([]finding.Finding, 0, len(groups))
	for _, g := range groups {
		items = append(items, g.Finding)
	}
	sortFindings(items)

	total := int64(len(items))
	offset := (f.Page - 1) * f.PageSize
	if offset > len(items) {
		offset = len(items)
	}
	end := offset + f.PageSize
	if end > len(items) {
		end = len(items)
	}
	return &FindingPage{
		Items:    items[offset:end],
		Total:    total,
		Page:     f.Page,
		PageSize: f.PageSize,
	}, nil
}

// groupFindings 把台账聚合行归组成 Finding（纯函数，便于单测）。
//
// 按 finding.id 归并：每条结果的 subject / vuln_class 由同一套口径算出，映射到同一
// 类目的不同 vulid 会自然合并。跨条目的代表值都取确定性的极值，归并结果与行顺序无关。
func groupFindings(rows []findingRow) []*findingGroup {
	order := make([]string, 0, len(rows))
	byID := make(map[string]*findingGroup, len(rows))
	cache := make(map[string]pocMeta)

	for _, r := range rows {
		meta, ok := cache[r.VulID]
		if !ok {
			meta = parsePocMeta(r.Poc)
			cache[r.VulID] = meta
		}
		id, subject, class := findingKey(r.ProjectID, r.FullTarget, r.Target, meta.CweID, meta.Tags, r.VulID)

		g, exists := byID[id]
		if !exists {
			nf, err := finding.New(finding.Finding{
				ProjectID: r.ProjectID,
				Subject:   subject,
				VulnClass: class,
				Severity:  strings.ToUpper(strings.TrimSpace(r.Severity)),
				Title:     strings.TrimSpace(r.VulName),
				State:     finding.StateFromStatus(r.Status),
				Status:    strings.ToLower(strings.TrimSpace(r.Status)),
				Source:    sourceForPoc(meta),
				FirstSeen: r.FirstSeen,
				LastSeen:  r.LastSeen,
			})
			if err != nil {
				// 没有主体或类目的退化行无法参与聚合，跳过。
				continue
			}
			g = &findingGroup{Finding: *nf}
			byID[id] = g
			order = append(order, id)
		} else {
			if severityRank(r.Severity) > severityRank(g.Finding.Severity) {
				g.Finding.Severity = strings.ToUpper(strings.TrimSpace(r.Severity))
			}
			if name := strings.TrimSpace(r.VulName); name > g.Finding.Title {
				g.Finding.Title = name
			}
		}

		if r.FirstSeen != "" && (g.Finding.FirstSeen == "" || r.FirstSeen < g.Finding.FirstSeen) {
			g.Finding.FirstSeen = r.FirstSeen
		}
		// 状态取「最近一次活动」的那条：命中可能被人工改过状态，最新的状态更接近事实。
		if r.LastSeen > g.Finding.LastSeen {
			g.Finding.LastSeen = r.LastSeen
			g.Finding.State = finding.StateFromStatus(r.Status)
			g.Finding.Status = strings.ToLower(strings.TrimSpace(r.Status))
		}
		g.Finding.HitCount += r.HitCount
		if r.ResultID > 0 {
			g.ResultIDs = append(g.ResultIDs, r.ResultID)
		}
	}

	out := make([]*findingGroup, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out
}

// fillFindingEvidence 给每条 Finding 回填 evidence[] 与 confidence。
//
// evidence[] 收集该结论下各条台账行的代表证据，一次批量取齐；confidence 取组内最高
// 的证据置信度（certain 优先于 probable），无证据时置空。
func fillFindingEvidence(groups []*findingGroup) {
	all := make([]int64, 0)
	for _, g := range groups {
		all = append(all, g.ResultIDs...)
	}
	refs := map[int64]EvidenceRef{}
	if len(all) > 0 {
		if got, err := SelectEvidenceRefsByResultIDs(all); err == nil {
			refs = got
		}
	}

	for _, g := range groups {
		evidence := make([]string, 0, len(g.ResultIDs))
		seen := make(map[string]struct{}, len(g.ResultIDs))
		confidence := ""
		for _, rid := range g.ResultIDs {
			ref, ok := refs[rid]
			if !ok || ref.ID == "" {
				continue
			}
			if _, dup := seen[ref.ID]; !dup {
				seen[ref.ID] = struct{}{}
				evidence = append(evidence, ref.ID)
			}
			if confidenceRank(ref.Confidence) > confidenceRank(confidence) {
				confidence = ref.Confidence
			}
		}
		g.Finding.Evidence = evidence
		g.Finding.Confidence = confidence
	}
}

// sourceForPoc 依据 PoC 作者与 id 判定产生路径：被动检测复用 result 表，
// 用 author=afrog-passive 与 id 前缀 passive- 区分，其余归为主动扫描。
func sourceForPoc(meta pocMeta) string {
	if strings.EqualFold(strings.TrimSpace(meta.Author), "afrog-passive") ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(meta.PocID)), "passive-") {
		return finding.SourcePassive
	}
	return finding.SourceActive
}

// parsePocMeta 从 result.poc（PocInfo 的 JSON 序列化）里取类目推导所需的字段。
// 解析失败返回零值：宁可退回 vulid 兜底，也不因为一条脏数据阻断整页查询。
func parsePocMeta(pocJSON string) pocMeta {
	pocJSON = strings.TrimSpace(pocJSON)
	if pocJSON == "" {
		return pocMeta{}
	}
	var raw struct {
		ID   string `json:"Id"`
		Info struct {
			Author         string `json:"Author"`
			Tags           string `json:"Tags"`
			Classification struct {
				CweID string `json:"CweId"`
			} `json:"Classification"`
		} `json:"Info"`
	}
	if err := json.Unmarshal([]byte(pocJSON), &raw); err != nil {
		return pocMeta{}
	}
	return pocMeta{
		CweID:  raw.Info.Classification.CweID,
		Tags:   raw.Info.Tags,
		Author: raw.Info.Author,
		PocID:  raw.ID,
	}
}

// severityRank 给严重度排序，用于跨条目取代表值；未知等级按最低处理。
func severityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// confidenceRank 给证据置信度排序，用于跨条目取代表值。
func confidenceRank(c string) int {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "certain":
		return 2
	case "probable":
		return 1
	default:
		return 0
	}
}

// sortFindings 按 last_seen 倒序排列；时间相同时按 id 升序，保证分页稳定。
func sortFindings(items []finding.Finding) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastSeen != items[j].LastSeen {
			return items[i].LastSeen > items[j].LastSeen
		}
		return items[i].ID < items[j].ID
	})
}
