package drafter

import (
	"sort"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
)

// Bucket 是按某个维度（severity / capability）切分后的一组计数。
type Bucket struct {
	Name       string  `json:"name"`
	Total      int     `json:"total"`
	Pending    int     `json:"pending"`
	Approved   int     `json:"approved"`
	Rejected   int     `json:"rejected"`
	IngestRate float64 `json:"ingest_rate"`
}

// Stats 是 Drafter 流水线的量化指标，回答「候选产出后有多少真的入库了」。
//
// 口径刻意显式：
//   - IngestRate = approved / (approved + rejected)，分母不含 pending——
//     pending 是「还没结论」，把它算进分母会把「没人审」误读成「审不过」。
//   - 分子分母都按当前 poc_draft 状态统计（更像「现在库里长什么样」）；
//     Reviews 另计流水条数，反映「历史上被决议过多少次」（草稿迭代会重复计数）。
type Stats struct {
	Total      int     `json:"total"`
	Pending    int     `json:"pending"`
	Approved   int     `json:"approved"`
	Rejected   int     `json:"rejected"`
	Reviewed   int     `json:"reviewed"`
	IngestRate float64 `json:"ingest_rate"`
	// Reviews 是终审决议流水总条数（同一草稿被多次决议会重复计数）。
	Reviews      int      `json:"reviews"`
	BySeverity   []Bucket `json:"by_severity"`
	ByCapability []Bucket `json:"by_capability"`
}

// Stats 聚合候选 PoC 流水线的当前状态与自动入库率。
func GetStats() (*Stats, error) {
	items, err := sqlite.SelectPocDrafts("")
	if err != nil {
		return nil, err
	}

	out := &Stats{Total: len(items)}
	bySeverity := map[string]*Bucket{}
	byCapability := map[string]*Bucket{}

	for _, it := range items {
		sev := strings.ToLower(strings.TrimSpace(it.Severity))
		if sev == "" {
			sev = "unknown"
		}
		cap := strings.ToLower(strings.TrimSpace(it.Capability))
		if cap == "" {
			cap = "unknown"
		}
		bump(out, it.Status)
		bumpBucket(bucketOf(bySeverity, sev), it.Status)
		bumpBucket(bucketOf(byCapability, cap), it.Status)
	}

	out.Reviewed = out.Approved + out.Rejected
	out.IngestRate = rate(out.Approved, out.Rejected)
	out.BySeverity = finalizeBuckets(bySeverity)
	out.ByCapability = finalizeBuckets(byCapability)

	reviews, err := sqlite.CountPocReviews()
	if err != nil {
		return nil, err
	}
	out.Reviews = reviews
	return out, nil
}

func bump(s *Stats, status string) {
	switch status {
	case sqlite.PocDraftApproved:
		s.Approved++
	case sqlite.PocDraftRejected:
		s.Rejected++
	default:
		s.Pending++
	}
}

func bucketOf(m map[string]*Bucket, name string) *Bucket {
	b := m[name]
	if b == nil {
		b = &Bucket{Name: name}
		m[name] = b
	}
	return b
}

func bumpBucket(b *Bucket, status string) {
	b.Total++
	switch status {
	case sqlite.PocDraftApproved:
		b.Approved++
	case sqlite.PocDraftRejected:
		b.Rejected++
	default:
		b.Pending++
	}
}

func rate(approved, rejected int) float64 {
	if approved+rejected == 0 {
		return 0
	}
	return float64(approved) / float64(approved+rejected)
}

// finalizeBuckets 算出每个分桶的入库率并固定排序（名称升序），保证输出不抖动。
func finalizeBuckets(m map[string]*Bucket) []Bucket {
	out := make([]Bucket, 0, len(m))
	for _, b := range m {
		b.IngestRate = rate(b.Approved, b.Rejected)
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
