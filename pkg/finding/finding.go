// Package finding 定义 afrog 的漏洞结论契约（Finding）：Agent 从「一堆命中」里
// 读到的「这个主体上有这一类漏洞」。
//
// 与 result / evidence 的分工：result 回答「发现了什么」，evidence 回答「凭什么
// 成立」，Finding 回答「这个主体上这一类漏洞的当前状态」。
//
// 投影而非双写：Finding 不是新的真源表，它的全部字段都由 result / vuln_ledger /
// task_project / evidence 四张表读时算出，漏洞台账（vuln_ledger）仍是报告真源。
// 这样引擎侧零改动、历史数据无需迁移，Agent 与报告永远看到同一份事实。
//
// 内容寻址：同一个 (project_id, subject, vuln_class) 在任何节点、任何进程、任何
// 任务里都得到同一个 fnd_ id，重复命中只累加 hit_count / last_seen，不新增结论。
// 项目间不做去重（project_id 参与 canonical）。
package finding

import (
	"fmt"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/ref"
)

// State 是 Finding 的生命周期状态（设计稿 §4.5）。
const (
	StateNew        = "new"
	StatePresent    = "present"
	StateFixed      = "fixed"
	StateRegression = "regression"
)

// Source 是 Finding 的产生路径：主动扫描、被动检测、Agent 工具面。
const (
	SourceActive  = "active"
	SourcePassive = "passive"
	SourceAgent   = "agent"
)

// Finding 是某个主体上一类漏洞的聚合结论。
type Finding struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	// Subject 是主体的内容寻址 id（endpoint_ 前缀）：它能被资产图与证据稳定引用，但读不出
	// 「这是哪个目标」。可读的原值见 Target。
	Subject string `json:"subject"`
	// Target 是主体的可读原值（命中所在的完整 URL，退而取种子目标或原始地址），由
	// TargetFor 按与 Subject 相同的优先级选出。只用它做展示与判断，引用一律用 Subject。
	Target    string `json:"target"`
	VulnClass string `json:"vuln_class"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	// PocIDs 是产生本条结论的 PoC id（去重、升序）。类目级聚合会把映射到同一类目的
	// 多个 PoC 合并成一条结论，只给一个 id 会丢信息，因此给出全集，供调用方据此回到
	// poc.search / scan.start 或核对来源。
	PocIDs     []string `json:"poc_ids"`
	Confidence string   `json:"confidence,omitempty"`
	Evidence   []string `json:"evidence"`
	State      string   `json:"state"`
	Source     string   `json:"source"`
	FirstSeen  string   `json:"first_seen"`
	LastSeen   string   `json:"last_seen"`
	HitCount   int64    `json:"hit_count"`
	// Status 保留台账原始状态：state 是 §4.5 的归一化枚举，false_positive 等 §4.5
	// 之外的状态会被折叠成 present，需要区分时读这里的原值。
	Status string `json:"status,omitempty"`
}

// IDFor 返回 (project_id, subject, vuln_class) 对应的内容寻址 id。
//
// 这三个字段就是 Finding 的聚合主键（类目级口径）：同一主体上的同一类漏洞只有
// 一条结论，命中次数的累加发生在 hit_count 上，而不是新增一行。
func IDFor(projectID, subject, vulnClass string) string {
	canonical := strings.Join([]string{projectID, subject, vulnClass}, "|")
	return ref.Make(ref.KindFinding, canonical)
}

// VulnClass 推导一类漏洞的归一化类目：cwe-id → 首个 tag → vulid。
//
// 类目用于把「同一主体上的同一类漏洞」聚合在一起：映射到同一 cwe-id 的不同 PoC
// 会合并成一条 Finding（title / severity 取组内代表值），这是类目级口径的已知取舍。
func VulnClass(cweID, tags, vulID string) string {
	if v := strings.ToLower(strings.TrimSpace(cweID)); v != "" {
		return v
	}
	for _, t := range strings.Split(tags, ",") {
		if v := strings.ToLower(strings.TrimSpace(t)); v != "" {
			return v
		}
	}
	return strings.ToLower(strings.TrimSpace(vulID))
}

// SubjectFor 返回 Finding 主体的内容寻址 id：优先取完整命中的端点，其次回退种子目标，
// 都不是绝对 URL 时退到可读原值。退到原值是为了避免非绝对 URL 的目标（如 host:port）
// 算出空 subject，把不同主体错误塌缩成同一条结论。
func SubjectFor(fullTarget, target string) string {
	raw := TargetFor(fullTarget, target)
	if id := ref.Endpoint(raw); id != "" {
		return id
	}
	return raw
}

// TargetFor 返回 Finding 主体的可读原值：与 SubjectFor 取同一个输入（优先完整的命中
// 端点，其次种子目标，最后原始地址），只是返回地址本身而不是内容寻址 id。
//
// 两者共用同一套优先级：Subject 是它的 id、Target 是它的原值，调用方才能一一对应地
// 「用 Subject 引用、用 Target 展示」。
func TargetFor(fullTarget, target string) string {
	ft := strings.TrimSpace(fullTarget)
	tg := strings.TrimSpace(target)
	switch {
	case ref.Endpoint(ft) != "":
		return ft
	case ref.Endpoint(tg) != "":
		return tg
	case ft != "":
		return ft
	default:
		return tg
	}
}

// StateFromStatus 把台账状态映射成 §4.5 的 state 枚举。
//
// false_positive 在 §4.5 里没有对应取值：命中是事实、结论仍然存在，只是被判为
// 不构成漏洞，因此折叠成 present；要区分时读 Finding.Status 的原始状态。
func StateFromStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "pending":
		return StateNew
	case "fixed":
		return StateFixed
	default:
		// confirmed / false_positive，以及将来新增的状态都折叠成 present。
		return StatePresent
	}
}

// New 归一化并构造一条 Finding，算好内容寻址 id。
//
// 校验失败（subject 或 vuln_class 为空）返回错误：投影宁可少一条，也不要写入无法
// 解释的结论——没有主体或没有类目的「命中」无法参与聚合，也无法被稳定引用。
func New(f Finding) (*Finding, error) {
	f.ProjectID = strings.TrimSpace(f.ProjectID)
	f.Subject = strings.TrimSpace(f.Subject)
	f.VulnClass = strings.TrimSpace(f.VulnClass)
	if f.Subject == "" {
		return nil, fmt.Errorf("finding: subject is required")
	}
	if f.VulnClass == "" {
		return nil, fmt.Errorf("finding: vuln_class is required")
	}
	f.ID = IDFor(f.ProjectID, f.Subject, f.VulnClass)
	if f.Evidence == nil {
		f.Evidence = []string{}
	}
	if f.PocIDs == nil {
		f.PocIDs = []string{}
	}
	return &f, nil
}
