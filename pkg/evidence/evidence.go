// Package evidence 定义 afrog 的「证据」对象：一次漏洞判定凭什么成立。
//
// 设计取向：证据由检测引擎原生产出，不由 UI 事后拼装。模型可以据此判断「下一步
// 试什么」，人也可以据此一键复核；两者看到的是同一份数据。
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/ref"
)

// Confidence 是一条证据的可信度，与主动 PoC 的确定性判定对齐。
type Confidence string

const (
	Certain  Confidence = "certain"
	Probable Confidence = "probable"
)

// Role 是一步证据在判定过程中的作用。
type Role string

const (
	RoleBaseline     Role = "baseline"
	RoleProbe        Role = "probe"
	RoleConfirm      Role = "confirm"
	RoleDiff         Role = "diff"
	RoleTimeBaseline Role = "time_baseline"
	RoleTimeConfirm  Role = "time_confirm"
)

// Request 是证据里的请求快照。只保留复核所需的最小字段。
type Request struct {
	Method  string `json:"method,omitempty"`
	URL     string `json:"url,omitempty"`
	Headers string `json:"headers,omitempty"`
	Body    string `json:"body,omitempty"`
}

// Response 是证据里的响应快照。
//
// LatencyMs 不参与摘要计算：同一条证据重放两次的耗时必然不同，若计入会让
// 幂等键失效。
type Response struct {
	Status    int    `json:"status,omitempty"`
	Headers   string `json:"headers,omitempty"`
	Body      string `json:"body,omitempty"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
}

// Diff 是差分判定的一步对照关系。
type Diff struct {
	// Against 是被对照步骤在 Steps 里的下标。
	Against    int     `json:"against"`
	Similarity float64 `json:"similarity,omitempty"`
}

// Step 是一步证据。
type Step struct {
	Role      Role              `json:"role"`
	Request   Request           `json:"request,omitempty"`
	Response  Response          `json:"response,omitempty"`
	Matched   bool              `json:"matched"`
	Extracted map[string]string `json:"extracted,omitempty"`
	Diff      *Diff             `json:"diff,omitempty"`
}

// Judgement 记录检测器采用的是哪种构造方式。SQLi 等需要区分技术路线的检测器，
// 证据里必须留下这些字段，否则复核者无法判断证明力。
type Judgement struct {
	Technique string `json:"technique,omitempty"`
	Dialect   string `json:"dialect,omitempty"`
	Evasion   string `json:"evasion,omitempty"`
	Construct string `json:"construct,omitempty"`
}

// Replay 描述如何重新得到这份证据。
type Replay struct {
	Command       string `json:"command,omitempty"`
	Deterministic bool   `json:"deterministic"`
}

// Evidence 是一次漏洞判定的完整证据链。
type Evidence struct {
	ID         string     `json:"id"`
	Finding    string     `json:"finding,omitempty"`
	PocID      string     `json:"poc_id,omitempty"`
	Target     string     `json:"target,omitempty"`
	Steps      []Step     `json:"steps"`
	Judgement  *Judgement `json:"judgement,omitempty"`
	Replay     Replay     `json:"replay"`
	Confidence string     `json:"confidence,omitempty"`
	Digest     string     `json:"digest"`
	Created    string     `json:"created,omitempty"`
}

// Builder 逐步收集证据并生成带摘要与 ID 的 Evidence。
type Builder struct {
	pocID      string
	target     string
	findingID  string
	confidence Confidence
	judgement  *Judgement
	steps      []Step
	now        func() time.Time
}

// NewBuilder 创建一个证据构建器。
//
// target 应是「种子目标」——扫描/verify 传入的那个 base（不含规则 path），因为
// replay.command 与 verify.replay 都要拿它当 base 重跑同一个 PoC。具体命中的完整
// URL 由每一步的 Request.URL 记录。
func NewBuilder(pocID, target string) *Builder {
	return &Builder{
		pocID:      strings.TrimSpace(pocID),
		target:     strings.TrimSpace(target),
		confidence: Certain,
		now:        time.Now,
	}
}

func (b *Builder) WithFinding(id string) *Builder {
	if b != nil {
		b.findingID = strings.TrimSpace(id)
	}
	return b
}

func (b *Builder) WithConfidence(c Confidence) *Builder {
	if b != nil && c != "" {
		b.confidence = c
	}
	return b
}

func (b *Builder) WithJudgement(j Judgement) *Builder {
	if b != nil {
		jj := j
		b.judgement = &jj
	}
	return b
}

// AddStep 追加一步证据。值为空、没有请求也没有响应的步骤会被丢弃，
// 避免在证据链里留下无法复核的空壳。
func (b *Builder) AddStep(s Step) *Builder {
	if b == nil {
		return b
	}
	if s.Request == (Request{}) && s.Response == (Response{}) {
		return b
	}
	b.steps = append(b.steps, s)
	return b
}

// Build 生成证据对象。没有任何有效步骤时返回 nil——空证据没有复核价值。
func (b *Builder) Build() *Evidence {
	if b == nil || len(b.steps) == 0 {
		return nil
	}
	ev := &Evidence{
		Finding:    b.findingID,
		PocID:      b.pocID,
		Target:     b.target,
		Steps:      append([]Step(nil), b.steps...),
		Confidence: string(b.confidence),
		Replay: Replay{
			Command:       replayCommand(b.pocID, b.target),
			Deterministic: replayable(b.steps),
		},
	}
	if b.judgement != nil {
		j := *b.judgement
		ev.Judgement = &j
	}
	if b.now != nil {
		ev.Created = b.now().UTC().Format(time.RFC3339)
	}
	ev.Digest = digestOf(ev)
	ev.ID = ref.Make(ref.KindEvidence, ev.Digest)
	return ev
}

// Clone 返回深拷贝，供快照边界使用。
func (e *Evidence) Clone() *Evidence {
	if e == nil {
		return nil
	}
	out := *e
	if len(e.Steps) > 0 {
		out.Steps = make([]Step, len(e.Steps))
		for i, s := range e.Steps {
			out.Steps[i] = s.Clone()
		}
	}
	if e.Judgement != nil {
		j := *e.Judgement
		out.Judgement = &j
	}
	return &out
}

// Clone 返回一步证据的深拷贝。
func (s Step) Clone() Step {
	out := s
	if s.Extracted != nil {
		out.Extracted = make(map[string]string, len(s.Extracted))
		for k, v := range s.Extracted {
			out.Extracted[k] = v
		}
	}
	if s.Diff != nil {
		d := *s.Diff
		out.Diff = &d
	}
	return out
}

// digestStep 是摘要计算用的步骤视图：刻意不包含响应耗时与响应正文。
//
// 响应正文里常有时间戳、随机 token 等每次都会变的内容；耗时则必然变化。
// 把它们计入摘要会让同一条证据每次重放都得到新 ID，幂等性随之失效。
type digestStep struct {
	Role      Role              `json:"role"`
	Matched   bool              `json:"matched"`
	Method    string            `json:"method,omitempty"`
	URL       string            `json:"url,omitempty"`
	Status    int               `json:"status,omitempty"`
	Extracted map[string]string `json:"extracted,omitempty"`
}

type digestView struct {
	PocID      string       `json:"poc_id"`
	Target     string       `json:"target"`
	Confidence string       `json:"confidence"`
	Judgement  *Judgement   `json:"judgement,omitempty"`
	Steps      []digestStep `json:"steps"`
}

func digestOf(e *Evidence) string {
	view := digestView{
		PocID:      e.PocID,
		Target:     e.Target,
		Confidence: e.Confidence,
		Judgement:  e.Judgement,
	}
	for _, s := range e.Steps {
		view.Steps = append(view.Steps, digestStep{
			Role:      s.Role,
			Matched:   s.Matched,
			Method:    s.Request.Method,
			URL:       s.Request.URL,
			Status:    s.Response.Status,
			Extracted: s.Extracted,
		})
	}
	b, err := json.Marshal(view)
	if err != nil {
		// digestView 只含可序列化字段，走到这里说明代码有 bug；用字符串兜底，
		// 保证 ID 仍然确定，不 panic 整个扫描。
		b = []byte(fmt.Sprintf("%s|%s", e.PocID, e.Target))
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// behaviorStep 是「行为指纹」用的步骤视图：与 digestStep 的唯一差别是 Extracted
// 只保留键、丢弃取值。
type behaviorStep struct {
	Role          Role     `json:"role"`
	Matched       bool     `json:"matched"`
	Method        string   `json:"method,omitempty"`
	URL           string   `json:"url,omitempty"`
	Status        int      `json:"status,omitempty"`
	ExtractedKeys []string `json:"extracted_keys,omitempty"`
}

type behaviorView struct {
	PocID      string         `json:"poc_id"`
	Target     string         `json:"target"`
	Confidence string         `json:"confidence"`
	Judgement  *Judgement     `json:"judgement,omitempty"`
	Steps      []behaviorStep `json:"steps"`
}

// BehaviorDigest 返回证据的「行为指纹」：与 Digest 同源，但丢弃抽取到的具体取值，
// 只保留「抽到了哪些键」。
//
// 抽取到的会话号、CSRF token、时间戳这类值每次请求都会变，把它们计入摘要会让同一次
// 判定在重放时得到不同指纹；但键集合（抽到了哪些字段）本身是稳定的行为特征。
// verify.replay 据此把重放结论分成两档：digest 不等而行为指纹相等，说明这次重放观察到
// 的是同一行为、只是响应里的易变值不同；两档都不等才是目标或 PoC 真的变了。
func BehaviorDigest(e *Evidence) string {
	if e == nil {
		return ""
	}
	view := behaviorView{
		PocID:      e.PocID,
		Target:     e.Target,
		Confidence: e.Confidence,
		Judgement:  e.Judgement,
	}
	for _, s := range e.Steps {
		keys := make([]string, 0, len(s.Extracted))
		for k := range s.Extracted {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		view.Steps = append(view.Steps, behaviorStep{
			Role:          s.Role,
			Matched:       s.Matched,
			Method:        s.Request.Method,
			URL:           s.Request.URL,
			Status:        s.Response.Status,
			ExtractedKeys: keys,
		})
	}
	b, err := json.Marshal(view)
	if err != nil {
		b = []byte(fmt.Sprintf("%s|%s", e.PocID, e.Target))
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func replayable(steps []Step) bool {
	for _, s := range steps {
		if strings.TrimSpace(s.Request.URL) == "" && strings.TrimSpace(s.Request.Method) == "" {
			return false
		}
	}
	return len(steps) > 0
}

func replayCommand(pocID, target string) string {
	pocID = strings.TrimSpace(pocID)
	target = strings.TrimSpace(target)
	if pocID == "" || target == "" {
		return ""
	}
	return fmt.Sprintf("afrog verify --poc %s --target %s", pocID, target)
}
