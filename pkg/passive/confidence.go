package passive

import "github.com/zan8in/afrog/v3/pkg/portscan"

// Confidence 复用端口指纹与 Web 指纹的可信度标尺，使「主动」与「被动」两条链路的
// 结果语义完全一致：unknown < port < probable < certain。
//
// 被动检测的硬性约束是：只有 ConfidenceCertain 的 Finding 才允许进入台账。
// 这条约束写在调度层（engine）里，任何检测器都无法绕过，从机制上保证零误报。
type Confidence = portscan.Confidence

const (
	// ConfidenceUnknown 没有任何证据。
	ConfidenceUnknown = portscan.ConfidenceUnknown
	// ConfidencePortOnly 仅凭位置/惯例推测，被动链路不应产出该级别。
	ConfidencePortOnly = portscan.ConfidencePortOnly
	// ConfidenceProbable 弱证据命中，只用于展示，不入台账。
	ConfidenceProbable = portscan.ConfidenceProbable
	// ConfidenceCertain 确定性证据命中，允许进入台账。
	ConfidenceCertain = portscan.ConfidenceCertain
)
