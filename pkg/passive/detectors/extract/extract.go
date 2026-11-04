// Package extract 实现被动「敏感信息提取」（等价于 BurpSuite 的 HAE 插件）。
//
// 它不做任何漏洞判定，也不发出任何请求：只对已经捕获到的事务（响应体、响应头、
// URL）做正则匹配，把命中的敏感字符串原样提取出来，经独立回调送往提取面板。
//
// 与漏洞检测的两条根本差异，决定了它被建模为 Extractor 而不是 Detector：
//   - 零流量：不重放，所以产物不是「某处存在漏洞」，而是「某处存在某个字符串」，
//     没有 Payload / 证据链的概念，落库表、去重口径与前端面板都完全独立；
//   - 不受短路：提取永不该因为「该注入点已有结论」而被跳过——一条 JS 里有没有密钥，
//     与它能不能被注入毫无关系。
//
// 匹配引擎（扫描面拆分、锚点秒筛、校验器与语境闸门、去重、证据截取）已抽到
// rulekit 共享包：本包只负责绑定内置规则表。这样「新增一个提取器 = 写一份规则表」，
// 不必再复制一份匹配循环。
package extract

import (
	"github.com/zan8in/afrog/v3/pkg/passive"
	"github.com/zan8in/afrog/v3/pkg/passive/detectors/rulekit"
)

// DetectorName 是提取器标识。
const DetectorName = "extract"

// Options 是提取器限额，直接复用 rulekit 的额度模型。
type Options = rulekit.Options

// DefaultOptions 返回默认限额。
func DefaultOptions() Options { return rulekit.DefaultOptions() }

// Extractor 是敏感信息提取器。
//
// 行为完全由内嵌的 rulekit.Engine 提供（Name / Interest / Extract），
// 这里只负责把内置规则表绑到引擎上。
type Extractor struct{ *rulekit.Engine }

// New 使用内置规则表创建提取器。
func New(opts Options) *Extractor {
	return &Extractor{rulekit.New(DetectorName, opts, defaultRules)}
}

// 编译期断言：本提取器必须满足 passive.Extractor 契约。
var _ passive.Extractor = (*Extractor)(nil)
