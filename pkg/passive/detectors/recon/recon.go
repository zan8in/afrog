// Package recon 实现被动「信息收集」提取（等价于浏览器插件 FindSomething 的高精度子集）。
//
// 与敏感信息提取（extract）同源：都是零流量本地计算、都走 rulekit 引擎、产物都进
// 提取面板。区别只在规则表的取向——extract 关心「凭据泄露」，recon 关心「资产线索」：
// 云存储桶、邮箱、绝对 URL、接口路径。这些是渗透工程师做信息收集时最想要的横向入口。
//
// 准确率优先在这里尤其关键：FindSomething 类功能天生噪声大（一个 JS 能吐出几十条
// URL/域名），若不加约束会立刻把面板淹没。因此本包只做**高精度子集**：
//   - 每条规则都带字面锚点（cloud storage 域名、@、http(s)://、/api）做廉价秒筛；
//   - URL 规则带校验器，剔除 XML 命名空间/静态资源等「到处都是」的噪声；
//   - 接口路径规则要求关键字后是路径边界，避免把 /apiaries 当成 /api。
//
// 本提取器默认关闭：它产出的是「线索」而非「结论」，是否值得开由使用者按场景决定。
package recon

import (
	"github.com/zan8in/afrog/v3/pkg/passive"
	"github.com/zan8in/afrog/v3/pkg/passive/detectors/rulekit"
)

// DetectorName 是提取器标识。
const DetectorName = "recon"

// Options 是提取器限额，直接复用 rulekit 的额度模型。
type Options = rulekit.Options

// DefaultOptions 返回默认限额。
func DefaultOptions() Options { return rulekit.DefaultOptions() }

// Extractor 是信息收集提取器。
type Extractor struct{ *rulekit.Engine }

// New 使用内置规则表创建提取器。
func New(opts Options) *Extractor {
	return &Extractor{rulekit.New(DetectorName, opts, defaultRules)}
}

// 编译期断言：本提取器必须满足 passive.Extractor 契约。
var _ passive.Extractor = (*Extractor)(nil)
