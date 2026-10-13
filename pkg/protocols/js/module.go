package js

import (
	"github.com/dop251/goja"
	"github.com/zan8in/afrog/v3/pkg/capability"
)

// moduleBuilder 构造一个可供 require() 返回的模块对象。
// state 为本次脚本执行的运行时状态，模块可从中取 ctx、变量表，
// 以及登记需要在脚本结束后兜底释放的资源。
type moduleBuilder func(state *execState) (goja.Value, error)

// moduleDef 描述一个 afrog 原生模块。新增模块只需定义 builder 并调用
// registerModule（见各模块文件的 init），无需改动引擎的模块分发逻辑。
type moduleDef struct {
	name    string           // 对外名称为 afrog/<name>
	summary string           // 一句话说明，用于文档与调试
	level   capability.Level // 模块能力等级；未显式设置时按 network 处理
	build   moduleBuilder
}

// moduleRegistry 保存所有已注册模块，键为完整的 require 名称（afrog/xxx）。
var moduleRegistry = map[string]moduleDef{}

// registerModule 注册一个模块，通常在模块文件的 init() 中调用。
func registerModule(def moduleDef) {
	if def.name == "" || def.build == nil {
		return
	}
	// 模块至少是 network 能力：漏标时不能反而降级成 declarative，
	// 否则将来接入特权模块会有"忘了打标签就没被拦"的风险。
	if def.level < capability.Network {
		def.level = capability.Network
	}
	full := "afrog/" + def.name
	moduleRegistry[full] = def
	capability.RegisterModule(full, def.level)
}

func lookupModule(name string) (moduleDef, bool) {
	def, ok := moduleRegistry[name]
	return def, ok
}

// ModulePolicy 决定某个模块是否允许被 require()。
// name 为完整模块名（如 afrog/exec），level 为其能力等级。
// 返回 false 时 require 会抛出明确错误，脚本无法取得该模块——
// 这是特权能力的运行期拦截点，静态扫描被绕过也拦得住。
type ModulePolicy func(name string, level capability.Level) bool
