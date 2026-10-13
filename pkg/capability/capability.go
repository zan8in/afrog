// Package capability 定义 afrog PoC 的"能力等级"，把「一个 PoC 能做什么」
// 与「是否允许它运行」解耦。
//
// 今天只有两档：声明式（http/tcp/ssl/raw）与 network（javascript 网络模块）。
// 将来新增"命令执行"时，只需在 Level 里补一档，并在加载/require 策略里放行或
// 拒绝该档，无需改动加载器与 JS 运行时。
package capability

// Level 是 PoC 的能力等级，值越大权限越高。
type Level int

const (
	// Declarative 纯声明式规则，不执行 PoC 内的代码。
	Declarative Level = iota
	// Network 执行 PoC 内的脚本，且脚本只能发起网络请求。
	Network
	// Exec 执行 PoC 内的脚本，且脚本可在本机执行命令。
	Exec
)

func (l Level) String() string {
	switch l {
	case Declarative:
		return "declarative"
	case Network:
		return "network"
	case Exec:
		return "exec"
	}
	return "unknown"
}

// Max 返回两个等级中较高的一个。
func Max(a, b Level) Level {
	if a > b {
		return a
	}
	return b
}

// moduleLevels 是模块能力登记表：由 pkg/protocols/js 注册模块时写入，
// 供 pkg/poc 在加载期推算 PoC 的能力等级。
var moduleLevels = map[string]Level{}

// RegisterModule 登记一个模块的能力等级，name 形如 afrog/exec。
func RegisterModule(name string, level Level) {
	if name == "" {
		return
	}
	moduleLevels[name] = level
}

// ModuleLevel 查询模块能力等级。未登记时返回 (Network, false)。
// 未登记按 Network 处理是保守下限——真正的特权拦截发生在 require 时
// （由 js 模块自身的登记信息决定），这里只服务于加载期的标记与提示。
func ModuleLevel(name string) (Level, bool) {
	l, ok := moduleLevels[name]
	if !ok {
		return Network, false
	}
	return l, true
}
