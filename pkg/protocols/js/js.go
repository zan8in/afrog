package js

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/gologger"
)

// execState 保存一次脚本执行的运行时状态。
type execState struct {
	vm       *goja.Runtime
	ctx      context.Context
	vars     map[string]any
	exported bytes.Buffer

	// allowModule 是模块准入策略；为 nil 表示不限制（仅测试与内部调用会出现）。
	allowModule ModulePolicy

	mu   sync.Mutex
	open map[any]func()
}

// track 登记一个需要在脚本结束后兜底释放的资源（如未显式关闭的连接）。
func (s *execState) track(key any, closeFn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open == nil {
		s.open = map[any]func(){}
	}
	s.open[key] = closeFn
}

// untrack 移除已由脚本显式释放的资源。
func (s *execState) untrack(key any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.open, key)
}

// closeAll 兜底释放脚本未关闭的资源，避免连接泄漏。
func (s *execState) closeAll() {
	s.mu.Lock()
	fns := make([]func(), 0, len(s.open))
	for k, fn := range s.open {
		fns = append(fns, fn)
		delete(s.open, k)
	}
	s.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

// programCache 按脚本源码缓存编译结果。PoC 的 code 是静态的，
// 不同脚本数量受 PoC 数量约束，因此无需担心缓存膨胀。
var programCache sync.Map // map[string]*goja.Program

func compileProgram(src string) (*goja.Program, error) {
	if v, ok := programCache.Load(src); ok {
		if p, ok2 := v.(*goja.Program); ok2 {
			return p, nil
		}
	}
	prog, err := goja.Compile("", src, false)
	if err != nil {
		return nil, err
	}
	programCache.Store(src, prog)
	return prog, nil
}

// watchContext 在 ctx 取消/超时或达到 maxTimeout 时中断脚本执行，返回停止函数。
// maxTimeout<=0 时只跟随 ctx，由调用方决定是否设置脚本级上限。
func watchContext(ctx context.Context, vm *goja.Runtime, maxTimeout time.Duration) func() {
	done := make(chan struct{})
	go func() {
		var timeoutC <-chan time.Time
		if maxTimeout > 0 {
			timer := time.NewTimer(maxTimeout)
			defer timer.Stop()
			timeoutC = timer.C
		}
		select {
		case <-ctx.Done():
			vm.Interrupt(ctx.Err())
		case <-timeoutC:
			vm.Interrupt("javascript execution timeout")
		case <-done:
		}
	}()
	return func() { close(done) }
}

// Execute 执行一段 afrog 风格的 javascript PoC 代码。
//
// ctx:    扫描任务上下文，取消或超时会立即中断脚本
// target: 当前扫描目标
// code:   request.code 中的 JS 脚本
// preCondition: request.pre-condition 中的前置表达式（可空），求值为假时跳过 code
// args:   request.args 渲染后的脚本入参，将作为同名全局变量注入
// vars:   与 checker 共享的变量表，脚本结果通过 response / response_text 回写
// maxTimeout: 脚本整体执行上限，<=0 时只跟随 ctx
// allowModule: 可选模块准入策略；不传表示不限制。它决定 require 能否取得
// 某个模块，是能力策略（如将来的 exec）的运行期拦截点。
func Execute(ctx context.Context, target, code, preCondition string, args map[string]any, vars map[string]any, maxTimeout time.Duration, allowModule ...ModulePolicy) error {
	if strings.TrimSpace(code) == "" {
		return fmt.Errorf("javascript: empty code")
	}
	if vars == nil {
		vars = map[string]any{}
	}
	if ctx == nil {
		ctx = context.Background()
	}

	codeProg, err := compileProgram(code)
	if err != nil {
		setResponse(vars, "")
		return fmt.Errorf("javascript: compile error: %w", err)
	}
	var preProg *goja.Program
	if s := strings.TrimSpace(preCondition); s != "" {
		preProg, err = compileProgram(s)
		if err != nil {
			setResponse(vars, "")
			return fmt.Errorf("javascript: pre-condition compile error: %w", err)
		}
	}

	vm := goja.New()
	stop := watchContext(ctx, vm, maxTimeout)
	defer stop()

	state := &execState{vm: vm, ctx: ctx, vars: vars}
	if len(allowModule) > 0 {
		state.allowModule = allowModule[0]
	}
	// 脚本结束（含出错/中断）时兜底释放未关闭的连接
	defer state.closeAll()
	if err := registerBuiltins(state); err != nil {
		return err
	}
	if err := registerRequire(state); err != nil {
		return err
	}

	for k, v := range args {
		if err := vm.Set(k, v); err != nil {
			return fmt.Errorf("javascript: set arg %q failed: %w", k, err)
		}
	}
	if _, ok := args["target"]; !ok {
		_ = vm.Set("target", target)
	}

	if preProg != nil {
		val, err := runProgram(vm, preProg)
		if err != nil {
			setResponse(vars, "")
			return fmt.Errorf("javascript: pre-condition error: %w", err)
		}
		if val == nil || !val.ToBoolean() {
			setResponse(vars, "")
			return nil
		}
	}

	val, err := runProgram(vm, codeProg)
	if err != nil {
		setResponse(vars, "")
		return fmt.Errorf("javascript: %w", err)
	}

	out := state.exported.String()
	if out == "" {
		out = stringify(vm, val)
	}
	setResponse(vars, out)
	return nil
}

func registerBuiltins(state *execState) error {
	vm := state.vm

	// Export(value): 将值转成字符串并追加到脚本输出，作为 response 内容
	if err := vm.Set("Export", func(call goja.FunctionCall) goja.Value {
		for _, arg := range call.Arguments {
			if out := stringify(vm, arg); out != "" {
				state.exported.WriteString(out)
			}
		}
		return goja.Null()
	}); err != nil {
		return err
	}

	// ExportAs(key, value): 将值写入同名变量，供规则 expression(CEL) 与
	// extractors 直接引用。key 必须是合法标识符。
	if err := vm.Set("ExportAs", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) != 2 {
			panic(vm.ToValue("ExportAs expects 2 arguments: ExportAs(key, value)"))
		}
		key := strings.TrimSpace(call.Argument(0).String())
		if !isIdent(key) {
			panic(vm.ToValue(fmt.Sprintf("ExportAs: invalid key %q, expected identifier", key)))
		}
		state.vars[key] = call.Argument(1).Export()
		return goja.Null()
	}); err != nil {
		return err
	}

	// log(msg): 调试输出
	if err := vm.Set("log", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return goja.Null()
		}
		gologger.Debug().Msgf("[JS] %v", stringify(vm, call.Argument(0)))
		return goja.Null()
	}); err != nil {
		return err
	}

	// to_json(value): 将对象序列化为 JSON 字符串
	if err := vm.Set("to_json", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return goja.Null()
		}
		b, err := json.Marshal(call.Argument(0).Export())
		if err != nil {
			return goja.Null()
		}
		return vm.ToValue(string(b))
	}); err != nil {
		return err
	}

	// ToString(value): 转为字符串
	if err := vm.Set("ToString", func(call goja.FunctionCall) goja.Value {
		var buff bytes.Buffer
		for _, arg := range call.Arguments {
			if v := arg.Export(); v != nil {
				buff.WriteString(fmt.Sprintf("%v", v))
			}
		}
		return vm.ToValue(buff.String())
	}); err != nil {
		return err
	}

	// isPortOpen(host, port, [timeoutSec]): 判断 TCP 端口是否开放
	if err := vm.Set("isPortOpen", func(call goja.FunctionCall) goja.Value {
		host := strings.TrimSpace(call.Argument(0).String())
		port := strings.TrimSpace(call.Argument(1).String())
		if host == "" || port == "" {
			return vm.ToValue(false)
		}
		timeout := 5 * time.Second
		if len(call.Arguments) >= 3 {
			if sec, ok := toInt(call.Argument(2).Export()); ok && sec > 0 {
				timeout = time.Duration(sec) * time.Second
			}
		}
		conn, err := (&net.Dialer{Timeout: timeout}).DialContext(state.ctx, "tcp", net.JoinHostPort(host, port))
		if err != nil {
			return vm.ToValue(false)
		}
		_ = conn.Close()
		return vm.ToValue(true)
	}); err != nil {
		return err
	}

	return nil
}

func registerRequire(state *execState) error {
	vm := state.vm
	return vm.Set("require", func(call goja.FunctionCall) goja.Value {
		name := strings.TrimSpace(call.Argument(0).String())
		def, ok := lookupModule(name)
		if !ok {
			panic(vm.ToValue(fmt.Sprintf("require: module %q not found", name)))
		}
		if state.allowModule != nil && !state.allowModule(name, def.level) {
			panic(vm.ToValue(fmt.Sprintf("require: module %q is not allowed (capability %q)", name, def.level)))
		}
		val, err := def.build(state)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return val
	})
}

func runProgram(vm *goja.Runtime, prog *goja.Program) (val goja.Value, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	val, err = vm.RunProgram(prog)
	if err != nil {
		if _, ok := err.(*goja.InterruptedError); ok {
			return val, fmt.Errorf("interrupted: %w", err)
		}
		if ex, ok := err.(*goja.Exception); ok {
			err = fmt.Errorf("%s", ex.Value().String())
		}
	}
	return val, err
}

func setResponse(vars map[string]any, body string) {
	b := []byte(body)
	vars["response"] = &proto.Response{Raw: b, Body: b}
	vars["response_text"] = body
}

// stringify 将 goja 值转为字符串；结构体/映射会被序列化为 JSON。
func stringify(vm *goja.Runtime, val goja.Value) string {
	if val == nil {
		return ""
	}
	value := val.Export()
	if value == nil {
		return ""
	}
	t := reflect.TypeOf(value)
	if t.Kind() == reflect.Struct || (t.Kind() == reflect.Pointer && t.Elem().Kind() == reflect.Struct) {
		if b, err := json.Marshal(value); err == nil {
			return string(b)
		}
	}
	return fmt.Sprintf("%v", value)
}

// isIdent 判断字符串是否为合法标识符（字母/下划线开头，后接字母、数字或下划线）。
func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '_' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'):
		case i > 0 && ch >= '0' && ch <= '9':
		default:
			return false
		}
	}
	return true
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case string:
		var out int
		if _, err := fmt.Sscanf(strings.TrimSpace(n), "%d", &out); err == nil {
			return out, true
		}
	}
	return 0, false
}
