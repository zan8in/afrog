// Package mcp 把 afrog 的观测、探测与验证能力暴露成 MCP 工具。
//
// 边界：本包只做协议翻译与策略门控，不实现任何检测逻辑。真正发包、判定、
// 出证据的仍然是 pkg/sdk、pkg/runner 与 pkg/db/sqlite。
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/zan8in/afrog/v3/pkg/capability"
	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/policy"
	"github.com/zan8in/afrog/v3/pkg/scantask"
	"github.com/zan8in/afrog/v3/pkg/webscan"
	"github.com/zan8in/gologger"
)

// ProtocolVersion 是默认协商的 MCP 协议版本。
const ProtocolVersion = "2025-06-18"

// Instructions 是 initialize 返回给客户端的用法说明。MCP 客户端（Claude、Cursor、
// Cline 等）会把它并入模型上下文；有了它，模型才知道 afrog 该怎么用——否则常见的
// 两种误用是：把一批候选拆成逐个串行验证，以及在指纹命中后不知道该去 poc.search
// 预检、再用 scan.start 一次跑完。
//
// 它只描述用法，不改变任何门控：是否放行仍由策略与预算决定。
const Instructions = `afrog 把本机的扫描结论、攻击面与 PoC 能力暴露成一组工具。按下面的规则组织任务。

默认循环：server.status（看档位与剩余额度）→ observe.findings（已扫出的结论）/ plan.next（服务端给出的确定性下一步）→ 需要发包时 probe.fingerprint → poc.search → scan.start。

主路径：先用 probe.fingerprint 拿技术栈，它返回的 suggested_search 可直接透传给 poc.search 预检「本机有没有该技术栈的 PoC」；非空就用同一串 scan.start 一次并发跑完。不要自己把 technologies 映射成关键词——曾出现识别出 jQuery、却去搜 wordpress,nginx 之类根本没识别到的产品。带关键词时，匹配关键词的指纹 PoC 不受 severity 限制也会保留（但关键词是硬前提，不命中的指纹 PoC 照样被滤掉），因而指纹阶段照常运行、requires 按真实指纹放行，既避免「单跑一个漏洞 PoC 被指纹门控跳过」的假阴性，也把 N 次串行验证压成一次并发扫描。

长任务：scan.start / act.brute 是长任务——它们在「短等窗口」（默认 30 秒）内跑完就返回完整结果，没跑完则返回一个 task_id 句柄（返回体的 conclusion 为 pending）。拿到 task_id 后不要当成失败：用 task.status 查状态与汇总、task.events 按 last_seq 增量拉事件（拉取式，任何传输都可用，因此不依赖服务端推送）、task.control 取消/暂停/恢复。verify.replay / poc.submit 是单 PoC 短任务，会一直等到跑完（它们的后处理——digest 比对、入待审队列——依赖跑完的结果，不能拆开）。

硬规则：
- 没有任何指纹线索时（technologies 为空、plan.next 也给不出关键词）：不要凭空编关键词；先问用户是否要用 afrog 扫描全部漏洞，得到同意后再用空 search 调 scan.start（空关键词 = 不加过滤、跑全库所有 PoC，请求量与耗时都大得多）。
- poc_id 只能来自 poc.search 的真实返回或 plan.next 的提议，禁止凭空编造；自己写的 PoC 先用 poc.draft（save=true）落盘，再把返回的 poc_path 交给 poc.submit 实跑取证据。
- 只读工具（observe.* / plan.* / judge.* / learn.* / server.* / task.list / task.status / task.events / poc.search / poc.draft）不发包也不消耗会话额度；probe.* / scan.* / verify.* / act.* 会发包并按请求数扣额度。拿不准当前档位、还剩多少额度，先看 server.status。
- 默认策略只读：probe.* / scan.* / verify.* 需要 safe 或 full 档位，act.brute / poc.submit 等破坏性动作还需要 destructive=true。被拒绝（403）是策略挡的，不是工具故障。

反模式（不要做）：
- 把一批候选拆成逐个串行的单 PoC 验证——用关键词让 scan.start 一次并发跑完。
- 用户没指定等级就无理由默认塞 severity=["high","critical"] 挨个扫——那是既白扣额度、又得不出可信「无漏洞」结论的遍历；留空即扫描所有等级。
- 把 observe.* / plan.next 返回为空当成「目标没有漏洞」或「无事可做」——前者只表示本地还没有这类数据，后者应改用 probe.* 补观测或直接 poc.search。
- 把 scan.start / act.brute 返回的 task_id 句柄当成「扫描失败」或「没有命中」——那只是还没在短等窗口内跑完，去 task.status / task.events 继续跟踪结果。

本工具面只做「按需、可解释、可重放的动作」；「整目标、全量库」的大范围扫描由用户在他自己的 afrog 入口（CLI / Web 控制台）完成，再用 observe.* 回读结论——除非用户明确同意在 scan.start 里用空 search 跑全库。`

// supportedProtocolVersions 是本服务能真正对话的 MCP 协议版本集合。
//
// initialize 的版本协商按规范来：客户端报的版本在集合内就沿用它的，否则回我们
// 支持的最新版，而不是把客户端说的数字原样复述——那等于宣称自己能说一种并不会说的协议。
var supportedProtocolVersions = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
	"2025-06-18": true,
}

// negotiateProtocolVersion 返回本次会话实际使用的协议版本。
func negotiateProtocolVersion(requested string) string {
	v := strings.TrimSpace(requested)
	if supportedProtocolVersions[v] {
		return v
	}
	return ProtocolVersion
}

// ServerInfo 是 tools/list 与 initialize 里回显的服务信息。
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ToolAnnotations 是 MCP 的工具注解提示（hints）：客户端据此决定「哪些只读工具可以
// 自动放行、哪些动作要先警告使用者」。它只是提示，不参与任何门控——放行与否仍然
// 由策略与预算决定（见 annotationsFor）。
type ToolAnnotations struct {
	ReadOnlyHint    bool `json:"readOnlyHint"`
	DestructiveHint bool `json:"destructiveHint"`
	IdempotentHint  bool `json:"idempotentHint"`
	OpenWorldHint   bool `json:"openWorldHint"`
}

// annotationsFor 按工具名推导注解提示。
//
// 判据与 pkg/policy 的 isReadOnly / 各工具的门控声明保持同一口径：
//   - readOnlyHint 与策略的「只读档」完全一致（observe.* / plan.* / judge.* /
//     learn.* / server.* / task.list / task.status / task.events / poc.search /
//     poc.draft），这样客户端对它们的自动放行与 afrog 自己的只读判定不会互相矛盾；
//   - openWorldHint 表示「会向外部目标发包」：probe.* / verify.* / act.* /
//     scan.* / poc.submit。act.oob_wait 只是等回连、task.* 只是读任务状态，
//     都不算对外发包；
//   - destructiveHint 只给真正可能改变目标状态的动作（act.brute、poc.submit）；
//   - idempotentHint 表示重放同一调用不会产生新的副作用：只读工具以及
//     probe.* / verify.* / scan.* 都满足（重扫得到的是同一批事实）。
func annotationsFor(name string) ToolAnnotations {
	readOnly := strings.HasPrefix(name, "observe.") || strings.HasPrefix(name, "plan.") ||
		strings.HasPrefix(name, "judge.") || strings.HasPrefix(name, "learn.") ||
		strings.HasPrefix(name, "server.") ||
		name == "task.list" || name == "task.status" || name == "task.events" ||
		name == "poc.search" || name == "poc.draft"

	openWorld := strings.HasPrefix(name, "probe.") || strings.HasPrefix(name, "verify.") ||
		strings.HasPrefix(name, "act.") || strings.HasPrefix(name, "scan.") || name == "poc.submit"
	if name == "act.oob_wait" {
		openWorld = false
	}

	return ToolAnnotations{
		ReadOnlyHint:    readOnly,
		DestructiveHint: name == "act.brute" || name == "poc.submit",
		IdempotentHint:  readOnly || strings.HasPrefix(name, "probe.") || strings.HasPrefix(name, "verify.") || strings.HasPrefix(name, "scan."),
		OpenWorldHint:   openWorld,
	}
}

// ProgressFunc 向客户端报告一次进度（对应 MCP 的 notifications/progress）。
type ProgressFunc func(progress, total float64, message string)

// notifyFunc 把一条服务端通知发给客户端。nil 表示该传输没有可推送的通道：
// Streamable HTTP 的一次 POST 是「一问一答」，中途没有地方塞通知。
type notifyFunc func(method string, params any)

type progressKey struct{}

func withProgress(ctx context.Context, fn ProgressFunc) context.Context {
	return context.WithValue(ctx, progressKey{}, fn)
}

// progressFrom 取当前调用的进度上报函数；客户端没带 progressToken 时返回 nil。
func progressFrom(ctx context.Context) ProgressFunc {
	fn, _ := ctx.Value(progressKey{}).(ProgressFunc)
	return fn
}

// logFunc 向客户端报告一条日志（对应 MCP 的 notifications/message）。
type logFunc func(level, message string)

type loggerKey struct{}

func withLogger(ctx context.Context, fn logFunc) context.Context {
	return context.WithValue(ctx, loggerKey{}, fn)
}

// loggerFrom 取当前调用的日志上报函数；当前传输没有推送通道时返回 nil。
func loggerFrom(ctx context.Context) logFunc {
	fn, _ := ctx.Value(loggerKey{}).(logFunc)
	return fn
}

// mcpLogLevels 是 MCP logging 规范的级别序（取自 RFC 5424），数值越大越严重。
// 服务端只推严重度不低于 setLevel 所设级别的消息，默认 info。
var mcpLogLevels = map[string]int{
	"debug": 0, "info": 1, "notice": 2, "warning": 3, "error": 4,
	"critical": 5, "alert": 6, "emergency": 7,
}

// logLevelRank 把级别名规范成序值；未知级别按 info 处理，免得一个拼错的级别名
// 把该发的消息整条吞掉。
func logLevelRank(level string) int {
	if n, ok := mcpLogLevels[strings.ToLower(strings.TrimSpace(level))]; ok {
		return n
	}
	return mcpLogLevels["info"]
}

// Options 配置 MCP 服务。
type Options struct {
	Policy  *policy.Policy
	Budget  *policy.Budget
	Auditor *policy.Auditor
	Info    ServerInfo

	// OOB 是工具面的带外（反连）后端，供 act.oob_payload / act.oob_wait 使用。
	// 为 nil 表示未配置：这两个工具仍然注册，但会明确报「未配置 OOB」。
	OOB OOBSource

	// Executor 是真正发包的执行器，供 scan.start / verify.replay / poc.submit /
	// act.brute 拉起独立子进程执行。为 nil 时懒加载本地子进程执行器
	// （executor.NewLocalProcess）；测试可注入假执行器，无需真实拉起进程。
	Executor executor.Executor
}

// Tool 是一个可调用的 MCP 工具。
type Tool struct {
	Name string
	// Title 是给人看的短标签（如「检索 PoC」），出现在客户端的工具选择界面里；
	// Description 才是给模型看的长说明。两者分工不同，不要互相复制。
	Title       string
	Description string
	InputSchema any
	// OutputSchema 可选。声明它就表示「本工具的返回结构是稳定契约」，客户端可以据此
	// 校验、并按 MCP 规范在结果里拿到 structuredContent（见 toolContent）。
	// 只给返回结构确实稳定的工具声明；返回大对象的工具留空，避免把同一份 payload
	// 在 content 与 structuredContent 里各塞一遍、凭空翻倍响应体。
	OutputSchema any
	// Handler 返回可 JSON 序列化的结果；错误会以工具错误（isError）回给调用方。
	Handler func(ctx context.Context, args json.RawMessage) (any, error)

	// Capability / Destructive 是该工具在门控里声明的静态能力等级与破坏性标记。
	// 它只用于「工具目录」这类只读展示：让使用者一眼看出哪些工具需要更高档位
	// （例如 act.brute 需要 full + destructive）。真正的门控发生在 Handler 内部，
	// 那里可以按入参动态提高（如 poc.submit 按草稿的 Capability）。
	Capability  capability.Level
	Destructive bool
}

// ToolSpec 是工具的对外描述，供 tools/list 与其它传输（gRPC AgentService/ListTools）复用，
// 保证「工具清单」只有一份来源。
type ToolSpec struct {
	Name         string
	Title        string
	Description  string
	InputSchema  any
	OutputSchema any
	// Capability / Destructive 见 Tool 的同名说明。
	Capability  capability.Level
	Destructive bool
}

// Server 是工具面的核心：持有工具注册表与策略门控，本身与传输无关。
//
// MCP（stdio / SSE / streamable）只是它的一种适配器；REST 等其它传输通过
// Call 复用同一份工具与门控，避免每接一种传输就把策略、预算、审计重写一遍。
type Server struct {
	gate  *policy.Gate
	info  ServerInfo
	oob   OOBSource
	tools map[string]*Tool

	// exec 是发包执行器：所有真正扫描都交给独立子进程（见 scanExecutor）。
	// SDK 的 HTTP 客户端、限速器、协议探测缓存都是进程级全局状态，同进程内并发
	// scanner 会互相覆盖参数，进程隔离是唯一干净的做法。
	exec     executor.Executor
	execOnce sync.Once
	execErr  error

	// taskMgr 是控制面任务层（懒加载）：长任务提交给它受理，task.* 从它读状态与
	// 事件。懒加载是为了让「从不发包」的会话不必付出拉子进程执行器的代价。
	taskMgr  *scantask.Manager
	taskOnce sync.Once
	taskErr  error

	// timeoutMu/timeouts 登记因超时被看护取消的任务，供 scanStatus 把「跑太久了」
	// 与「人去取消的」区分开。
	timeoutMu sync.Mutex
	timeouts  map[string]struct{}

	// callMu/cancels 登记在途调用的取消函数，供 notifications/cancelled 精确取消
	// 某一次调用（而不是靠客户端断连把整条连接一起掐掉）。
	callMu  sync.Mutex
	cancels map[string]context.CancelFunc

	// logMu/logMinLevel 是 logging 原语的当前最低级别（logging/setLevel 设置），
	// 低于它的日志不推给客户端。默认 info。
	logMu       sync.Mutex
	logMinLevel int

	// webscanOnce/webscanMatcher 缓存内置 Web 指纹规则：规则集是只读的，
	// 每次调用都重新解析只会白白拖慢探测。
	webscanOnce    sync.Once
	webscanMatcher *webscan.Matcher
	webscanErr     error
}

// New 创建服务端并注册内置工具。
func New(opts Options) *Server {
	p := opts.Policy
	if p == nil {
		p = policy.Default()
	}
	b := opts.Budget
	if b == nil {
		b = policy.NewBudget(p.Limits, nowFunc())
	}
	info := opts.Info
	if info.Name == "" {
		info.Name = "afrog"
	}

	s := &Server{gate: policy.NewGate(p, b, opts.Auditor), info: info, oob: opts.OOB, exec: opts.Executor, logMinLevel: mcpLogLevels["info"]}
	s.tools = s.buildTools()
	return s
}

// scanExecutor 返回发包执行器：显式注入的优先，否则懒加载本地子进程执行器。
//
// 子进程的 stderr 只进服务端日志：它的 stdout 已被 NDJSON 事件流占用。
func (s *Server) scanExecutor() (executor.Executor, error) {
	if s.exec != nil {
		return s.exec, nil
	}
	s.execOnce.Do(func() {
		lp, err := executor.NewLocalProcess()
		if err != nil {
			s.execErr = err
			return
		}
		lp.OnStderr = func(line string) {
			if strings.TrimSpace(line) != "" {
				gologger.Debug().Str("source", "mcp-scan-child").Msg(line)
			}
		}
		s.exec = lp
	})
	if s.execErr != nil {
		return nil, s.execErr
	}
	return s.exec, nil
}

// NewWithPaths 按策略 YAML 与审计 JSONL 路径装配工具面，供 MCP 之外的传输适配层
// （REST `/api/v1/call`、gRPC `AgentService`）复用同一套装配口径。
//
// 两者都留空即沿用只读默认策略、不落盘审计：Web 服务与 `afrog serve` 因此默认
// 不获得发包能力。策略文件格式与 `afrog mcp -policy` 完全一致。
//
// oob 为 nil 表示不使用带外能力：act.oob_* 仍然注册，但会明确报未配置。
func NewWithPaths(policyPath, auditPath string, oob OOBSource, info ServerInfo) (*Server, error) {
	p := policy.Default()
	if strings.TrimSpace(policyPath) != "" {
		loaded, err := policy.Load(policyPath)
		if err != nil {
			return nil, err
		}
		p = loaded
	}
	var auditor *policy.Auditor
	if strings.TrimSpace(auditPath) != "" {
		auditor = policy.NewAuditor(FileAuditWriter{Path: auditPath})
	}
	return New(Options{Policy: p, Auditor: auditor, OOB: oob, Info: info}), nil
}

// FileAuditWriter 每次写入都重新打开文件：不持有长驻句柄，日志轮转/删除后能自动重建。
type FileAuditWriter struct{ Path string }

func (w FileAuditWriter) Write(p []byte) (int, error) {
	f, err := os.OpenFile(w.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.Write(p)
}

// ToolNames 返回已注册的工具名，便于测试与自检。
func (s *Server) ToolNames() []string {
	out := make([]string, 0, len(s.tools))
	for name := range s.tools {
		out = append(out, name)
	}
	return out
}

// Specs 返回全部工具的描述（名称、标题、说明、入参/出参 schema），顺序与 toolList 一致。
// tools/list 与其它传输的「列出工具」都从这里取，避免清单出现两份。
func (s *Server) Specs() []ToolSpec {
	out := make([]ToolSpec, 0, len(s.tools))
	for _, t := range s.tools {
		out = append(out, ToolSpec{
			Name:         t.Name,
			Title:        t.Title,
			Description:  t.Description,
			InputSchema:  t.InputSchema,
			OutputSchema: t.OutputSchema,
			Capability:   t.Capability,
			Destructive:  t.Destructive,
		})
	}
	return out
}

// Gate 返回底层的策略门控，供 Web 控制台读取当前策略与预算余量。
// 它只暴露既有能力（Policy / Budget 都是只读访问器），不新增执行入口。
func (s *Server) Gate() *policy.Gate {
	return s.gate
}

// --- JSON-RPC 传输层 ---

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
	// codeResourceNotFound 是 MCP 为 resources/read 约定的「没有这个资源」。
	codeResourceNotFound = -32002
)

// Serve 在给定的读写流上跑 MCP 主循环，直到输入结束。
//
// 每个请求在独立协程里处理，而不是逐条串行：stdio 是可并发读写的持久连接，只有这样
// notifications/cancelled 才可能在一次长调用进行中被读到，progress 也才有地方推。
// 响应写回用互斥锁串起来，避免多次 Encode 交错成半行 JSON。
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var writeMu sync.Mutex
	enc := json.NewEncoder(out)
	write := func(v any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return enc.Encode(v)
	}

	// notify 让工具在长调用过程中推送通知（目前只有 notifications/progress）。
	notify := func(method string, params any) {
		_ = write(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
	}

	var wg sync.WaitGroup
	var loopErr error
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			loopErr = err
			break
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			if werr := write(response{JSONRPC: "2.0", Error: &rpcError{Code: codeParseError, Message: "parse error"}}); werr != nil {
				loopErr = werr
				break
			}
			continue
		}

		wg.Add(1)
		go func(req request) {
			defer wg.Done()
			resp, isNotify := s.handle(ctx, &req, notify)
			if isNotify || resp == nil {
				return
			}
			_ = write(resp)
		}(req)
	}
	wg.Wait()

	if loopErr != nil {
		return loopErr
	}
	return scanner.Err()
}

func (s *Server) handle(ctx context.Context, req *request, notify notifyFunc) (*response, bool) {
	// 没有 id 的是通知（如 notifications/initialized），按协议不回复。
	notification := len(req.ID) == 0

	switch req.Method {
	case "initialize":
		return s.ok(req.ID, s.initializeResult(req.Params)), false
	case "ping":
		return s.ok(req.ID, map[string]any{}), false
	case "tools/list":
		return s.ok(req.ID, map[string]any{"tools": s.toolList()}), false
	case "tools/call":
		return s.callTool(ctx, req, notify)
	case "resources/list":
		return s.ok(req.ID, map[string]any{"resources": s.resourceList()}), false
	case "resources/templates/list":
		return s.ok(req.ID, map[string]any{"resourceTemplates": s.resourceTemplates()}), false
	case "resources/read":
		return s.resourceRead(ctx, req)
	case "prompts/list":
		return s.ok(req.ID, map[string]any{"prompts": s.promptList()}), false
	case "prompts/get":
		return s.promptGet(req)
	case "logging/setLevel":
		return s.setLogLevel(req)
	case "notifications/initialized":
		return nil, true
	case "notifications/cancelled":
		// 客户端放弃某一次调用：按 requestId 精确取消它，而不是把整条连接一起断掉。
		s.cancelCall(req.Params)
		return nil, true
	default:
		if notification {
			return nil, true
		}
		return &response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{
			Code:    codeMethodNotFound,
			Message: fmt.Sprintf("method not found: %s", req.Method),
		}}, false
	}
}

// callKey 把 JSON-RPC id 规范成登记用的键，让 `3` 与 ` 3 ` 视作同一次调用。
func callKey(id json.RawMessage) string {
	return string(bytes.TrimSpace(id))
}

func (s *Server) registerCall(id json.RawMessage, cancel context.CancelFunc) {
	key := callKey(id)
	if key == "" {
		return
	}
	s.callMu.Lock()
	if s.cancels == nil {
		s.cancels = make(map[string]context.CancelFunc)
	}
	s.cancels[key] = cancel
	s.callMu.Unlock()
}

func (s *Server) unregisterCall(id json.RawMessage) {
	key := callKey(id)
	if key == "" {
		return
	}
	s.callMu.Lock()
	delete(s.cancels, key)
	s.callMu.Unlock()
}

// cancelCall 处理 notifications/cancelled：只取消被点名的那一次调用。找不到就忽略——
// 它可能已经正常结束，也可能本传输根本不支持中途取消。
func (s *Server) cancelCall(params json.RawMessage) {
	var p struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return
	}
	key := callKey(p.RequestID)
	if key == "" {
		return
	}
	s.callMu.Lock()
	cancel := s.cancels[key]
	s.callMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Server) initializeResult(params json.RawMessage) map[string]any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	return map[string]any{
		// 客户端报的版本在支持集内就沿用，否则回我们自己支持的最新版；
		// 原样复述一个不会说的版本等于宣称支持它。
		"protocolVersion": negotiateProtocolVersion(p.ProtocolVersion),
		"capabilities": map[string]any{
			"tools":   map[string]any{"listChanged": false},
			"logging": map[string]any{},
			// resources 只读、不订阅：本服务没有会话级订阅状态（见 resources.go）。
			// 显式写 false 而不是留空，免得客户端以为可以订阅、然后等一个永不来的推送。
			"resources": map[string]any{"subscribe": false, "listChanged": false},
			"prompts":   map[string]any{"listChanged": false},
		},
		"serverInfo": s.info,
		// instructions 是 MCP 规范里 initialize 的可选字段：客户端会把它并入
		// 模型上下文，用来告诉模型「这套工具该怎么用」。见 Instructions。
		"instructions": Instructions,
	}
}

func (s *Server) toolList() []map[string]any {
	specs := s.Specs()
	out := make([]map[string]any, 0, len(specs))
	for _, t := range specs {
		entry := map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
			// annotations 只是提示，不参与门控：客户端据此决定能否把只读工具
			// 自动放行、是否对破坏性动作先弹确认。放行与否仍由策略与预算决定。
			"annotations": annotationsFor(t.Name),
		}
		if t.Title != "" {
			entry["title"] = t.Title
		}
		if t.OutputSchema != nil {
			entry["outputSchema"] = t.OutputSchema
		}
		out = append(out, entry)
	}
	return out
}

func (s *Server) callTool(ctx context.Context, req *request, notify notifyFunc) (*response, bool) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		// _meta.progressToken 是客户端「要进度」的声明：没带就不该推通知。
		Meta *struct {
			ProgressToken any `json:"progressToken"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{
			Code: codeInvalidParams, Message: "invalid params",
		}}, false
	}

	tool, ok := s.tools[params.Name]
	if !ok {
		return &response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{
			Code: codeMethodNotFound, Message: "unknown tool: " + params.Name,
		}}, false
	}

	// 让这次调用可以被 notifications/cancelled 精确取消。
	if len(req.ID) > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		s.registerCall(req.ID, cancel)
		defer s.unregisterCall(req.ID)
	}

	// 客户端带了 progressToken、且当前传输有推送通道时，才把进度接进 ctx。
	if notify != nil && params.Meta != nil && params.Meta.ProgressToken != nil {
		token := params.Meta.ProgressToken
		ctx = withProgress(ctx, func(progress, total float64, message string) {
			notify("notifications/progress", map[string]any{
				"progressToken": token,
				"progress":      progress,
				"total":         total,
				"message":       message,
			})
		})
	}

	// 有推送通道时把日志接进 ctx：工具执行期间的诊断日志经 notifications/message
	// 实时给到客户端，调用方据此排障，不必等整批结束（也看不到中途发生了什么）。
	if notify != nil {
		ctx = withLogger(ctx, func(level, message string) {
			if !s.logAtLeast(level) {
				return
			}
			notify("notifications/message", map[string]any{
				"level":  level,
				"logger": "afrog",
				"data":   message,
			})
		})
	}

	result, err := tool.Handler(ctx, params.Arguments)
	if err != nil {
		return s.ok(req.ID, toolError(err)), false
	}
	return s.ok(req.ID, toolContent(tool, result)), false
}

func (s *Server) ok(id json.RawMessage, result any) *response {
	return &response{JSONRPC: "2.0", ID: id, Result: result}
}

// setLogLevel 处理 logging/setLevel：设定服务端推送日志的最低级别。
//
// 只接受 MCP 规范里的级别名（debug…emergency）；未知级别按协议报 -32602，
// 而不是静默回落——静默会让客户端以为设置生效了。
func (s *Server) setLogLevel(req *request) (*response, bool) {
	var p struct {
		Level string `json:"level"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return &response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{
			Code: codeInvalidParams, Message: "invalid params",
		}}, false
	}
	rank, ok := mcpLogLevels[strings.ToLower(strings.TrimSpace(p.Level))]
	if !ok {
		return &response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{
			Code: codeInvalidParams, Message: "unknown log level: " + p.Level,
		}}, false
	}
	s.logMu.Lock()
	s.logMinLevel = rank
	s.logMu.Unlock()
	return s.ok(req.ID, map[string]any{}), false
}

// logAtLeast 判断某级别的日志是否达到当前最低级别、可以推送给客户端。
func (s *Server) logAtLeast(level string) bool {
	s.logMu.Lock()
	min := s.logMinLevel
	s.logMu.Unlock()
	return logLevelRank(level) >= min
}

func toolError(err error) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": err.Error()}},
		"isError": true,
	}
}

// toolContent 把工具结果包成 MCP 的 CallToolResult。
//
// 声明了 outputSchema 的工具，其返回结构是稳定契约，因此额外给一份 structuredContent：
// 客户端可以直接按 schema 取值，不必再从 text 里解析 JSON。没声明的工具只给 text——
// 它们的返回值可能很大，多塞一份只会让响应体凭空翻倍。
func toolContent(t *Tool, v any) map[string]any {
	var text string
	switch s := v.(type) {
	case string:
		text = s
	default:
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return toolError(err)
		}
		text = string(b)
	}
	out := map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
	}
	if t != nil && t.OutputSchema != nil {
		var generic any
		if b, err := json.Marshal(v); err == nil && json.Unmarshal(b, &generic) == nil {
			if _, ok := generic.(map[string]any); ok {
				out["structuredContent"] = generic
			}
		}
	}
	return out
}

// Call 以编程方式调用一个工具，供 MCP 之外的传输（如 REST）复用同一套工具面
// 与策略门控：策略、预算、审计都在工具处理器内部统一执行，调用方无需重复实现。
func (s *Server) Call(ctx context.Context, name string, args json.RawMessage) (any, error) {
	tool, ok := s.tools[name]
	if !ok {
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	return tool.Handler(ctx, args)
}
