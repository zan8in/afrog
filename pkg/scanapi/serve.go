package scanapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/mcp"
	"github.com/zan8in/afrog/v3/pkg/scantask"
	afrogv1 "github.com/zan8in/afrog/v3/proto/afrog/v1"
	"github.com/zan8in/gologger"
	"google.golang.org/grpc"
)

// DefaultListenAddr 是控制面 gRPC 的默认监听地址。
// 16868 留给 Web UI，控制面用相邻端口，避免两个服务抢同一个地址。
const DefaultListenAddr = ":16869"

// ServeCommand 实现 `afrog serve`：解析自身参数并启动控制面 gRPC 服务。
//
// 放在库包而不是 cmd/afrog 目录下，是因为 README 与安装文档使用
// `go run cmd/afrog/main.go` / `go build -o afrog cmd/afrog/main.go` 这类单文件构建，
// 同目录新增的其它文件不会被编译进去。
func ServeCommand(args []string) error {
	fs := flag.NewFlagSet("afrog serve", flag.ContinueOnError)
	listen := fs.String("listen", DefaultListenAddr, "gRPC 监听地址")
	apiToken := fs.String("api-token", "", "控制台 API token；留空则随机生成并在启动时打印")
	maxRunning := fs.Int("max-running", scantask.DefaultMaxRunning, "并发扫描上限")
	eventBuffer := fs.Int("event-buffer", scantask.DefaultEventBuffer, "每个任务保留的事件条数上限")
	if err := fs.Parse(args); err != nil {
		return err
	}

	token := strings.TrimSpace(*apiToken)
	generated := false
	if token == "" {
		var err error
		if token, err = randomToken(); err != nil {
			return err
		}
		generated = true
	}

	// 控制面要能查结果（GetResults），因此需要打开与控制面同一份 sqlite。
	// 扫描结果由执行扫描的一方写入：本机是子进程自己写，远程节点由控制面按事件写。
	if err := sqlite.NewWebSqliteDB(); err != nil {
		return fmt.Errorf("init sqlite: %w", err)
	}
	defer sqlite.CloseX()

	ex, err := executor.NewLocalProcess()
	if err != nil {
		return err
	}
	ex.OnStderr = func(line string) {
		if strings.TrimSpace(line) != "" {
			gologger.Debug().Str("source", "scan-child").Msg(line)
		}
	}

	// Agent 工具面（AgentService）：与 MCP / REST 共用同一份工具注册表与门控。
	// 策略/审计来自 afrog-config.yaml 的 agent 段，留空即只读默认——控制面默认
	// 不获得发包能力，写动作一律被拒。
	agentCfg := config.Agent{}
	var reverseCfg config.Reverse
	if cfg, cerr := config.LoadConfigReadOnly(""); cerr != nil {
		gologger.Error().Msgf("读取 afrog-config.yaml 失败，Agent 工具面沿用只读默认: %v", cerr)
	} else if cfg != nil {
		agentCfg = cfg.Agent
		reverseCfg = cfg.Reverse
	}
	// agent.oob 指定工具面的反连适配器（凭据取 reverse 段）：未配置就没有反连能力，
	// act.oob_* 会明确报未配置。适配器配错不应拖垮整个工具面，因此只记日志、不发包。
	oob, oobErr := mcp.NewOOBSource(agentCfg.OOB, reverseCfg)
	if oobErr != nil {
		gologger.Error().Msgf("初始化工具面反连后端失败，act.oob_* 将不可用: %v", oobErr)
		oob = nil
	}
	tools, err := mcp.NewWithPaths(agentCfg.Policy, agentCfg.Audit, oob, mcp.ServerInfo{})
	if err != nil {
		return fmt.Errorf("init agent tools: %w", err)
	}

	mgr, err := scantask.New(scantask.Options{
		Executor:   ex,
		Dispatcher: tools.Dispatcher(),
		MaxRunning: *maxRunning,
		// 工具面动作（probe_http / replay_evidence / brute）与扫描任务共用同一套
		// 排队、事件窗口与收尾，见 scantask.Dispatcher。
		EventBuffer: *eventBuffer,
	})
	if err != nil {
		return err
	}

	srv, err := New(Options{Manager: mgr, Token: token})
	if err != nil {
		return err
	}

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", *listen, err)
	}

	grpcSrv := grpc.NewServer(
		grpc.UnaryInterceptor(UnaryAuth(token)),
		grpc.StreamInterceptor(StreamAuth(token)),
	)
	afrogv1.RegisterAfrogScannerServer(grpcSrv, srv)

	// Agent 工具面（AgentService）：与控制面共用同一份工具注册表与门控。
	agentSrv, err := NewAgentService(tools)
	if err != nil {
		return err
	}
	afrogv1.RegisterAgentServiceServer(grpcSrv, agentSrv)

	agentLabel := "只读默认（未配置 agent.policy）"
	if strings.TrimSpace(agentCfg.Policy) != "" {
		agentLabel = agentCfg.Policy
	}

	gologger.Info().Msgf("控制面 gRPC 已启动: %s", lis.Addr().String())
	if generated {
		gologger.Info().Msgf("控制台 API token（本次启动有效）: %s", token)
	}
	gologger.Info().Msgf("节点=%s 并发上限=%d 事件窗口=%d Agent工具面=%s", mgr.Node(), *maxRunning, *eventBuffer, agentLabel)
	gologger.Info().Msgf("示例: grpcurl -H 'authorization: Bearer <token>' -d '{\"spec\":{\"targets\":[\"http://example.com\"]}}' %s afrog.v1.AfrogScanner/SubmitScan",
		lis.Addr().String())
	gologger.Info().Msgf("示例: grpcurl -H 'authorization: Bearer <token>' -d '{\"name\":\"observe.state\",\"arguments_json\":\"{\\\"subject\\\":\\\"example.com\\\"}\"}' %s afrog.v1.AgentService/Invoke",
		lis.Addr().String())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() { serveErr <- grpcSrv.Serve(lis) }()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		gologger.Info().Msg("收到退出信号，正在停止控制面…")
		grpcSrv.GracefulStop()
		return nil
	}
}

// randomToken 生成 32 字符的十六进制 token，与 Web 访问密码同规格。
func randomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("scanapi: generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
