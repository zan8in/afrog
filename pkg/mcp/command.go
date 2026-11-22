package mcp

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/policy"
	"github.com/zan8in/gologger"
	"github.com/zan8in/gologger/levels"
)

// stderrLogWriter 把 gologger 输出统一改到 stderr。
//
// MCP 的 stdio 传输把 stdout 当作协议通道，任何一行日志混进去都会让客户端
// 解析失败，因此引擎与 SDK 的人类可读输出必须全部改道。
type stderrLogWriter struct{}

func (stderrLogWriter) Write(data []byte, _ levels.Level) {
	_, _ = os.Stderr.Write(data)
	_, _ = os.Stderr.Write([]byte("\n"))
}

// Command 实现 `afrog mcp`：在 stdio 上提供 MCP 工具服务。
//
// 策略来源与 Web 控制台同一份：优先 -policy 指向的 YAML，未传时用 afrog-config.yaml
// 的 agent.policy（控制台「策略与审计」保存的就是它）。两者都没有才回落到只读默认——
// 一个刚被拉起的服务不应该自动获得发包能力，放宽档位必须由使用者显式配置。
func Command(args []string) error {
	fs := flag.NewFlagSet("afrog mcp", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "策略 YAML 路径；留空时用 afrog-config.yaml 的 agent.policy，仍为空则只读默认")
	auditPath := fs.String("audit", "", "策略审计日志路径（JSONL）；留空时用 afrog-config.yaml 的 agent.audit，仍为空则不记录")
	listen := fs.String("listen", "", "以 HTTP+SSE 方式监听（如 127.0.0.1:16870）；留空时用 afrog-config.yaml 的 agent.mcp.listen，仍为空则走 stdio")
	token := fs.String("token", "", "SSE 模式的访问 token；留空时用 afrog-config.yaml 的 agent.mcp.token；监听非本机地址时必须提供")
	if err := fs.Parse(args); err != nil {
		return err
	}

	gologger.DefaultLogger.SetWriter(stderrLogWriter{})

	// 策略、审计与观测保留上限共用 afrog-config.yaml；读不到配置就沿用默认值。
	cfg, cfgErr := config.LoadConfigReadOnly("")
	if cfgErr != nil {
		cfg = nil
	}

	path := strings.TrimSpace(*policyPath)
	explicitPolicy := path != ""
	if !explicitPolicy && cfg != nil {
		path = strings.TrimSpace(cfg.Agent.Policy)
	}
	p := policy.Default()
	if path != "" {
		loaded, err := policy.Load(path)
		switch {
		case err == nil:
			p = loaded
		case explicitPolicy:
			return err
		default:
			// 配置里指的策略文件坏了不该让 MCP 起不来：退回只读默认并说明原因。
			gologger.Error().Msgf("加载 agent.policy(%s) 失败，本次回退只读默认: %v", path, err)
		}
	}

	audit := strings.TrimSpace(*auditPath)
	if audit == "" && cfg != nil {
		audit = strings.TrimSpace(cfg.Agent.Audit)
	}
	var auditor *policy.Auditor
	if audit != "" {
		f, err := os.OpenFile(audit, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		auditor = policy.NewAuditor(f)
	}

	// observe.* 直接查库，因此服务启动时就把与 Web 控制台同一份 sqlite 打开。
	if err := sqlite.NewWebSqliteDB(); err != nil {
		return err
	}
	defer sqlite.CloseX()

	// agent.oob 指定工具面的反连适配器（凭据取 reverse 段）：未配置就没有反连能力，
	// act.oob_* 会明确报未配置，而不是静默等一个不会来的回连。
	var oob OOBSource
	if cfg != nil {
		if cfg.Observe.MaxRows != nil {
			sqlite.SetObservationMaxRows(*cfg.Observe.MaxRows)
		}
		src, oobErr := NewOOBSource(cfg.Agent.OOB, cfg.Reverse)
		if oobErr != nil {
			gologger.Error().Msgf("初始化工具面反连后端失败，act.oob_* 将不可用: %v", oobErr)
		} else {
			oob = src
		}
	}

	srv := New(Options{
		Policy:  p,
		Auditor: auditor,
		OOB:     oob,
		Info:    ServerInfo{Name: "afrog", Version: config.Version},
	})

	addr := strings.TrimSpace(*listen)
	addrFromConfig := false
	if addr == "" && cfg != nil {
		if v := strings.TrimSpace(cfg.Agent.MCP.Listen); v != "" {
			addr, addrFromConfig = v, true
		}
	}
	if addr == "" {
		return srv.Serve(context.Background(), os.Stdin, os.Stdout)
	}
	if addrFromConfig {
		// 配置生效必须可见：否则使用者会以为服务监听在别处。
		gologger.Info().Msgf("使用 afrog-config.yaml 的 agent.mcp.listen=%s", addr)
	}

	tok := strings.TrimSpace(*token)
	if tok == "" && cfg != nil {
		if v := strings.TrimSpace(cfg.Agent.MCP.Token); v != "" {
			tok = v
			gologger.Info().Msgf("使用 afrog-config.yaml 的 agent.mcp.token=%s", maskMCPToken(v))
		}
	}
	if !IsLoopbackAddr(addr) && tok == "" {
		return fmt.Errorf("refusing to expose MCP on %s without -token", addr)
	}
	return serveSSE(srv, addr, tok)
}

// serveSSE 以 HTTP+SSE 方式提供 MCP 服务，收到 Ctrl+C / SIGTERM 时优雅退出。
func serveSSE(srv *Server, addr, token string) error {
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           newHTTPMux(srv, token),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	gologger.Info().Msgf("afrog mcp listening on %s (http: /mcp, /sse)", addr)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// IsLoopbackAddr 判断监听地址是否只对本机可见。空 host、0.0.0.0、:: 都算对外暴露。
//
// 导出供 Web 控制台的「MCP 服务」面板复用，避免各处重复实现同一判定。
func IsLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// maskMCPToken 用于日志回显 token：只留首尾各两位，中间以 `*` 占位。
//
// 目的是让使用者确认「读到了哪个 token」，又不把明文写进日志或终端回滚缓冲。
func maskMCPToken(token string) string {
	if token == "" {
		return ""
	}
	if len(token) <= 6 {
		return strings.Repeat("*", len(token))
	}
	return token[:2] + strings.Repeat("*", len(token)-4) + token[len(token)-2:]
}
