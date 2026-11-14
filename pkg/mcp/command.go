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
// 默认策略是只读——一个刚被拉起的服务不应该自动获得发包能力，需要按需用
// -policy 显式放宽到 safe 或 full。
func Command(args []string) error {
	fs := flag.NewFlagSet("afrog mcp", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "策略 YAML 路径；留空使用只读默认策略")
	auditPath := fs.String("audit", "", "策略审计日志路径（JSONL）；留空不记录")
	listen := fs.String("listen", "", "以 HTTP+SSE 方式监听（如 127.0.0.1:16870）；留空走 stdio")
	token := fs.String("token", "", "SSE 模式的访问 token；监听非本机地址时必须提供")
	if err := fs.Parse(args); err != nil {
		return err
	}

	gologger.DefaultLogger.SetWriter(stderrLogWriter{})

	p := policy.Default()
	if strings.TrimSpace(*policyPath) != "" {
		loaded, err := policy.Load(*policyPath)
		if err != nil {
			return err
		}
		p = loaded
	}

	var auditor *policy.Auditor
	if strings.TrimSpace(*auditPath) != "" {
		f, err := os.OpenFile(*auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
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

	// 保留策略与 CLI/Web 共用 afrog-config.yaml；读不到配置就沿用默认值。
	if cfg, cfgErr := config.LoadConfigReadOnly(""); cfgErr == nil && cfg.Observe.MaxRows != nil {
		sqlite.SetObservationMaxRows(*cfg.Observe.MaxRows)
	}

	srv := New(Options{
		Policy:  p,
		Auditor: auditor,
		Info:    ServerInfo{Name: "afrog", Version: config.Version},
	})

	addr := strings.TrimSpace(*listen)
	if addr == "" {
		return srv.Serve(context.Background(), os.Stdin, os.Stdout)
	}
	if !isLoopbackAddr(addr) && strings.TrimSpace(*token) == "" {
		return fmt.Errorf("refusing to expose MCP on %s without -token", addr)
	}
	return serveSSE(srv, addr, *token)
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

// isLoopbackAddr 判断监听地址是否只对本机可见。空 host、0.0.0.0、:: 都算对外暴露。
func isLoopbackAddr(addr string) bool {
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
