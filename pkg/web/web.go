package web

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/guard"
	"github.com/zan8in/gologger"
	"github.com/zan8in/gologger/levels"
)

var serverInstanceID string
var serverStartedAt time.Time
var serverBaseURL string
var serverPID int
var serverArgv []string

func generateInstanceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func StartServer(addr string) error {
	// 先占端口：端口不可用（被占用/无权限）就没必要再初始化数据库、调度器与实例编排，
	// 也能避免先打印一堆「已启动」再紧跟一串「已停止」的误导日志。
	ln, err := listenWebPort(addr)
	if err != nil {
		return err
	}
	serving := false
	defer func() {
		// 交给 srv.Serve 后由它负责关闭；中途失败（数据库/路由出错）在这里释放。
		if !serving {
			_ = ln.Close()
		}
	}()

	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	generatedPassword = generateRandomPassword()
	initJWTSecret()
	gologger.Info().Msgf("Web访问密码: %s", generatedPassword)

	// 闸门裁决落盘：重启后仍能看到谁被拒绝/放行。写入失败只记日志（见 appendGuardAudit），
	// 不影响任何动作。只在服务端启用，避免测试或 CLI 路径写用户目录。
	guard.SetSink(appendGuardAudit)
	defer guard.SetSink(nil)

	// 初始化数据库（连接 + 写入worker）
	if err := sqlite.NewWebSqliteDB(); err != nil {
		return err
	}
	if err := sqlite.InitX(); err != nil {
		return err
	}
	defer sqlite.CloseX()

	// 一次性升级：旧版项目里独立保存的 targets 改为对资产的引用。
	migrateProjectsToAssets()

	// 历史脏资产清洗：只删「从未扫描、未收藏/打标签/归档」的无效地址（如 "21"），
	// 避免它们混进「一键扫描」建议。失败只记日志，不影响启动。
	if n, err := sqlite.CleanupInvalidAssets(); err != nil {
		gologger.Debug().Msgf("无效资产清理失败: %v", err)
	} else if n > 0 {
		gologger.Info().Msgf("已清理 %d 条无效资产（无法作为扫描目标的地址）", n)
	}

	// 历史资产补建图边：新库为空几乎无开销；失败只记日志，不影响启动。
	if n, err := sqlite.BackfillAssetGraph(5000); err != nil {
		gologger.Debug().Msgf("资产图补建失败: %v", err)
	} else if n > 0 {
		gologger.Info().Msgf("资产图补建完成: %d 条资产", n)
	}

	// 历史被动命中补建「端点 → 参数」边：同样幂等，重复启动不会产生新行。
	if n, err := sqlite.BackfillEndpointGraph(2000); err != nil {
		gologger.Debug().Msgf("端点图补建失败: %v", err)
	} else if n > 0 {
		gologger.Info().Msgf("端点图补建完成: %d 条被动命中", n)
	}

	// 初始化系统监控
	InitMonitor()
	defer StopMonitor() // 确保退出时停止

	// 启动计划扫描调度器（Curated 会员能力；非会员时只推进时间、不执行）
	StartScheduler()
	defer StopScheduler()

	// 启动多实例编排的同伴心跳（未配置 cluster.peers 时只保留本机视图）
	StartCluster()
	defer StopCluster()

	// 被动扫描代理：配置里开启 auto_start 时自动启动；否则等前端显式开启。
	// 退出时一定收尾，避免 API 启动过的代理在进程退出后仍占用端口。
	AutoStartPassive()
	defer StopPassive()

	// 恢复上次运行落盘的远程派发镜像记录：发起端重启后任务列表不丢，
	// 未完成的任务继续交给对账协程按远端任务号收敛。
	remotePersistEnabled = true
	if RestoreRemoteTasks() > 0 {
		startRemoteReconciler()
	}

	// 构建路由与静态文件服务
	handler, err := setupHandler()
	if err != nil {
		return err
	}

	// 使用 http.Server 并设置超时，提升抗慢速攻击能力
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}

	serverInstanceID = generateInstanceID()
	serverStartedAt = time.Now().UTC()
	// 监听地址常配成 ":16868"（所有网卡），它本身不是合法 URL 的主机部分：
	// 直接拼成 "http://:16868" 会误导用户去浏览器打开一个打不开的地址，
	// 也会让前端拿到一个解析不了的 base_url。
	serverBaseURL = "http://" + browsableAddr(addr)
	serverPID = os.Getpid()
	serverArgv = os.Args

	gologger.Info().Msgf("Web服务器启动于: %s", serverBaseURL)
	serving = true
	return srv.Serve(ln)
}

// listenWebPort 提前完成端口绑定：把「端口被占用」这类问题在启动早期就暴露出来。
func listenWebPort(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, describeListenError(addr, err)
	}
	return ln, nil
}

// describeListenError 把绑定失败整理成能照着做的提示，端口被占用时额外指出占用进程。
func describeListenError(addr string, err error) error {
	host := browsableAddr(addr)
	if !errors.Is(err, syscall.EADDRINUSE) {
		return fmt.Errorf("无法监听 %s: %w", host, err)
	}
	msg := fmt.Sprintf("端口已被占用，Web 服务无法启动：%s", host)
	if holder := portHolder(addr); holder != "" {
		msg += fmt.Sprintf(" 已被 %s 监听", holder)
	}
	return fmt.Errorf("%s；请先停止占用该端口的进程，或在 afrog-config.yaml 里把 server 改成其他端口（例如 \":16869\"）后重试", msg)
}

// portHolder 尽力找出监听该端口的进程，仅用于错误提示；取不到（如系统无 lsof）返回空串。
func portHolder(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return ""
	}
	out, err := exec.Command("lsof", "-nP", "-iTCP:"+port, "-sTCP:LISTEN").Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 { // 只有表头，说明没查到
		return ""
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 2 {
		return ""
	}
	return fmt.Sprintf("%s (pid %s)", fields[0], fields[1])
}

// browsableAddr 把监听地址转成浏览器/客户端可直接使用的地址。
func browsableAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "127.0.0.1"
	}
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	return addr
}
