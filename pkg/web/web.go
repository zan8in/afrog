package web

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
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
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	generatedPassword = generateRandomPassword()
	initJWTSecret()
	gologger.Info().Msgf("Web访问密码: %s", generatedPassword)

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

	// 初始化系统监控
	InitMonitor()
	defer StopMonitor() // 确保退出时停止

	// 启动计划扫描调度器（Curated 会员能力；非会员时只推进时间、不执行）
	StartScheduler()
	defer StopScheduler()

	// 启动多实例编排的同伴心跳（未配置 cluster.peers 时只保留本机视图）
	StartCluster()
	defer StopCluster()

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
	return srv.ListenAndServe()
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
