package web

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
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
var httpSrv *http.Server

func generateInstanceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func StartServer(addr string) error {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
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

	// 初始化系统监控
	InitMonitor()
	defer StopMonitor() // 确保退出时停止

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
	serverBaseURL = "http://" + addr
	serverPID = os.Getpid()
	serverArgv = os.Args
	httpSrv = srv

	gologger.Info().Msgf("Web服务器启动于: http://%s", addr)
	return srv.ListenAndServe()
}
