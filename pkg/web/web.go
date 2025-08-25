package web

import (
	"net/http"
	"time"

	"github.com/zan8in/gologger"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
)

func StartServer(addr string) error {
	// 初始化安全组件
	generatedPassword = generateRandomPassword()
	initJWTSecret()
	gologger.Info().Str("password", generatedPassword).Msg("Web访问密码")

	// 初始化数据库（连接 + 写入worker）
	if err := sqlite.NewWebSqliteDB(); err != nil {
		return err
	}
	if err := sqlite.InitX(); err != nil {
		return err
	}
	defer sqlite.CloseX()

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
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	gologger.Info().Msgf("Web服务器启动于: http://%s", addr)
	return srv.ListenAndServe()
}
