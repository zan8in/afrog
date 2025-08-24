package web

import (
	"net/http"

	"github.com/zan8in/gologger"
)

func StartServer(addr string) error {
	// 初始化安全组件
	generatedPassword = generateRandomPassword()
	initJWTSecret()
	gologger.Info().Str("password", generatedPassword).Msg("Web访问密码")

	// 构建路由与静态文件服务
	handler, err := setupHandler()
	if err != nil {
		return err
	}

	gologger.Info().Msgf("Web服务器启动于: http://%s", addr)
	return http.ListenAndServe(addr, handler)
}
