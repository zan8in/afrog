package web

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zan8in/gologger"
)

// 包内共享的访问密码（由 StartServer 设置）
var generatedPassword string

// JWT密钥（进程内随机）
var jwtSecret []byte

// JWT Claims结构
type Claims struct {
	UserID    string `json:"user_id"`
	LoginTime int64  `json:"login_time"`
	jwt.RegisteredClaims
}

// 初始化JWT密钥
func initJWTSecret() {
	jwtSecret = make([]byte, 32)
	rand.Read(jwtSecret)
	gologger.Info().Msg("JWT密钥已生成")
}

// 生成JWT Token
func generateJWTToken(userID string) (string, int64, error) {
	expires := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID:    userID,
		LoginTime: time.Now().Unix(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expires),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "afrog-security-scanner",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	return tokenString, expires.Unix(), err
}

// 验证JWT Token
func validateJWTToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("意外的签名方法: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("无效的token")
}