package web

import (
	"crypto/rand"
	"encoding/hex"
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
	// 短期有效（建议10-15分钟），提升被窃取后的风险控制能力
	expires := time.Now().Add(1 * time.Minute)
	jti := generateJTI()

	claims := &Claims{
		UserID:    userID,
		LoginTime: time.Now().Unix(),
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,                               // jti
			Subject:   userID,                            // sub
			Audience:  jwt.ClaimStrings{"afrog-web-api"}, // aud
			ExpiresAt: jwt.NewNumericDate(expires),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "afrog-security-scanner", // iss
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
		// 强化校验：issuer 与 audience
		if claims.Issuer != "afrog-security-scanner" {
			return nil, fmt.Errorf("issuer不匹配")
		}
		// 修改这里：不要使用 VerifyAudience，手动校验 audience
		audOK := false
		for _, aud := range claims.Audience {
			if aud == "afrog-web-api" {
				audOK = true
				break
			}
		}
		if !audOK {
			return nil, fmt.Errorf("audience不匹配")
		}
		return claims, nil
	}
	return nil, fmt.Errorf("无效的token")
}

// 生成 jti
func generateJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
