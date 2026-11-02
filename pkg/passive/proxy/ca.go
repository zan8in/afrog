package proxy

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/martian/v3/mitm"
)

// CA 是被动扫描的根证书。
//
// 根证书必须持久化：客户端（Burp / 浏览器）一旦信任了某张 CA，服务重启后就必须
// 还是同一张，否则每次重启都要重新导入，实际不可用。
type CA struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

const (
	caCertFile = "afrog-ca.crt"
	caKeyFile  = "afrog-ca.key"
	// caValidity 是根证书有效期。被动扫描的信任关系是长期配置，
	// 过短会迫使使用者频繁重装证书。
	caValidity = 10 * 365 * 24 * time.Hour
)

// LoadOrCreateCA 从 dir 加载根证书；不存在时生成并落盘。
func LoadOrCreateCA(dir string) (*CA, error) {
	if dir == "" {
		return nil, fmt.Errorf("proxy: ca dir is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("proxy: create ca dir: %w", err)
	}

	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	if fileExists(certPath) && fileExists(keyPath) {
		ca, err := loadCA(certPath, keyPath)
		if err == nil {
			return ca, nil
		}
		// 已存在的证书不可用时重新生成，避免整个被动链路因一次损坏而不可启动。
	}

	cert, key, err := mitm.NewAuthority("afrog", "afrog", caValidity)
	if err != nil {
		return nil, fmt.Errorf("proxy: generate ca: %w", err)
	}

	ca := &CA{Cert: cert, Key: key}
	if err := ca.save(certPath, keyPath); err != nil {
		return nil, err
	}
	return ca, nil
}

// CertPEM 返回根证书的 PEM，供使用者下载安装。
func (c *CA) CertPEM() []byte {
	if c == nil || c.Cert == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})
}

// CACertPath 返回 dir 下根证书文件的路径，供界面展示「证书装的是哪一个」。
func CACertPath(dir string) string {
	if dir == "" {
		dir = DefaultCADir()
	}
	return filepath.Join(dir, caCertFile)
}

func (c *CA) save(certPath, keyPath string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return fmt.Errorf("proxy: write ca cert: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(c.Key)})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("proxy: write ca key: %w", err)
	}
	return nil
}

func loadCA(certPath, keyPath string) (*CA, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, fmt.Errorf("proxy: invalid ca cert pem")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, fmt.Errorf("proxy: invalid ca key pem")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &CA{Cert: cert, Key: key}, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
