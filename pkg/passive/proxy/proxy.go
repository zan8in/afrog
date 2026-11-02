// Package proxy 提供内嵌 afrogweb 的被动流量代理。
//
// 它只做一件事：把经过代理的 HTTP/HTTPS 流量归一化成 passive.CapturedTransaction，
// 通过回调交给调度层。它不认识任何漏洞类型，新增检测能力无需改动本包。
package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/martian/v3"
	"github.com/google/martian/v3/mitm"
	"github.com/zan8in/afrog/v3/pkg/passive"
)

// Options 是代理服务的配置。
type Options struct {
	// Addr 是监听地址，如 "127.0.0.1:16869"。
	Addr string
	// CADir 是根证书存放目录，必须持久化以保证多次启动使用同一张 CA。
	CADir string
	// MaxBodyBytes 是参与检测的单条报文体上限。
	MaxBodyBytes int64
	// Upstream 是上游代理：代理转发目标请求时先经过它（企业网络常见）。
	// 为空表示直连目标。
	Upstream *url.URL
	// OnTransaction 是事务完成后的回调。回调应尽快返回，耗时逻辑交给调度层异步处理。
	OnTransaction func(*passive.CapturedTransaction)
	// OnTraffic 上报被代理层直接放过的流量（静态资源 / 方法 / 归一化失败），
	// 让界面能解释「捕获数为什么不涨」。回调必须非阻塞。
	OnTraffic func(passive.TrafficEvent)
	// OnError 上报代理自身的异常：目前只有 TLS 握手失败。
	// 客户端不信任根证书时握手会在服务端失败，这是「HTTPS 一条都抓不到」最常见的原因，
	// 必须让使用者看到，否则只能靠猜。回调必须非阻塞。
	OnError func(scope string, err error)
}

// Server 是被动流量代理服务。
type Server struct {
	opts Options
	ca   *CA
	mp   *martian.Proxy
	ln   net.Listener

	mu      sync.Mutex
	running bool
}

// New 创建一个代理服务（尚未开始监听）。
func New(opts Options) (*Server, error) {
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:16869"
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 2 << 20
	}
	if opts.CADir == "" {
		opts.CADir = DefaultCADir()
	}

	ca, err := LoadOrCreateCA(opts.CADir)
	if err != nil {
		return nil, err
	}

	cfg, err := mitm.NewConfig(ca.Cert, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("proxy: build mitm config: %w", err)
	}
	// 被动扫描的目标经常使用自签名或过期证书。mitm.Config 的 SkipTLSVerify 只影响
	// 「代理 → 客户端」这一跳，真正决定能否连上上游的是 RoundTripper，必须单独设置。
	cfg.SkipTLSVerify(true)
	cfg.SetValidity(365 * 24 * time.Hour)
	// 客户端不信任根证书时，握手在服务端就失败了，请求根本到不了检测链路。
	// 这是「HTTPS 抓不到」的头号原因，必须显式上报。
	cfg.SetHandshakeErrorCallback(func(req *http.Request, err error) {
		if opts.OnError == nil {
			return
		}
		host := ""
		if req != nil && req.URL != nil {
			host = req.URL.Host
		}
		opts.OnError("proxy", fmt.Errorf("TLS 握手失败（%s）：%w，请确认客户端已信任根证书", host, err))
	})

	mp := martian.NewProxy()
	mp.SetRoundTripper(&http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   false,
	})
	// 上游代理必须在 SetRoundTripper 之后设置：SetRoundTripper 会把 roundTripper
	// 换成新的 Transport，先设的 Proxy 字段会被覆盖掉。
	if opts.Upstream != nil {
		mp.SetDownstreamProxy(opts.Upstream)
	}
	mp.SetMITM(cfg)

	cap := &capture{onTx: opts.OnTransaction, onTraffic: opts.OnTraffic, maxBody: opts.MaxBodyBytes}
	mp.SetRequestModifier(cap)
	mp.SetResponseModifier(cap)

	return &Server{opts: opts, ca: ca, mp: mp}, nil
}

// Start 开始监听。监听失败会直接返回错误，便于上层决定是否降级。
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return nil
	}
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return fmt.Errorf("proxy: listen %s: %w", s.opts.Addr, err)
	}
	s.ln = ln
	s.running = true

	go func() {
		_ = s.mp.Serve(ln)
	}()
	return nil
}

// Stop 停止代理并关闭所有在途连接。
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return nil
	}
	s.running = false
	if s.mp != nil {
		s.mp.Close()
	}
	if s.ln != nil {
		err := s.ln.Close()
		s.ln = nil
		return err
	}
	return nil
}

// Addr 返回实际监听地址（支持 :0 随机端口场景）。
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		return s.ln.Addr().String()
	}
	return s.opts.Addr
}

// CACertPEM 返回根证书 PEM，供 Web 端下载安装。
func (s *Server) CACertPEM() []byte {
	return s.ca.CertPEM()
}

// DefaultCADir 返回默认的根证书目录。
//
// 与 afrog 的数据库、配置文件同属 ~/.config/afrog：被动代理的 CA 是「本机信任根」，
// 放在同一个受管目录里更符合使用者的直觉，也能复用该目录既有的 0700 权限约定。
func DefaultCADir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".afrog", "ca")
	}
	return filepath.Join(home, ".config", "afrog", "ca")
}
