package portscan

import (
	"crypto/tls"
	"net"
	"time"
)

const (
	// probeMinBannerWait 是等待服务端主动吐出 banner 的最短窗口。
	probeMinBannerWait = 200 * time.Millisecond
	// probeMaxBannerWait 是该窗口的上限，避免大超时配置下每个开放端口都等很久。
	probeMaxBannerWait = time.Second
	// probeIdleWait 是已经收到数据后，继续等待后续分片的空闲窗口。
	probeIdleWait = 100 * time.Millisecond
	// probeMaxBytes 是单条探针最多读取的字节数。
	probeMaxBytes = 8192
)

// Grabber 在一条已建立的连接上执行探针并给出识别结果。
//
// 两阶段语义：
//   - 被动阶段（默认）：只读，等待服务端主动吐 banner；TLS 端口会先做一次握手，
//     因为不握手就无法观察 443/8443 这类只讲 TLS 的服务。
//   - 主动阶段（需显式开启）：发送应用层 payload（GET /、PING、BSON 查询……）激发响应。
//
// 是否做 TLS 握手完全由端口先验（ports.yaml 的 tls 标记）决定，因此不会对普通端口
// 产生多余往返。
type Grabber struct {
	engine  *Fingerprinter
	timeout time.Duration
	active  bool
}

// NewGrabber 创建抓取器，active 为 true 时启用主动探针。
func NewGrabber(engine *Fingerprinter, timeout time.Duration, active bool) *Grabber {
	if timeout <= 0 {
		timeout = time.Second
	}
	return &Grabber{engine: engine, timeout: timeout, active: active}
}

// Grab 在连接上完成识别。连接由调用方负责关闭。
func (g *Grabber) Grab(conn net.Conn, host string, port int) *ServiceInfo {
	s := &probeSession{link: conn, timeout: g.timeout}
	if g.engine.TLSPort(port) {
		s.upgradeTLS(host)
	}

	obs := make([]Observation, 0, 6)
	for _, p := range g.engine.Probes(port, ProbeModePassive) {
		if p.TLS != s.tlsActive() {
			continue
		}
		obs = append(obs, s.execute(p))
	}
	info := g.engine.Identify(port, obs)

	// 主动探针只在还没有拿到明确结论时才发，避免对已识别的服务做无谓的往返。
	if !g.active || info.Confidence >= ConfidenceCertain {
		return info
	}
	for _, p := range g.engine.Probes(port, ProbeModeActive) {
		if p.TLS != s.tlsActive() {
			continue
		}
		obs = append(obs, s.execute(p))
		if g.engine.Identify(port, obs).Confidence >= ConfidenceCertain {
			break
		}
	}
	return g.engine.Identify(port, obs)
}

// probeSession 是一条连接上的探针执行上下文，TLS 握手成功后读写都走 TLS 连接。
type probeSession struct {
	link    net.Conn
	timeout time.Duration
}

func (s *probeSession) tlsActive() bool {
	_, ok := s.link.(*tls.Conn)
	return ok
}

// upgradeTLS 尝试把连接升级成 TLS；握手失败则保持明文，让后续明文探针继续工作
// （例如 8443 上其实跑着明文 HTTP 的情况）。
func (s *probeSession) upgradeTLS(host string) {
	cfg := &tls.Config{InsecureSkipVerify: true}
	if host != "" && net.ParseIP(host) == nil {
		cfg.ServerName = host
	}
	tc := tls.Client(s.link, cfg)
	_ = tc.SetDeadline(time.Now().Add(s.timeout))
	if err := tc.Handshake(); err != nil {
		return
	}
	_ = tc.SetDeadline(time.Time{})
	s.link = tc
}

func (s *probeSession) execute(p *Probe) Observation {
	o := Observation{ProbeID: p.ID, TLS: s.tlsActive()}
	if len(p.payload) > 0 {
		_ = s.link.SetWriteDeadline(time.Now().Add(s.timeout))
		if _, err := s.link.Write(p.payload); err != nil {
			return o
		}
	}

	wait := s.bannerWait()
	if len(p.payload) > 0 {
		// 已经主动发问，给服务端完整的超时预算来回答。
		wait = s.timeout
	}
	o.Data = s.read(wait)
	return o
}

// bannerWait 决定被动等待 banner 的窗口：随超时缩放，但限制在合理区间内，
// 免得每个开放端口都白等一整个超时。
func (s *probeSession) bannerWait() time.Duration {
	wait := s.timeout / 4
	if wait < probeMinBannerWait {
		wait = probeMinBannerWait
	}
	if wait > probeMaxBannerWait {
		wait = probeMaxBannerWait
	}
	return wait
}

// read 读取响应：首轮用 wait 作为预算，一旦读到数据就把预算收缩成空闲窗口，
// 这样既不会漏掉返回较慢的服务，也不会为无声的服务等满整个超时。
func (s *probeSession) read(wait time.Duration) []byte {
	buf := make([]byte, 0, 1024)
	chunk := make([]byte, 1024)
	deadline := time.Now().Add(wait)
	for len(buf) < probeMaxBytes {
		_ = s.link.SetReadDeadline(deadline)
		n, err := s.link.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			deadline = time.Now().Add(probeIdleWait)
		}
		if err != nil {
			break
		}
	}
	return buf
}
