package js

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dop251/goja"
	"github.com/zan8in/afrog/v3/pkg/capability"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/gologger"
	"golang.org/x/crypto/ssh"
)

// sshBaseTimeout 是 SSH 模块的读写超时基准，实际取值与 afrog 全局 -timeout 取较小者。
const sshBaseTimeout = 6 * time.Second

// sshClientModule 是 afrog/ssh 模块暴露给 JS 的 SSH 客户端。
//
// 约定与 afrog/net 一致：模块方法不抛异常，失败返回零值，原因见 LastError()。
type sshClientModule struct {
	state   *execState
	client  *ssh.Client
	timeout time.Duration
	lastErr error
}

func buildSSHModule(state *execState) (goja.Value, error) {
	vm := state.vm
	obj := vm.NewObject()
	if err := obj.Set("SSHClient", func() *sshClientModule {
		return &sshClientModule{state: state}
	}); err != nil {
		return nil, err
	}
	return obj, nil
}

func (c *sshClientModule) context() context.Context {
	if c.state != nil && c.state.ctx != nil {
		return c.state.ctx
	}
	return context.Background()
}

func (c *sshClientModule) setErr(err error) {
	if err == nil {
		return
	}
	c.lastErr = err
	gologger.Debug().Msgf("[JS] afrog/ssh: %v", err)
}

// LastError 返回最近一次方法的错误描述；无错误时返回空串。
func (c *sshClientModule) LastError() string {
	if c.lastErr == nil {
		return ""
	}
	return c.lastErr.Error()
}

func (c *sshClientModule) timeoutOf() time.Duration {
	if c.timeout > 0 {
		return c.timeout
	}
	return minTimeout(sshBaseTimeout)
}

// deadline 返回本次读写应使用的截止时间：取模块超时与 ctx 截止时间中较早者。
func (c *sshClientModule) deadline() time.Time {
	d := time.Now().Add(c.timeoutOf())
	if dl, ok := c.context().Deadline(); ok && dl.Before(d) {
		d = dl
	}
	return d
}

// SetTimeout 设置连接超时（秒）。
func (c *sshClientModule) SetTimeout(sec int) {
	if sec > 0 {
		c.timeout = time.Duration(sec) * time.Second
	}
}

// watchConn 在 ctx 取消时把连接 deadline 归零，中断阻塞中的读取；返回停止函数。
func (c *sshClientModule) watchConn(conn net.Conn) func() {
	ctx := c.context()
	if ctx.Done() == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()
	return func() { close(done) }
}

// closeClient 释放底层 SSH 连接，可重复调用。
func (c *sshClientModule) closeClient() {
	if c.client == nil {
		return
	}
	_ = c.client.Close()
	c.client = nil
}

// ConnectSSHInfoMode 只完成 SSH 版本交换，读取服务端标识串（banner），不需要认证。
// 返回对象中的 ServerID.Raw 形如 SSH-2.0-Serv-U_15.2.3.742；失败时字段为空串。
func (c *sshClientModule) ConnectSSHInfoMode(host string, port any) map[string]any {
	empty := map[string]any{"ServerID": map[string]any{"Raw": ""}, "Banner": ""}

	p, ok := toInt(port)
	if !ok || p <= 0 {
		c.setErr(fmt.Errorf("ssh: invalid port"))
		return empty
	}
	host = strings.TrimSpace(host)
	if host == "" {
		c.setErr(fmt.Errorf("ssh: empty host"))
		return empty
	}

	ctx := c.context()
	if err := retryhttpclient.WaitHostPort(ctx, host, strconv.Itoa(p)); err != nil {
		c.setErr(err)
		return empty
	}

	addr := net.JoinHostPort(host, strconv.Itoa(p))
	conn, err := (&net.Dialer{Timeout: c.timeoutOf()}).DialContext(ctx, "tcp", addr)
	if err != nil {
		c.setErr(err)
		return empty
	}
	defer conn.Close()

	_ = conn.SetDeadline(c.deadline())
	stop := c.watchConn(conn)
	defer stop()

	// 主动发送客户端标识串，兼容等待客户端先发 banner 的服务端
	_, _ = conn.Write([]byte("SSH-2.0-afrog\r\n"))

	reader := bufio.NewReader(conn)
	for i := 0; i < 10; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			c.setErr(err)
			return empty
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "SSH-") {
			return map[string]any{
				"ServerID": map[string]any{"Raw": line},
				"Banner":   line,
			}
		}
	}
	c.setErr(fmt.Errorf("ssh: no identification string received"))
	return empty
}

// Connect 使用用户名/密码建立 SSH 连接，成功返回 true。
func (c *sshClientModule) Connect(host string, port any, username, password string) bool {
	p, ok := toInt(port)
	if !ok || p <= 0 {
		c.setErr(fmt.Errorf("ssh: invalid port"))
		return false
	}
	host = strings.TrimSpace(host)
	if host == "" {
		c.setErr(fmt.Errorf("ssh: empty host"))
		return false
	}

	ctx := c.context()
	if err := retryhttpclient.WaitHostPort(ctx, host, strconv.Itoa(p)); err != nil {
		c.setErr(err)
		return false
	}

	addr := net.JoinHostPort(host, strconv.Itoa(p))
	conn, err := (&net.Dialer{Timeout: c.timeoutOf()}).DialContext(ctx, "tcp", addr)
	if err != nil {
		c.setErr(err)
		return false
	}

	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         c.timeoutOf(),
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		c.setErr(err)
		return false
	}
	c.client = ssh.NewClient(sshConn, chans, reqs)
	c.lastErr = nil
	if c.state != nil {
		// 脚本若忘记 Close，由 Execute 结束时兜底释放
		c.state.track(c, c.closeClient)
	}
	return true
}

// Run 在当前连接上执行命令并返回输出；失败返回空串。
func (c *sshClientModule) Run(cmd string) string {
	if c.client == nil {
		c.setErr(fmt.Errorf("ssh: no connection"))
		return ""
	}
	session, err := c.client.NewSession()
	if err != nil {
		c.setErr(err)
		return ""
	}
	defer func() { _ = session.Close() }()

	out, err := session.Output(cmd)
	if err != nil {
		c.setErr(err)
		return ""
	}
	return string(out)
}

// Close 关闭当前连接。
func (c *sshClientModule) Close() bool {
	if c.client == nil {
		return false
	}
	c.closeClient()
	if c.state != nil {
		c.state.untrack(c)
	}
	return true
}

func init() {
	registerModule(moduleDef{name: "ssh", summary: "SSH 交互（banner、认证、执行命令）", level: capability.Network, build: buildSSHModule})
}
