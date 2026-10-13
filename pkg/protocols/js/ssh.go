package js

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dop251/goja"
	"golang.org/x/crypto/ssh"
)

const defaultSSHTimeout = 10 * time.Second

// sshClientModule 是 afrog/ssh 模块暴露给 JS 的 SSH 客户端。
// 用法与 nuclei 的 nuclei/ssh 保持一致，便于迁移脚本写法。
type sshClientModule struct {
	client  *ssh.Client
	timeout time.Duration
}

func buildSSHModule(vm *goja.Runtime) (goja.Value, error) {
	obj := vm.NewObject()
	if err := obj.Set("SSHClient", func() *sshClientModule {
		return &sshClientModule{timeout: defaultSSHTimeout}
	}); err != nil {
		return nil, err
	}
	return obj, nil
}

func (c *sshClientModule) timeoutOf() time.Duration {
	if c.timeout > 0 {
		return c.timeout
	}
	return defaultSSHTimeout
}

// SetTimeout 设置连接超时（秒）。
func (c *sshClientModule) SetTimeout(sec int) {
	if sec > 0 {
		c.timeout = time.Duration(sec) * time.Second
	}
}

// ConnectSSHInfoMode 只完成 SSH 版本交换，读取服务端标识串（banner），
// 不需要认证。返回结构中的 ServerID.Raw 即形如 SSH-2.0-Serv-U_15.2.3.742。
func (c *sshClientModule) ConnectSSHInfoMode(host string, port any) (map[string]any, error) {
	p, ok := toInt(port)
	if !ok || p <= 0 {
		return nil, fmt.Errorf("ssh: invalid port")
	}
	addr := net.JoinHostPort(host, strconv.Itoa(p))

	conn, err := net.DialTimeout("tcp", addr, c.timeoutOf())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeoutOf()))

	// 主动发送客户端标识串，兼容等待客户端先发 banner 的服务端
	_, _ = conn.Write([]byte("SSH-2.0-afrog\r\n"))

	reader := bufio.NewReader(conn)
	for i := 0; i < 10; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "SSH-") {
			return map[string]any{
				"ServerID": map[string]any{"Raw": line},
				"Banner":   line,
			}, nil
		}
	}
	return nil, fmt.Errorf("ssh: no identification string received")
}

// Connect 使用用户名/密码建立 SSH 连接。
func (c *sshClientModule) Connect(host string, port any, username, password string) (bool, error) {
	p, ok := toInt(port)
	if !ok || p <= 0 {
		return false, fmt.Errorf("ssh: invalid port")
	}
	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         c.timeoutOf(),
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(p)), cfg)
	if err != nil {
		return false, err
	}
	c.client = client
	return true, nil
}

// Run 在当前连接上执行命令并返回输出。
func (c *sshClientModule) Run(cmd string) (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("ssh: no connection")
	}
	session, err := c.client.NewSession()
	if err != nil {
		return "", err
	}
	defer func() { _ = session.Close() }()

	out, err := session.Output(cmd)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Close 关闭当前连接。
func (c *sshClientModule) Close() (bool, error) {
	if c.client == nil {
		return false, nil
	}
	err := c.client.Close()
	c.client = nil
	return err == nil, err
}
