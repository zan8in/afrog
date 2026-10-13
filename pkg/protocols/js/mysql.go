package js

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/dop251/goja"
	"github.com/zan8in/afrog/v3/pkg/capability"
	"github.com/zan8in/gologger"
)

// MySQL 能力标志（握手响应需要）。
const (
	mysqlClientLongPassword     uint32 = 0x00000001
	mysqlClientLongFlag         uint32 = 0x00000004
	mysqlClientProtocol41       uint32 = 0x00000200
	mysqlClientTransactions     uint32 = 0x00002000
	mysqlClientSecureConnection uint32 = 0x00008000
	mysqlClientMultiResults     uint32 = 0x00020000
	mysqlClientPluginAuth       uint32 = 0x00080000
)

// mysqlHandshakeInfo 是服务端握手包解析结果。
type mysqlHandshakeInfo struct {
	Version      string
	ThreadID     uint32
	Charset      byte
	Capabilities uint32
	AuthPlugin   string
	Salt         []byte
}

// mysqlClient 是 afrog/mysql 模块暴露给 JS 的 MySQL 客户端。
//
// 约定与其它模块一致：方法不抛异常，失败返回零值，原因见 LastError()。
// 传输层复用 afrog/net 的客户端，因此超时、ctx 取消、连接兜底释放都一致。
//
//	var mysql = require("afrog/mysql");
//	var c = mysql.MySQLClient();
//	if (c.Connect(Host, Port)) {
//	  var hs = c.Handshake();      // 认证前即可拿到服务端版本
//	  ExportAs("version", hs.Version);
//	  var ok = c.Login("root", "root");
//	  c.Close();
//	}
type mysqlClient struct {
	state      *execState
	tc         *tcpClient
	hs         *mysqlHandshakeInfo
	timeoutSec int
	lastErr    error
}

func buildMySQLModule(state *execState) (goja.Value, error) {
	vm := state.vm
	obj := vm.NewObject()
	if err := obj.Set("MySQLClient", func() *mysqlClient {
		return &mysqlClient{state: state}
	}); err != nil {
		return nil, err
	}
	return obj, nil
}

func init() {
	registerModule(moduleDef{name: "mysql", summary: "MySQL 握手 / 登录（版本探测、弱口令）", level: capability.Network, build: buildMySQLModule})
}

func (c *mysqlClient) context() context.Context {
	if c.state != nil && c.state.ctx != nil {
		return c.state.ctx
	}
	return context.Background()
}

func (c *mysqlClient) setErr(err error) {
	if err == nil {
		return
	}
	c.lastErr = err
	gologger.Debug().Msgf("[JS] afrog/mysql: %v", err)
}

// LastError 返回最近一次方法的错误描述；无错误时返回空串。
func (c *mysqlClient) LastError() string {
	if c.lastErr == nil {
		return ""
	}
	return c.lastErr.Error()
}

// SetTimeout 设置连接与读写超时（秒）。
func (c *mysqlClient) SetTimeout(sec int) {
	if sec > 0 {
		c.timeoutSec = sec
	}
}

// Connect 建立连接并读取服务端握手包，成功返回 true。
func (c *mysqlClient) Connect(host string, port any) bool {
	tc := &tcpClient{state: c.state, readSize: defaultNetReadSize}
	if c.timeoutSec > 0 {
		tc.SetTimeout(c.timeoutSec)
	}
	if !tc.Connect(host, port) {
		c.setErr(fmt.Errorf("mysql: connect failed: %v", tc.LastError()))
		return false
	}
	c.tc = tc

	raw, err := c.readPacket()
	if err != nil {
		c.setErr(err)
		_ = tc.Close()
		c.tc = nil
		return false
	}
	hs, err := parseMySQLHandshake(raw)
	if err != nil {
		c.setErr(err)
		_ = tc.Close()
		c.tc = nil
		return false
	}
	c.hs = hs
	c.lastErr = nil
	return true
}

// Handshake 返回握手信息（认证前即可用，含服务端版本）。
func (c *mysqlClient) Handshake() map[string]any {
	if c.hs == nil {
		return map[string]any{
			"Version": "", "ThreadID": uint32(0), "Charset": 0,
			"Capabilities": uint32(0), "AuthPlugin": "", "Salt": "",
		}
	}
	return map[string]any{
		"Version":      c.hs.Version,
		"ThreadID":     c.hs.ThreadID,
		"Charset":      int(c.hs.Charset),
		"Capabilities": c.hs.Capabilities,
		"AuthPlugin":   c.hs.AuthPlugin,
		"Salt":         string(c.hs.Salt),
	}
}

// Login 使用用户名 / 密码完成认证，成功返回 true。
func (c *mysqlClient) Login(username, password string) bool {
	if c.tc == nil || c.hs == nil {
		c.setErr(fmt.Errorf("mysql: not connected"))
		return false
	}
	pkt, err := buildMySQLHandshakeResponse(username, password, c.hs, 1)
	if err != nil {
		c.setErr(err)
		return false
	}
	if n := c.tc.Send(string(pkt)); n == 0 {
		c.setErr(fmt.Errorf("mysql: write failed: %v", c.tc.LastError()))
		return false
	}
	raw, err := c.readPacket()
	if err != nil {
		c.setErr(err)
		return false
	}
	if !c.authFlow(raw, username, password) {
		return false
	}
	c.lastErr = nil
	return true
}

// Close 关闭连接。
func (c *mysqlClient) Close() bool {
	if c.tc == nil {
		return false
	}
	ok := c.tc.Close()
	c.tc = nil
	c.hs = nil
	return ok
}

// Query 发送一条 SQL（COM_QUERY）并解析响应。
// 返回对象包含：Columns、Rows、AffectedRows、LastInsertID、ErrNo、ErrMsg。
// 失败（含服务端返回错误）时 Rows 为空，原因见 ErrMsg / LastError()。
func (c *mysqlClient) Query(sql string) map[string]any {
	res := map[string]any{
		"Columns":      []any{},
		"Rows":         []any{},
		"AffectedRows": uint64(0),
		"LastInsertID": uint64(0),
		"ErrNo":        0,
		"ErrMsg":       "",
	}
	if c.tc == nil {
		c.setErr(fmt.Errorf("mysql: not connected"))
		return res
	}

	payload := append([]byte{0x03}, []byte(sql)...) // 0x03 = COM_QUERY
	if n := c.tc.Send(string(mysqlBuildPacket(payload, 0))); n == 0 {
		c.setErr(fmt.Errorf("mysql: write failed: %v", c.tc.LastError()))
		return res
	}
	return c.readQueryResult(res)
}

func (c *mysqlClient) readQueryResult(res map[string]any) map[string]any {
	raw, err := c.readPacket()
	if err != nil {
		c.setErr(err)
		return res
	}
	payload, _, err := mysqlPacketPayload(raw)
	if err != nil {
		c.setErr(err)
		return res
	}
	if len(payload) == 0 {
		c.setErr(fmt.Errorf("mysql: empty query response"))
		return res
	}

	switch payload[0] {
	case 0x00: // OK（非结果集语句）
		affected, lastID, perr := parseMySQLOKPacket(payload)
		if perr != nil {
			c.setErr(perr)
			return res
		}
		res["AffectedRows"] = affected
		res["LastInsertID"] = lastID
		c.lastErr = nil
		return res
	case 0xff: // ERR
		code, msg := parseMySQLErrPacket(payload)
		c.setErr(fmt.Errorf("mysql: query error %d: %s", code, msg))
		res["ErrNo"] = code
		res["ErrMsg"] = msg
		return res
	}

	// 结果集：列数 + 列定义 + EOF + 行 + EOF
	colCount, _, ok := readLenEncInt(payload, 0)
	if !ok || colCount == 0 {
		c.setErr(fmt.Errorf("mysql: invalid column count"))
		return res
	}

	cols := make([]any, 0, colCount)
	for i := uint64(0); i < colCount; i++ {
		raw, err := c.readPacket()
		if err != nil {
			c.setErr(err)
			return res
		}
		pl, _, err := mysqlPacketPayload(raw)
		if err != nil {
			c.setErr(err)
			return res
		}
		cols = append(cols, parseMySQLColumnName(pl))
	}
	res["Columns"] = cols

	if err := c.consumeEOF(); err != nil {
		c.setErr(err)
		return res
	}

	rows := make([]any, 0, 8)
	for {
		raw, err := c.readPacket()
		if err != nil {
			c.setErr(err)
			return res
		}
		pl, _, err := mysqlPacketPayload(raw)
		if err != nil {
			c.setErr(err)
			return res
		}
		if isMySQLEOFPacket(pl) {
			break
		}
		row := make([]any, 0, len(cols))
		pos := 0
		for i := 0; i < len(cols); i++ {
			v, next, isNull, ok := readLenEncString(pl, pos)
			if !ok {
				c.setErr(fmt.Errorf("mysql: malformed row packet"))
				return res
			}
			pos = next
			if isNull {
				row = append(row, "")
			} else {
				row = append(row, v)
			}
		}
		rows = append(rows, row)
	}
	res["Rows"] = rows
	c.lastErr = nil
	return res
}

func (c *mysqlClient) consumeEOF() error {
	raw, err := c.readPacket()
	if err != nil {
		return err
	}
	pl, _, err := mysqlPacketPayload(raw)
	if err != nil {
		return err
	}
	if !isMySQLEOFPacket(pl) {
		return fmt.Errorf("mysql: expected EOF packet after columns")
	}
	return nil
}

// readPacket 读取一个完整的 MySQL 包（含 4 字节包头）。
func (c *mysqlClient) readPacket() ([]byte, error) {
	if c.tc == nil || c.tc.reader == nil {
		return nil, fmt.Errorf("mysql: not connected")
	}
	c.tc.setReadDeadline()
	header := make([]byte, 4)
	if _, err := io.ReadFull(c.tc.reader, header); err != nil {
		return nil, err
	}
	n := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	if n < 0 || n > 16*1024*1024 {
		return nil, fmt.Errorf("mysql: invalid packet length %d", n)
	}
	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(c.tc.reader, payload); err != nil {
			return nil, err
		}
	}
	return append(header, payload...), nil
}

// authFlow 处理握手响应之后的认证交互，直到成功或失败。
func (c *mysqlClient) authFlow(firstRespRaw []byte, username, password string) bool {
	raw := firstRespRaw
	for i := 0; i < 5; i++ {
		payload, seq, err := mysqlPacketPayload(raw)
		if err != nil {
			c.setErr(err)
			return false
		}
		if len(payload) == 0 {
			c.setErr(fmt.Errorf("mysql: empty auth response"))
			return false
		}

		switch payload[0] {
		case 0x00: // OK
			return true
		case 0xff: // ERR
			code, msg := parseMySQLErrPacket(payload)
			c.setErr(fmt.Errorf("mysql: auth rejected %d: %s", code, msg))
			return false
		case 0xfe: // Auth switch request
			plugin, scramble := parseMySQLAuthSwitch(payload)
			if strings.TrimSpace(plugin) == "" {
				plugin = c.hs.AuthPlugin
			}
			if len(scramble) == 0 {
				scramble = c.hs.Salt
			}
			token, terr := mysqlBuildAuthToken(plugin, password, scramble)
			if terr != nil {
				c.setErr(terr)
				return false
			}
			if n := c.tc.Send(string(mysqlBuildPacket(token, seq+1))); n == 0 {
				c.setErr(fmt.Errorf("mysql: write failed: %v", c.tc.LastError()))
				return false
			}
			raw, err = c.readPacket()
			if err != nil {
				c.setErr(err)
				return false
			}
		case 0x01: // Auth more data（如 caching_sha2 的 fast-auth 结果）
			if len(payload) >= 2 && payload[1] == 0x03 {
				raw, err = c.readPacket()
				if err != nil {
					c.setErr(err)
					return false
				}
				continue
			}
			c.setErr(fmt.Errorf("mysql: unsupported auth continuation"))
			return false
		default:
			c.setErr(fmt.Errorf("mysql: unexpected auth response 0x%02x", payload[0]))
			return false
		}
	}
	c.setErr(fmt.Errorf("mysql: auth flow exceeded max rounds"))
	return false
}

func mysqlPacketPayload(raw []byte) ([]byte, byte, error) {
	if len(raw) < 4 {
		return nil, 0, fmt.Errorf("mysql: short packet")
	}
	n := int(uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16)
	seq := raw[3]
	if n < 0 || len(raw) < 4+n {
		return nil, 0, fmt.Errorf("mysql: incomplete packet")
	}
	return raw[4 : 4+n], seq, nil
}

func mysqlBuildPacket(payload []byte, seq byte) []byte {
	l := len(payload)
	out := make([]byte, 4+l)
	out[0] = byte(l)
	out[1] = byte(l >> 8)
	out[2] = byte(l >> 16)
	out[3] = seq
	copy(out[4:], payload)
	return out
}

// parseMySQLErrPacket 解析 ERR 包（0xff + 2 字节错误码 + '#' + 5 字节 sqlstate + 消息）。
func parseMySQLErrPacket(payload []byte) (int, string) {
	if len(payload) < 3 {
		return 0, ""
	}
	code := int(binary.LittleEndian.Uint16(payload[1:3]))
	msg := payload[3:]
	if len(msg) > 0 && msg[0] == '#' && len(msg) >= 6 {
		msg = msg[6:]
	}
	return code, strings.TrimSpace(string(msg))
}

// parseMySQLOKPacket 解析 OK 包（0x00 + lenenc 影响行数 + lenenc 自增 ID + ...）。
func parseMySQLOKPacket(payload []byte) (uint64, uint64, error) {
	if len(payload) < 1 || payload[0] != 0x00 {
		return 0, 0, fmt.Errorf("mysql: not an OK packet")
	}
	affected, next, ok := readLenEncInt(payload, 1)
	if !ok {
		return 0, 0, fmt.Errorf("mysql: invalid OK packet")
	}
	lastID, _, ok := readLenEncInt(payload, next)
	if !ok {
		return 0, 0, fmt.Errorf("mysql: invalid OK packet")
	}
	return affected, lastID, nil
}

// readLenEncInt 读取长度编码整数，返回 (值, 新位置, 是否成功)。
func readLenEncInt(b []byte, pos int) (uint64, int, bool) {
	if pos < 0 || pos >= len(b) {
		return 0, pos, false
	}
	switch first := b[pos]; {
	case first < 0xfb:
		return uint64(first), pos + 1, true
	case first == 0xfc:
		if pos+3 > len(b) {
			return 0, pos, false
		}
		return uint64(binary.LittleEndian.Uint16(b[pos+1 : pos+3])), pos + 3, true
	case first == 0xfd:
		if pos+4 > len(b) {
			return 0, pos, false
		}
		v := uint64(b[pos+1]) | uint64(b[pos+2])<<8 | uint64(b[pos+3])<<16
		return v, pos + 4, true
	case first == 0xfe:
		if pos+9 > len(b) {
			return 0, pos, false
		}
		return binary.LittleEndian.Uint64(b[pos+1 : pos+9]), pos + 9, true
	}
	return 0, pos, false // 0xfb (NULL) / 0xff 不属于长度编码整数
}

// readLenEncString 读取长度编码字符串，返回 (值, 新位置, 是否 NULL, 是否成功)。
func readLenEncString(b []byte, pos int) (string, int, bool, bool) {
	if pos < 0 || pos >= len(b) {
		return "", pos, false, false
	}
	if b[pos] == 0xfb { // NULL
		return "", pos + 1, true, true
	}
	n, next, ok := readLenEncInt(b, pos)
	if !ok || next+int(n) > len(b) {
		return "", pos, false, false
	}
	return string(b[next : next+int(n)]), next + int(n), false, true
}

// isMySQLEOFPacket 判断是否为 EOF 包（0xfe 且长度 < 9，用于区分长度编码数据）。
func isMySQLEOFPacket(payload []byte) bool {
	return len(payload) > 0 && payload[0] == 0xfe && len(payload) < 9
}

// parseMySQLColumnName 从列定义包中取出列名（第 5 个长度编码字符串）。
func parseMySQLColumnName(payload []byte) string {
	pos := 0
	for i := 0; i < 5; i++ { // catalog, schema, table, org_table, name
		v, next, _, ok := readLenEncString(payload, pos)
		if !ok {
			return ""
		}
		if i == 4 {
			return v
		}
		pos = next
	}
	return ""
}

func readNullTerm(b []byte, start int) (string, int, bool) {
	if start < 0 || start >= len(b) {
		return "", start, false
	}
	idx := bytes.IndexByte(b[start:], 0x00)
	if idx < 0 {
		return "", start, false
	}
	end := start + idx
	return string(b[start:end]), end + 1, true
}

func parseMySQLHandshake(raw []byte) (*mysqlHandshakeInfo, error) {
	payload, _, err := mysqlPacketPayload(raw)
	if err != nil {
		return nil, err
	}
	if len(payload) < 1 {
		return nil, fmt.Errorf("mysql: empty handshake payload")
	}

	i := 1 // protocol version
	version, next, ok := readNullTerm(payload, i)
	if !ok {
		return nil, fmt.Errorf("mysql: invalid server version")
	}
	i = next
	if i+4 > len(payload) {
		return nil, fmt.Errorf("mysql: invalid connection id")
	}
	threadID := binary.LittleEndian.Uint32(payload[i : i+4])
	i += 4
	if i+8 > len(payload) {
		return nil, fmt.Errorf("mysql: invalid auth plugin data part1")
	}
	auth1 := payload[i : i+8]
	i += 8
	if i+1 > len(payload) {
		return nil, fmt.Errorf("mysql: invalid filler")
	}
	i++
	if i+2 > len(payload) {
		return nil, fmt.Errorf("mysql: invalid capability lower")
	}
	capLow := binary.LittleEndian.Uint16(payload[i : i+2])
	i += 2
	if i+1 > len(payload) {
		return nil, fmt.Errorf("mysql: invalid charset")
	}
	charset := payload[i]
	i++
	if i+2 > len(payload) {
		return nil, fmt.Errorf("mysql: invalid status flags")
	}
	i += 2
	if i+2 > len(payload) {
		return nil, fmt.Errorf("mysql: invalid capability upper")
	}
	capHigh := binary.LittleEndian.Uint16(payload[i : i+2])
	i += 2
	serverCaps := uint32(capLow) | uint32(capHigh)<<16
	if i+1 > len(payload) {
		return nil, fmt.Errorf("mysql: invalid auth data length")
	}
	authDataLen := int(payload[i])
	i++
	if i+10 > len(payload) {
		return nil, fmt.Errorf("mysql: invalid reserved bytes")
	}
	i += 10

	auth2Len := 13
	if authDataLen > 8 {
		if v := authDataLen - 8; v > auth2Len {
			auth2Len = v
		}
	}
	if i+auth2Len > len(payload) {
		auth2Len = len(payload) - i
		if auth2Len < 0 {
			auth2Len = 0
		}
	}
	salt := append([]byte{}, auth1...)
	salt = append(salt, payload[i:i+auth2Len]...)
	i += auth2Len
	salt = bytes.TrimRight(salt, "\x00")
	if len(salt) > 20 {
		salt = salt[:20]
	}

	plugin := ""
	if (serverCaps&mysqlClientPluginAuth) != 0 && i < len(payload) {
		if payload[i] == 0x00 {
			i++
		}
		if s, _, ok := readNullTerm(payload, i); ok {
			plugin = s
		}
	}

	return &mysqlHandshakeInfo{
		Version:      version,
		ThreadID:     threadID,
		Charset:      charset,
		Capabilities: serverCaps,
		AuthPlugin:   plugin,
		Salt:         salt,
	}, nil
}

func buildMySQLHandshakeResponse(username, password string, hs *mysqlHandshakeInfo, seq byte) ([]byte, error) {
	clientCaps := mysqlClientLongPassword | mysqlClientLongFlag | mysqlClientProtocol41 |
		mysqlClientSecureConnection | mysqlClientMultiResults
	if hs.Capabilities&mysqlClientTransactions != 0 {
		clientCaps |= mysqlClientTransactions
	}
	plugin := strings.TrimSpace(hs.AuthPlugin)
	if plugin == "" {
		plugin = "mysql_native_password"
	}
	if hs.Capabilities&mysqlClientPluginAuth != 0 {
		clientCaps |= mysqlClientPluginAuth
	}

	token, err := mysqlBuildAuthToken(plugin, password, hs.Salt)
	if err != nil {
		return nil, err
	}

	charset := hs.Charset
	if charset == 0 {
		charset = 33
	}

	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.LittleEndian, clientCaps)
	_ = binary.Write(&payload, binary.LittleEndian, uint32(0))
	_ = payload.WriteByte(charset)
	_, _ = payload.Write(make([]byte, 23))
	_, _ = payload.WriteString(username)
	_ = payload.WriteByte(0x00)
	_ = payload.WriteByte(byte(len(token)))
	_, _ = payload.Write(token)
	if clientCaps&mysqlClientPluginAuth != 0 {
		_, _ = payload.WriteString(plugin)
		_ = payload.WriteByte(0x00)
	}
	return mysqlBuildPacket(payload.Bytes(), seq), nil
}

func mysqlBuildAuthToken(plugin, password string, salt []byte) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(plugin)) {
	case "mysql_native_password", "":
		return mysqlNativePasswordToken(password, salt), nil
	case "caching_sha2_password":
		return mysqlCachingSha2Token(password, salt), nil
	default:
		return nil, fmt.Errorf("mysql: unsupported auth plugin %q", plugin)
	}
}

func mysqlNativePasswordToken(password string, salt []byte) []byte {
	if password == "" {
		return []byte{}
	}
	s1 := sha1.Sum([]byte(password))
	s2 := sha1.Sum(s1[:])
	h := sha1.New()
	_, _ = h.Write(salt)
	_, _ = h.Write(s2[:])
	s3 := h.Sum(nil)
	out := make([]byte, len(s1))
	for i := range s1 {
		out[i] = s3[i] ^ s1[i]
	}
	return out
}

func mysqlCachingSha2Token(password string, salt []byte) []byte {
	if password == "" {
		return []byte{}
	}
	s1 := sha256.Sum256([]byte(password))
	s2 := sha256.Sum256(s1[:])
	h := sha256.New()
	_, _ = h.Write(s2[:])
	_, _ = h.Write(salt)
	s3 := h.Sum(nil)
	out := make([]byte, len(s1))
	for i := range s1 {
		out[i] = s3[i] ^ s1[i]
	}
	return out
}

func parseMySQLAuthSwitch(payload []byte) (string, []byte) {
	if len(payload) < 2 {
		return "", nil
	}
	plugin, next, ok := readNullTerm(payload, 1)
	if !ok {
		return "", nil
	}
	salt := append([]byte{}, payload[next:]...)
	salt = bytes.TrimRight(salt, "\x00")
	if len(salt) > 20 {
		salt = salt[:20]
	}
	return plugin, salt
}
