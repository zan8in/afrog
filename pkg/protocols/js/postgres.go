package js

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/dop251/goja"
	"github.com/zan8in/afrog/v3/pkg/capability"
	"github.com/zan8in/gologger"
)

// postgresClient 是 afrog/postgres 模块暴露给 JS 的 PostgreSQL 客户端。
//
// 支持 trust / 明文 / MD5 / SCRAM-SHA-256 四种认证方式，与 lib/pq 的
// sslmode=disable 行为对齐。传输层复用 afrog/net 的客户端，因此超时、
// ctx 取消、连接兜底释放都一致。
//
//	var pg = require("afrog/postgres");
//	var c = pg.PostgresClient();
//	c.SetTimeout(3);
//	if (c.Connect(Host, Port)) {
//	  var ok = c.Login("postgres", "postgres", "postgres");
//	  c.Close();
//	}
//
// 约定与其它模块一致：方法不抛异常，失败返回零值，原因见 LastError()。
type postgresClient struct {
	state      *execState
	tc         *tcpClient
	timeoutSec int
	lastErr    error
}

func buildPostgresModule(state *execState) (goja.Value, error) {
	vm := state.vm
	obj := vm.NewObject()
	if err := obj.Set("PostgresClient", func() *postgresClient {
		return &postgresClient{state: state}
	}); err != nil {
		return nil, err
	}
	return obj, nil
}

func init() {
	registerModule(moduleDef{name: "postgres", summary: "PostgreSQL 登录（trust/明文/MD5/SCRAM 弱口令）", level: capability.Network, build: buildPostgresModule})
}

func (c *postgresClient) setErr(err error) {
	if err == nil {
		return
	}
	c.lastErr = err
	gologger.Debug().Msgf("[JS] afrog/postgres: %v", err)
}

// LastError 返回最近一次方法的错误描述；无错误时返回空串。
func (c *postgresClient) LastError() string {
	if c.lastErr == nil {
		return ""
	}
	return c.lastErr.Error()
}

// SetTimeout 设置连接与读写超时（秒）。
func (c *postgresClient) SetTimeout(sec int) {
	if sec > 0 {
		c.timeoutSec = sec
	}
}

// Connect 建立 TCP 连接，成功返回 true。认证报文由 Login 负责收发。
func (c *postgresClient) Connect(host string, port any) bool {
	tc := &tcpClient{state: c.state, readSize: defaultNetReadSize}
	if c.timeoutSec > 0 {
		tc.SetTimeout(c.timeoutSec)
	}
	if !tc.Connect(host, port) {
		c.setErr(fmt.Errorf("postgres: connect failed: %v", tc.LastError()))
		return false
	}
	c.tc = tc
	c.lastErr = nil
	return true
}

// Login 使用用户名 / 密码 / 数据库完成认证，成功返回 true。
func (c *postgresClient) Login(username, password, database string) bool {
	if c.tc == nil {
		c.setErr(fmt.Errorf("postgres: not connected"))
		return false
	}
	database = strings.TrimSpace(database)
	if database == "" {
		database = "postgres"
	}
	if err := c.sendStartup(username, database); err != nil {
		c.setErr(err)
		return false
	}
	if err := c.authFlow(username, password); err != nil {
		c.setErr(err)
		return false
	}
	c.lastErr = nil
	return true
}

// Close 关闭连接。
func (c *postgresClient) Close() bool {
	if c.tc == nil {
		return false
	}
	ok := c.tc.Close()
	c.tc = nil
	return ok
}

func (c *postgresClient) sendStartup(username, database string) error {
	var body bytes.Buffer
	body.WriteString("user\x00")
	body.WriteString(username)
	body.WriteByte(0x00)
	body.WriteString("database\x00")
	body.WriteString(database)
	body.WriteByte(0x00)
	body.WriteByte(0x00) // 参数列表结束标记

	payload := body.Bytes()
	total := 4 + 4 + len(payload)
	msg := make([]byte, 0, total)
	msg = append(msg, byte(total>>24), byte(total>>16), byte(total>>8), byte(total))
	msg = append(msg, 0x00, 0x03, 0x00, 0x00) // protocol 3.0
	msg = append(msg, payload...)

	if n := c.tc.Send(string(msg)); n == 0 {
		return fmt.Errorf("postgres: write failed: %v", c.tc.LastError())
	}
	return nil
}

// authFlow 处理服务端认证报文，直到成功（ReadyForQuery）或失败（ErrorResponse）。
func (c *postgresClient) authFlow(username, password string) error {
	var scram *pgScramState
	// 认证成功时服务端会连续下发十几条 ParameterStatus + BackendKeyData 才到
	// ReadyForQuery，这里的上限只是防止异常服务端无休止地灌报文，必须足够宽松。
	const maxAuthMessages = 256
	rounds := 0
	for {
		rounds++
		if rounds > maxAuthMessages {
			return fmt.Errorf("postgres: auth flow exceeded max rounds")
		}
		typ, payload, err := c.readMessage()
		if err != nil {
			return err
		}
		switch typ {
		case 'R': // AuthenticationRequest
			if len(payload) < 4 {
				return fmt.Errorf("postgres: short authentication request")
			}
			switch binary.BigEndian.Uint32(payload[:4]) {
			case 0: // AuthenticationOk
			case 3: // 明文密码
				if err := c.sendPassword(password); err != nil {
					return err
				}
			case 5: // MD5 密码
				if len(payload) < 8 {
					return fmt.Errorf("postgres: short md5 challenge")
				}
				if err := c.sendPassword(pgMD5Token(username, password, payload[4:8])); err != nil {
					return err
				}
			case 10: // SASL
				if !pgSupportsScram(payload[4:]) {
					return fmt.Errorf("postgres: no supported SASL mechanism")
				}
				st, serr := newPGScramState(username, password)
				if serr != nil {
					return serr
				}
				scram = st
				if err := c.sendSASLInitial(scram); err != nil {
					return err
				}
			case 11: // SASLContinue
				if scram == nil {
					return fmt.Errorf("postgres: unexpected SASL continue")
				}
				if err := scram.handleServerFirst(payload[4:]); err != nil {
					return err
				}
				if err := c.sendSASLResponse(scram.clientFinal); err != nil {
					return err
				}
			case 12: // SASLFinal
				if scram == nil {
					return fmt.Errorf("postgres: unexpected SASL final")
				}
				if err := scram.verifyServerFinal(payload[4:]); err != nil {
					return err
				}
			default:
				return fmt.Errorf("postgres: unsupported auth method %d", binary.BigEndian.Uint32(payload[:4]))
			}
		case 'E': // ErrorResponse（认证失败等）
			return fmt.Errorf("postgres: server error: %s", pgErrorMessage(payload))
		case 'Z': // ReadyForQuery
			return nil
		case 'S', 'K', 'N': // ParameterStatus / BackendKeyData / NoticeResponse
			// 认证阶段忽略
		default:
			// 其它报文不影响认证结果
		}
	}
}

// readMessage 读取一条 PostgreSQL 报文（1 字节类型 + 4 字节长度 + 载荷）。
func (c *postgresClient) readMessage() (byte, []byte, error) {
	if c.tc == nil || c.tc.reader == nil {
		return 0, nil, fmt.Errorf("postgres: not connected")
	}
	c.tc.setReadDeadline()
	var head [5]byte
	if _, err := io.ReadFull(c.tc.reader, head[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(head[1:5]))
	if n < 4 || n > 16*1024*1024 {
		return 0, nil, fmt.Errorf("postgres: invalid message length %d", n)
	}
	payload := make([]byte, n-4)
	if len(payload) > 0 {
		if _, err := io.ReadFull(c.tc.reader, payload); err != nil {
			return 0, nil, err
		}
	}
	return head[0], payload, nil
}

// sendPassword 发送 PasswordMessage（'p'）。
func (c *postgresClient) sendPassword(token string) error {
	body := append([]byte(token), 0x00)
	return c.sendTypedMessage('p', body)
}

// sendSASLInitial 发送 SASLInitialResponse（'p' + 机制名 + 初始响应）。
func (c *postgresClient) sendSASLInitial(scram *pgScramState) error {
	initial := scram.clientFirst()
	var body bytes.Buffer
	body.WriteString("SCRAM-SHA-256")
	body.WriteByte(0x00)
	lb := make([]byte, 4)
	binary.BigEndian.PutUint32(lb, uint32(len(initial)))
	body.Write(lb)
	body.WriteString(initial)
	return c.sendTypedMessage('p', body.Bytes())
}

// sendSASLResponse 发送 SCRAM 客户端的 client-final 消息（'p'）。
func (c *postgresClient) sendSASLResponse(final string) error {
	return c.sendTypedMessage('p', []byte(final))
}

func (c *postgresClient) sendTypedMessage(typ byte, body []byte) error {
	total := 4 + len(body)
	msg := make([]byte, 0, total+1)
	msg = append(msg, typ)
	msg = append(msg, byte(total>>24), byte(total>>16), byte(total>>8), byte(total))
	msg = append(msg, body...)
	if n := c.tc.Send(string(msg)); n == 0 {
		return fmt.Errorf("postgres: write failed: %v", c.tc.LastError())
	}
	return nil
}

// pgMD5Token 计算 PostgreSQL MD5 认证响应：md5(md5(password+user) + salt)。
func pgMD5Token(username, password string, salt []byte) string {
	inner := md5.Sum([]byte(password + username))
	outerInput := append([]byte(fmt.Sprintf("%x", inner)), salt...)
	outer := md5.Sum(outerInput)
	return "md5" + fmt.Sprintf("%x", outer)
}

// pgErrorMessage 从 ErrorResponse / NoticeResponse 载荷中取出 M 字段（可读消息）。
func pgErrorMessage(payload []byte) string {
	for i := 0; i < len(payload); {
		code := payload[i]
		i++
		if code == 0 {
			break
		}
		j := bytes.IndexByte(payload[i:], 0)
		if j < 0 {
			break
		}
		value := string(payload[i : i+j])
		i += j + 1
		if code == 'M' {
			return value
		}
	}
	return ""
}

// pgSupportsScram 判断服务端 SASL 机制列表中是否包含 SCRAM-SHA-256。
func pgSupportsScram(payload []byte) bool {
	for _, m := range bytes.Split(payload, []byte{0x00}) {
		if bytes.EqualFold(m, []byte("SCRAM-SHA-256")) {
			return true
		}
	}
	return false
}

// pgScramState 保存一次 SCRAM-SHA-256 交换的中间状态。
type pgScramState struct {
	username        string
	password        string
	clientNonce     string
	clientFirstBare string
	clientFinal     string
	serverSignature []byte
}

func newPGScramState(username, password string) (*pgScramState, error) {
	nonceBytes := make([]byte, 18)
	if _, err := crand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonce := base64.RawStdEncoding.EncodeToString(nonceBytes)
	escaped := strings.NewReplacer("=", "=3D", ",", "=2C").Replace(username)
	return &pgScramState{
		username:        username,
		password:        password,
		clientNonce:     nonce,
		clientFirstBare: "n=" + escaped + ",r=" + nonce,
	}, nil
}

func (s *pgScramState) clientFirst() string {
	return "n,," + s.clientFirstBare
}

// handleServerFirst 解析服务端 server-first 消息，计算 client-final 与 server 签名。
func (s *pgScramState) handleServerFirst(payload []byte) error {
	first := string(payload)
	attrs := pgScramAttrs(first)
	nonce := attrs["r"]
	saltB64 := attrs["s"]
	iterStr := attrs["i"]
	if nonce == "" || saltB64 == "" || iterStr == "" {
		return fmt.Errorf("postgres: invalid SCRAM server-first message")
	}
	if !strings.HasPrefix(nonce, s.clientNonce) {
		return fmt.Errorf("postgres: SCRAM nonce mismatch")
	}
	iter, err := strconv.Atoi(iterStr)
	if err != nil || iter <= 0 {
		return fmt.Errorf("postgres: invalid SCRAM iteration count")
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return fmt.Errorf("postgres: invalid SCRAM salt")
	}

	saltedPassword := pgPBKDF2SHA256([]byte(s.password), salt, iter, sha256.Size)
	clientKey := pgHMAC(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)

	finalNoProof := "c=biws,r=" + nonce
	authMessage := s.clientFirstBare + "," + first + "," + finalNoProof

	clientSignature := pgHMAC(storedKey[:], []byte(authMessage))
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSignature[i]
	}
	s.clientFinal = finalNoProof + ",p=" + base64.StdEncoding.EncodeToString(proof)

	serverKey := pgHMAC(saltedPassword, []byte("Server Key"))
	s.serverSignature = pgHMAC(serverKey, []byte(authMessage))
	return nil
}

// verifyServerFinal 校验服务端 server-final 中的 v 字段签名。
func (s *pgScramState) verifyServerFinal(payload []byte) error {
	attrs := pgScramAttrs(string(payload))
	value := attrs["v"]
	if value == "" {
		return fmt.Errorf("postgres: missing SCRAM server signature")
	}
	sig, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("postgres: invalid SCRAM server signature")
	}
	if !hmac.Equal(sig, s.serverSignature) {
		return fmt.Errorf("postgres: SCRAM server signature mismatch")
	}
	return nil
}

// pgScramAttrs 解析 SCRAM 的 k=v 列表（只在第一个 '=' 处切分，base64 里也会出现 '='）。
func pgScramAttrs(msg string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(msg, ",") {
		if part == "" {
			continue
		}
		idx := strings.IndexByte(part, '=')
		if idx < 0 {
			continue
		}
		out[part[:idx]] = part[idx+1:]
	}
	return out
}

func pgHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// pgPBKDF2SHA256 实现 PBKDF2-HMAC-SHA256，避免引入额外依赖。
func pgPBKDF2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	blocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, blocks*hashLen)
	var buf [4]byte
	for block := 1; block <= blocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf[:], uint32(block))
		prf.Write(buf[:])
		u := prf.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
