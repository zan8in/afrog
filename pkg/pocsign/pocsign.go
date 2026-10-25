// Package pocsign 实现 PoC 模板的 ed25519 签名与验签。
//
// 签名以注释行的形式追加在 PoC 文件末尾，不参与 YAML 解析：
//
//	# digest: <base64(ed25519 signature)>
//
// 设计取舍（与 nuclei 对齐但更轻量）：
//   - 只对"携带代码/特权能力"的 PoC 强制签名，纯声明式 PoC 不参与；
//   - 默认宽松：有签名则验，验不过只告警不拦截；需要时可开启严格模式；
//   - 单一算法 ed25519，复用 afrog 现有 curated 验签的心智与依赖，
//     不引入 x509 证书体系。
package pocsign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/utils"
)

// SignaturePattern 是签名行的前缀。签名行必须是文件最后一行。
const SignaturePattern = "# digest: "

// ErrNoSignature 表示内容中不含签名行。
var ErrNoSignature = errors.New("pocsign: no signature found")

// EnvTrustedPubKey 允许通过环境变量追加一个受信任公钥（base64），
// 便于 CI 或企业内部分发自带 PoC 时注入信任锚。
// 命名风格与 curated 的 AFROG_CURATED_MANIFEST_PUBKEY_B64 保持一致。
const EnvTrustedPubKey = "AFROG_POC_PUBKEY_B64"

// EnvSigningKeyB64 允许通过环境变量提供一个 base64 编码的 ed25519 私钥，
// 作为签名密钥使用。发布流水线用它注入官方私钥来签名官方 PoC；设置后不再
// 读写用户密钥目录，也不会生成新密钥对。命名与 EnvTrustedPubKey 对称。
const EnvSigningKeyB64 = "AFROG_POC_SIGNING_KEY_B64"

// officialPublicKeyB64 是 afrog 官方 PoC 的验签公钥（base64）。
// 源码树里为空表示开发态未启用官方验签；发布构建时通过
//
//	-ldflags "-X github.com/zan8in/afrog/v3/pkg/pocsign.officialPublicKeyB64=<...>"
//
// 注入。私钥只存在于发布流水线，绝不进入仓库。
var officialPublicKeyB64 = ""

const (
	keysDirName    = "keys"
	signingKeyName = "signing.key"
	verifyKeyName  = "verification.pub"
)

// ExtractSignature 从 PoC 原始内容中拆出签名与去签名的正文。
// 找到签名时返回解码后的签名与去尾空白的正文；找不到时返回 ErrNoSignature
// 及去尾空白的完整内容。签名无法解码、或签名行之后仍有内容时同样返回
// ErrNoSignature：签名必须位于文件末尾，否则签名无法覆盖尾部内容。
func ExtractSignature(data []byte) (sig []byte, content []byte, err error) {
	idx := bytes.LastIndex(data, []byte(SignaturePattern))
	if idx < 0 {
		return nil, bytes.TrimSpace(data), ErrNoSignature
	}
	content = bytes.TrimSpace(data[:idx])

	line := data[idx+len(SignaturePattern):]
	if nl := bytes.IndexByte(line, '\n'); nl >= 0 {
		// 签名行之后还有内容（哪怕只是空行之外的任何东西），签名不覆盖它，
		// 一律视为未签名，避免“尾部追加 YAML”绕过签名。
		if len(bytes.TrimSpace(line[nl+1:])) > 0 {
			return nil, bytes.TrimSpace(data), ErrNoSignature
		}
		line = line[:nl]
	}
	sigStr := strings.TrimSpace(string(line))
	if sigStr == "" {
		return nil, content, ErrNoSignature
	}
	sig, decErr := base64.StdEncoding.DecodeString(sigStr)
	if decErr != nil {
		return nil, content, fmt.Errorf("pocsign: decode signature: %w", decErr)
	}
	return sig, content, nil
}

// Sign 用私钥对正文签名，返回可追加到文件末尾的签名行（含结尾换行）。
// 若 data 中已有旧签名，会先剥离再重新签名。
func Sign(priv ed25519.PrivateKey, data []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("pocsign: invalid private key size")
	}
	_, content, _ := ExtractSignature(data)
	sig := ed25519.Sign(priv, content)
	return []byte(SignaturePattern + base64.StdEncoding.EncodeToString(sig) + "\n"), nil
}

// SignFile 就地签名一个 PoC 文件：先剥离旧签名，再追加新签名。
func SignFile(path string, priv ed25519.PrivateKey) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	line, err := Sign(priv, data)
	if err != nil {
		return err
	}
	_, content, _ := ExtractSignature(data)

	var buf bytes.Buffer
	buf.Write(content)
	if len(content) > 0 {
		buf.WriteByte('\n')
	}
	buf.Write(line)

	mode := os.FileMode(0o644)
	if fi, statErr := os.Stat(path); statErr == nil {
		mode = fi.Mode()
	}
	// 就地在 POC 文件末尾追加签名行。扫描进程会并发读取同一批 PoC yaml，
	// 用原子写避免读方拿到「已截断但还没写完」的半截文件。
	return utils.WriteFileAtomic(path, buf.Bytes(), mode)
}

// SignPath 对文件或目录下的所有 .yaml/.yml 就地签名，返回处理的文件数。
func SignPath(root string, priv ed25519.PrivateKey) (int, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return 0, errors.New("pocsign: empty path")
	}
	fi, err := os.Stat(root)
	if err != nil {
		return 0, err
	}
	if !fi.IsDir() {
		if err := SignFile(root, priv); err != nil {
			return 0, err
		}
		return 1, nil
	}

	count := 0
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		low := strings.ToLower(d.Name())
		if !strings.HasSuffix(low, ".yaml") && !strings.HasSuffix(low, ".yml") {
			return nil
		}
		if err := SignFile(path, priv); err != nil {
			return err
		}
		count++
		return nil
	})
	return count, walkErr
}

// Verify 用公钥验证签名。任何形状不符都直接判失败。
func Verify(pub ed25519.PublicKey, data, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, data, sig)
}

// KeysDir 返回用户密钥目录 ~/.config/afrog/keys。
func KeysDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "afrog", keysDirName), nil
}

// LoadSigningKey 读取用户签名私钥；不存在时返回 os.ErrNotExist。
func LoadSigningKey() (ed25519.PrivateKey, error) {
	dir, err := KeysDir()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, signingKeyName))
	if err != nil {
		return nil, err
	}
	b, err := decodeBase64Key(raw, ed25519.PrivateKeySize)
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(b), nil
}

// LoadPublicKey 读取用户验签公钥；不存在时返回 os.ErrNotExist。
func LoadPublicKey() (ed25519.PublicKey, error) {
	dir, err := KeysDir()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, verifyKeyName))
	if err != nil {
		return nil, err
	}
	b, err := decodeBase64Key(raw, ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(b), nil
}

// LoadOrCreateSigningKey 读取用户签名私钥；不存在则生成一对新密钥并落盘
// （signing.key 权限 0600，verification.pub 权限 0644）。
func LoadOrCreateSigningKey() (ed25519.PrivateKey, error) {
	priv, err := LoadSigningKey()
	if err == nil {
		return priv, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	dir, err := KeysDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := utils.WriteFileAtomic(filepath.Join(dir, signingKeyName), encodeBase64Key(priv), 0o600); err != nil {
		return nil, err
	}
	if err := utils.WriteFileAtomic(filepath.Join(dir, verifyKeyName), encodeBase64Key(pub), 0o644); err != nil {
		return nil, err
	}
	return priv, nil
}

// ResolveSigningKey 返回用于签名的私钥：
//   - 若设置了 AFROG_POC_SIGNING_KEY_B64，直接解码使用（不落盘、不生成密钥对），
//     这是发布流水线注入官方私钥的路径；
//   - 否则读取用户密钥，不存在则生成，即自签工具路径。
func ResolveSigningKey() (ed25519.PrivateKey, error) {
	if s := strings.TrimSpace(os.Getenv(EnvSigningKeyB64)); s != "" {
		b, err := decodeBase64Key([]byte(s), ed25519.PrivateKeySize)
		if err != nil {
			return nil, fmt.Errorf("pocsign: %s: %w", EnvSigningKeyB64, err)
		}
		return ed25519.PrivateKey(b), nil
	}
	return LoadOrCreateSigningKey()
}

// PublicKeyOf 返回私钥对应的公钥；私钥形状非法时返回 nil。
func PublicKeyOf(priv ed25519.PrivateKey) ed25519.PublicKey {
	if len(priv) != ed25519.PrivateKeySize {
		return nil
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	return pub
}

// EncodePublicKeyB64 返回公钥的 base64 文本，便于注入 -ldflags。
func EncodePublicKeyB64(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		return ""
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// Fingerprint 返回公钥的短指纹（base64 前 12 个字符），用于展示身份。
func Fingerprint(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		return ""
	}
	s := base64.StdEncoding.EncodeToString(pub)
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// Verifier 持有一组受信任公钥，任一命中即视为验签通过。
type Verifier struct {
	keys []ed25519.PublicKey
}

// NewVerifier 返回一个空的验签器。
func NewVerifier() *Verifier { return &Verifier{} }

// Add 追加一个受信任公钥；公钥形状非法时忽略。
func (v *Verifier) Add(pub ed25519.PublicKey) {
	if len(pub) != ed25519.PublicKeySize {
		return
	}
	v.keys = append(v.keys, pub)
}

// Len 返回受信任公钥数量。
func (v *Verifier) Len() int { return len(v.keys) }

// Verify 判断签名是否由任一受信任公钥签发。
func (v *Verifier) Verify(data, sig []byte) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	for _, k := range v.keys {
		if ed25519.Verify(k, data, sig) {
			return true
		}
	}
	return false
}

// DefaultVerifier 组装默认验签器，来源依次为：
//  1. 内嵌的官方公钥（发布构建注入）；
//  2. 用户自己的 ~/.config/afrog/keys/verification.pub；
//  3. 环境变量 AFROG_POC_PUBKEY_B64。
//
// 任一项缺失都静默跳过，不视为错误。
func DefaultVerifier() *Verifier {
	v := NewVerifier()
	if pk := decodePubKeyB64(officialPublicKeyB64); pk != nil {
		v.Add(pk)
	}
	if pk, err := LoadPublicKey(); err == nil {
		v.Add(pk)
	}
	if pk := decodePubKeyB64(os.Getenv(EnvTrustedPubKey)); pk != nil {
		v.Add(pk)
	}
	return v
}

func decodePubKeyB64(s string) ed25519.PublicKey {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(b)
}

func encodeBase64Key(k []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(k) + "\n")
}

func decodeBase64Key(raw []byte, size int) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("pocsign: decode key: %w", err)
	}
	if len(b) != size {
		return nil, fmt.Errorf("pocsign: invalid key size %d, want %d", len(b), size)
	}
	return b, nil
}
