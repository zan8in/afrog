package pocsign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("id: test\ninfo:\n  name: demo\n")

	line, err := Sign(priv, body)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	signed := append(append([]byte{}, body...), line...)

	sig, content, err := ExtractSignature(signed)
	if err != nil {
		t.Fatalf("ExtractSignature: %v", err)
	}
	if !bytes.Equal(content, bytes.TrimSpace(body)) {
		t.Fatalf("content mismatch: %q", content)
	}
	if !Verify(pub, content, sig) {
		t.Fatal("Verify should pass for freshly signed content")
	}
}

func TestExtractSignatureMissing(t *testing.T) {
	body := []byte("id: test\ninfo:\n  name: demo\n")
	sig, content, err := ExtractSignature(body)
	if err != ErrNoSignature {
		t.Fatalf("err = %v, want ErrNoSignature", err)
	}
	if sig != nil {
		t.Fatal("sig should be nil")
	}
	if !bytes.Equal(content, bytes.TrimSpace(body)) {
		t.Fatalf("content = %q", content)
	}
}

func TestVerifyRejectsTamperedContent(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte("id: test\ninfo:\n  name: demo\n")
	line, _ := Sign(priv, body)
	sig, content, _ := ExtractSignature(append(append([]byte{}, body...), line...))

	tampered := append([]byte{}, content...)
	tampered = append(tampered, []byte("\n# injected\n")...)
	if Verify(pub, tampered, sig) {
		t.Fatal("Verify must fail when content changes")
	}
}

func TestVerifyAgainstWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte("id: test\n")
	line, _ := Sign(priv, body)
	sig, content, _ := ExtractSignature(append(append([]byte{}, body...), line...))
	if Verify(otherPub, content, sig) {
		t.Fatal("Verify must fail with an unrelated key")
	}
}

func TestSignIdempotent(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte("id: test\n")

	line1, _ := Sign(priv, body)
	once := append(append([]byte{}, body...), line1...)
	line2, _ := Sign(priv, once)

	// 二次签名应先剥离旧签名再签，正文不含旧的 digest 行。
	_, content2, _ := ExtractSignature(append(append([]byte{}, body...), line2...))
	if bytes.Contains(content2, []byte(SignaturePattern)) {
		t.Fatalf("content still contains digest line: %q", content2)
	}
}

func TestSignPathAndLoadOrCreateKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := t.TempDir()
	p1 := filepath.Join(dir, "a.yaml")
	p2 := filepath.Join(dir, "b.yml")
	if err := os.WriteFile(p1, []byte("id: a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p2, []byte("id: b\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	priv, err := LoadOrCreateSigningKey()
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey: %v", err)
	}
	pub, err := LoadPublicKey()
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}

	n, err := SignPath(dir, priv)
	if err != nil {
		t.Fatalf("SignPath: %v", err)
	}
	if n != 2 {
		t.Fatalf("signed %d files, want 2", n)
	}

	for _, p := range []string{p1, p2} {
		raw, _ := os.ReadFile(p)
		sig, content, err := ExtractSignature(raw)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if !Verify(pub, content, sig) {
			t.Fatalf("%s: signature did not verify", p)
		}
	}

	// 再次调用应复用同一密钥，而非重新生成。
	priv2, err := LoadOrCreateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Equal(priv2) {
		t.Fatal("LoadOrCreateSigningKey regenerated the key on second call")
	}
}

func TestResolveSigningKeyFromEnv(t *testing.T) {
	// 隔离 HOME，确保不会读到真实用户密钥。
	t.Setenv("HOME", t.TempDir())

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvSigningKeyB64, base64.StdEncoding.EncodeToString(priv))

	got, err := ResolveSigningKey()
	if err != nil {
		t.Fatalf("ResolveSigningKey: %v", err)
	}
	if !got.Equal(priv) {
		t.Fatal("ResolveSigningKey should return the key from the environment")
	}
	// 环境变量路径不应在用户目录创建密钥文件。
	dir, err := KeysDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("env path must not create user key files, stat err = %v", err)
	}
}

func TestResolveSigningKeyInvalidEnv(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(EnvSigningKeyB64, "not-a-valid-key")
	if _, err := ResolveSigningKey(); err == nil {
		t.Fatal("expected an error for an invalid AFROG_POC_SIGNING_KEY_B64")
	}
}

func TestDefaultVerifierIncludesEnvKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv(EnvTrustedPubKey, base64.StdEncoding.EncodeToString(pub))

	body := []byte("id: test\n")
	line, _ := Sign(priv, body)
	sig, content, _ := ExtractSignature(append(append([]byte{}, body...), line...))

	v := DefaultVerifier()
	if !v.Verify(content, sig) {
		t.Fatal("DefaultVerifier should trust the AFROG_POC_PUBKEY_B64 key")
	}
}

func TestDefaultVerifierIncludesUserKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if _, err := LoadOrCreateSigningKey(); err != nil {
		t.Fatal(err)
	}

	body := []byte("id: test\n")
	priv, _ := LoadSigningKey()
	line, _ := Sign(priv, body)
	sig, content, _ := ExtractSignature(append(append([]byte{}, body...), line...))

	v := DefaultVerifier()
	if v.Len() == 0 {
		t.Fatal("DefaultVerifier has no trusted keys after key generation")
	}
	if !v.Verify(content, sig) {
		t.Fatal("DefaultVerifier should verify the user's own signature")
	}
}
