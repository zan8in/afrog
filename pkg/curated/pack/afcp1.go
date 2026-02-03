package pack

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type AFCP1Header struct {
	Format        string `json:"format"`
	ManifestID    string `json:"manifest_id"`
	Type          string `json:"type"`
	CreatedAt     string `json:"created_at"`
	Nonce         string `json:"nonce"`
	PayloadFormat string `json:"payload_format"`
}

func DecryptAFCP1ToDir(afcpPath string, destDir string, contentKey []byte) (*AFCP1Header, error) {
	if len(contentKey) != 32 {
		return nil, errors.New("content key must be 32 bytes")
	}
	b, err := os.ReadFile(afcpPath)
	if err != nil {
		return nil, err
	}
	if len(b) < 10 {
		return nil, errors.New("afcp too small")
	}
	if string(b[:4]) != "AFCP" {
		return nil, errors.New("invalid afcp magic")
	}
	ver := binary.BigEndian.Uint16(b[4:6])
	if ver != 1 {
		return nil, errors.New("unsupported afcp version")
	}
	headerLen := binary.BigEndian.Uint32(b[6:10])
	if headerLen == 0 {
		return nil, errors.New("empty header")
	}
	if int(10+headerLen) > len(b) {
		return nil, errors.New("invalid header length")
	}
	headerBytes := b[10 : 10+headerLen]
	var hdr AFCP1Header
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return nil, err
	}
	nonceB, err := base64.StdEncoding.DecodeString(strings.TrimSpace(hdr.Nonce))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonceB) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}
	ciphertext := b[10+headerLen:]
	plain, err := gcm.Open(nil, nonceB, ciphertext, headerBytes)
	if err != nil {
		return nil, err
	}
	if err := extractTarBytes(destDir, plain); err != nil {
		return nil, err
	}
	return &hdr, nil
}

func extractTarBytes(destDir string, tarBytes []byte) error {
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}
	tr := tar.NewReader(bytes.NewReader(tarBytes))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := strings.ReplaceAll(h.Name, "\\", "/")
		name = strings.TrimPrefix(name, "/")
		clean := filepath.Clean(name)
		if clean == "." || clean == "" {
			continue
		}
		if strings.Contains(clean, "..") {
			return errors.New("invalid tar path")
		}
		full := filepath.Join(destDir, clean)
		if !strings.HasPrefix(filepath.Clean(full), filepath.Clean(destDir)+string(os.PathSeparator)) && filepath.Clean(full) != filepath.Clean(destDir) {
			return errors.New("invalid tar path")
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(full, 0755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return err
			}
			_, cpErr := io.Copy(f, tr)
			closeErr := f.Close()
			if cpErr != nil {
				return cpErr
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return errors.New("unsupported tar entry type")
		}
	}
}

