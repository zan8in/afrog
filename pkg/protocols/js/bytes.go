package js

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/dop251/goja"
	"github.com/zan8in/afrog/v3/pkg/capability"
)

// afrog/bytes：二进制缓冲区，用于拼装协议报文后再交给 afrog/net 发送。
//
//	var bytes = require("afrog/bytes");
//	var b = bytes.NewBuffer();
//	b.WriteString("GET /");
//	b.WriteHex("0d0a");
//	b.Pack(">H", 80);
//	Export(b.Hex());
type byteBuffer struct {
	buf []byte
}

func buildBytesModule(state *execState) (goja.Value, error) {
	vm := state.vm
	obj := vm.NewObject()
	if err := obj.Set("NewBuffer", func(parts ...any) (*byteBuffer, error) {
		b := &byteBuffer{}
		for _, p := range parts {
			if err := b.append(p); err != nil {
				return nil, err
			}
		}
		return b, nil
	}); err != nil {
		return nil, err
	}
	return obj, nil
}

func init() {
	registerModule(moduleDef{name: "bytes", summary: "二进制缓冲区（拼装报文）", level: capability.Network, build: buildBytesModule})
}

// cleanHex 去掉十六进制串里的 0x 前缀与空白，并对奇数长度补零。
func cleanHex(s string) string {
	clean := strings.NewReplacer("0x", "", " ", "", "\r", "", "\n", "", "\t", "").Replace(strings.TrimSpace(s))
	if len(clean)%2 == 1 {
		clean = "0" + clean
	}
	return clean
}

func (b *byteBuffer) append(v any) error {
	switch d := v.(type) {
	case nil:
	case string:
		b.buf = append(b.buf, []byte(d)...)
	case []byte:
		b.buf = append(b.buf, d...)
	case []any:
		for _, it := range d {
			n, err := toInt64(it)
			if err != nil || n < 0 || n > 255 {
				return fmt.Errorf("bytes: invalid byte %v", it)
			}
			b.buf = append(b.buf, byte(n))
		}
	default:
		return fmt.Errorf("bytes: unsupported data type %T", v)
	}
	return nil
}

// Write 追加字符串 / 字节数组 / 字节数字数组，返回自身以便链式调用。
func (b *byteBuffer) Write(data ...any) (*byteBuffer, error) {
	for _, d := range data {
		if err := b.append(d); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// WriteString 追加字符串。
func (b *byteBuffer) WriteString(s string) *byteBuffer {
	b.buf = append(b.buf, []byte(s)...)
	return b
}

// WriteHex 追加十六进制字符串表示的字节。
func (b *byteBuffer) WriteHex(hexStr string) (*byteBuffer, error) {
	decoded, err := hex.DecodeString(cleanHex(hexStr))
	if err != nil {
		return nil, fmt.Errorf("bytes: invalid hex: %w", err)
	}
	b.buf = append(b.buf, decoded...)
	return b, nil
}

// WriteUint8 追加 1 字节。
func (b *byteBuffer) WriteUint8(n int) *byteBuffer {
	b.buf = append(b.buf, byte(n))
	return b
}

// WriteUint16 以大端追加 2 字节整数。
func (b *byteBuffer) WriteUint16(n int) *byteBuffer {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(n))
	b.buf = append(b.buf, buf...)
	return b
}

// WriteUint32 以大端追加 4 字节整数。
func (b *byteBuffer) WriteUint32(n int) *byteBuffer {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(n))
	b.buf = append(b.buf, buf...)
	return b
}

// WriteUint64 以大端追加 8 字节整数。
func (b *byteBuffer) WriteUint64(n int) *byteBuffer {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(n))
	b.buf = append(b.buf, buf...)
	return b
}

// Pack 按 afrog/structs 的格式打包并追加。
func (b *byteBuffer) Pack(format string, values ...any) (*byteBuffer, error) {
	bin, err := structPack(format, expandStructValues(values))
	if err != nil {
		return nil, err
	}
	b.buf = append(b.buf, bin...)
	return b, nil
}

// Bytes 返回底层字节数组。
func (b *byteBuffer) Bytes() []byte {
	return b.buf
}

// String 返回字符串表示（可直接交给 afrog/net 的 Send）。
func (b *byteBuffer) String() string {
	return string(b.buf)
}

// Hex 返回十六进制表示。
func (b *byteBuffer) Hex() string {
	return hex.EncodeToString(b.buf)
}

// Len 返回当前长度（字节）。
func (b *byteBuffer) Len() int {
	return len(b.buf)
}

// Reset 清空缓冲区，返回自身。
func (b *byteBuffer) Reset() *byteBuffer {
	b.buf = b.buf[:0]
	return b
}
