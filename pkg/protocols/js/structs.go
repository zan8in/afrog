package js

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/dop251/goja"
	"github.com/zan8in/afrog/v3/pkg/capability"
)

// afrog/structs：二进制打包 / 解包的底座，供 tcp 之外的二进制协议 PoC 使用。
//
// 支持 Python struct 风格的子集：
//
//	字节序： '<' 小端，'>' / '!' 大端（默认大端）
//	类型：   b/B int8/uint8，h/H int16/uint16，i/I int32/uint32，
//	         q/Q int64/uint64，s 字符串（需带长度，如 4s），x 填充字节
//	重复：   如 2H、4s
//
// Pack 返回原始字节串（Go string，可直接交给 afrog/net 的 Send）；
// Unpack 返回按格式解出的值数组（只读，不影响未消费的尾部数据）。

type structItem struct {
	typ   byte
	count int // 仅 's' 使用
}

func buildStructsModule(state *execState) (goja.Value, error) {
	vm := state.vm
	obj := vm.NewObject()

	if err := obj.Set("Pack", func(format string, values ...any) (string, error) {
		b, err := structPack(format, expandStructValues(values))
		if err != nil {
			return "", err
		}
		return string(b), nil
	}); err != nil {
		return nil, err
	}

	if err := obj.Set("Unpack", func(format string, data any) ([]any, error) {
		b, err := structDataToBytes(data)
		if err != nil {
			return nil, err
		}
		return structUnpack(format, b)
	}); err != nil {
		return nil, err
	}

	if err := obj.Set("CalcSize", func(format string) (int, error) {
		return structCalcSize(format)
	}); err != nil {
		return nil, err
	}

	return obj, nil
}

func init() {
	registerModule(moduleDef{name: "structs", summary: "二进制打包/解包（struct 风格格式）", level: capability.Network, build: buildStructsModule})
}

// expandStructValues 同时支持 Pack(">HH", 1, 2) 与 Pack(">HH", [1, 2])。
func expandStructValues(values []any) []any {
	if len(values) == 1 {
		if arr, ok := values[0].([]any); ok {
			return arr
		}
	}
	return values
}

// structDataToBytes 把 Unpack 的入参规整为 []byte，接受字符串 / 字节数组 / 数字数组。
func structDataToBytes(data any) ([]byte, error) {
	switch v := data.(type) {
	case nil:
		return nil, nil
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	case []any:
		out := make([]byte, 0, len(v))
		for _, it := range v {
			n, err := toInt64(it)
			if err != nil || n < 0 || n > 255 {
				return nil, fmt.Errorf("struct: invalid byte %v", it)
			}
			out = append(out, byte(n))
		}
		return out, nil
	}
	return nil, fmt.Errorf("struct: unsupported data type %T", data)
}

// structValueBytes 把 Pack 的字符串字段取值规整为 []byte。
func structValueBytes(v any) ([]byte, error) {
	switch s := v.(type) {
	case string:
		return []byte(s), nil
	case []byte:
		return s, nil
	}
	return nil, fmt.Errorf("struct: string field expects a string, got %T", v)
}

func validStructType(c byte) bool {
	switch c {
	case 'b', 'B', 'h', 'H', 'i', 'I', 'q', 'Q', 's', 'x':
		return true
	}
	return false
}

func structTypeSize(t byte) int {
	switch t {
	case 'b', 'B', 'x':
		return 1
	case 'h', 'H':
		return 2
	case 'i', 'I':
		return 4
	case 'q', 'Q':
		return 8
	}
	return 0
}

// parseStructFormat 解析格式串，并把重复计数展开为逐项（'s' 保留长度）。
func parseStructFormat(format string) (little bool, items []structItem, err error) {
	s := strings.TrimSpace(format)
	if s == "" {
		return false, nil, fmt.Errorf("struct: empty format")
	}

	i := 0
	switch s[0] {
	case '<':
		little = true
		i = 1
	case '>', '!':
		i = 1
	}

	for i < len(s) {
		c := s[i]
		if c == ' ' {
			i++
			continue
		}
		count := 0
		if c >= '0' && c <= '9' {
			for i < len(s) && s[i] >= '0' && s[i] <= '9' {
				count = count*10 + int(s[i]-'0')
				i++
			}
			if i >= len(s) {
				return false, nil, fmt.Errorf("struct: format %q ends with a count", format)
			}
			c = s[i]
		}
		if !validStructType(c) {
			return false, nil, fmt.Errorf("struct: unsupported type %q in format %q", string(c), format)
		}

		switch {
		case c == 's':
			if count <= 0 {
				return false, nil, fmt.Errorf("struct: string type 's' requires a count, e.g. 4s")
			}
			items = append(items, structItem{typ: c, count: count})
		case count > 1:
			for k := 0; k < count; k++ {
				items = append(items, structItem{typ: c})
			}
		default:
			items = append(items, structItem{typ: c})
		}
		i++
	}

	if len(items) == 0 {
		return false, nil, fmt.Errorf("struct: format %q has no items", format)
	}
	return little, items, nil
}

func structByteOrder(little bool) binary.ByteOrder {
	if little {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

func structPack(format string, values []any) ([]byte, error) {
	little, items, err := parseStructFormat(format)
	if err != nil {
		return nil, err
	}
	order := structByteOrder(little)

	need := 0
	for _, it := range items {
		if it.typ != 'x' {
			need++
		}
	}
	if len(values) != need {
		return nil, fmt.Errorf("struct: format %q needs %d values, got %d", format, need, len(values))
	}

	out := make([]byte, 0, 16)
	vi := 0
	for _, it := range items {
		if it.typ == 'x' {
			out = append(out, 0)
			continue
		}
		v := values[vi]
		vi++

		if it.typ == 's' {
			sb, err := structValueBytes(v)
			if err != nil {
				return nil, err
			}
			buf := make([]byte, it.count)
			copy(buf, sb)
			out = append(out, buf...)
			continue
		}

		size := structTypeSize(it.typ)
		buf := make([]byte, size)
		switch it.typ {
		case 'b', 'h', 'i', 'q':
			n, err := toInt64(v)
			if err != nil {
				return nil, fmt.Errorf("struct: %v", err)
			}
			switch it.typ {
			case 'b':
				buf[0] = byte(int8(n))
			case 'h':
				order.PutUint16(buf, uint16(int16(n)))
			case 'i':
				order.PutUint32(buf, uint32(int32(n)))
			case 'q':
				order.PutUint64(buf, uint64(n))
			}
		default: // B H I Q
			n, err := toUint64(v)
			if err != nil {
				return nil, fmt.Errorf("struct: %v", err)
			}
			switch it.typ {
			case 'B':
				buf[0] = byte(n)
			case 'H':
				order.PutUint16(buf, uint16(n))
			case 'I':
				order.PutUint32(buf, uint32(n))
			case 'Q':
				order.PutUint64(buf, n)
			}
		}
		out = append(out, buf...)
	}
	return out, nil
}

func structUnpack(format string, data []byte) ([]any, error) {
	little, items, err := parseStructFormat(format)
	if err != nil {
		return nil, err
	}
	order := structByteOrder(little)

	offset := 0
	out := make([]any, 0, len(items))
	for _, it := range items {
		size := structTypeSize(it.typ)
		if it.typ == 's' {
			size = it.count
		}
		if offset+size > len(data) {
			return nil, fmt.Errorf("struct: data too short for format %q: need %d bytes at offset %d, have %d",
				format, size, offset, len(data)-offset)
		}
		chunk := data[offset : offset+size]
		offset += size

		switch it.typ {
		case 'x':
			// 填充字节，跳过
		case 's':
			out = append(out, string(chunk))
		case 'b':
			out = append(out, int64(int8(chunk[0])))
		case 'B':
			out = append(out, int64(chunk[0]))
		case 'h':
			out = append(out, int64(int16(order.Uint16(chunk))))
		case 'H':
			out = append(out, int64(order.Uint16(chunk)))
		case 'i':
			out = append(out, int64(int32(order.Uint32(chunk))))
		case 'I':
			out = append(out, int64(order.Uint32(chunk)))
		case 'q':
			out = append(out, int64(order.Uint64(chunk)))
		case 'Q':
			out = append(out, order.Uint64(chunk))
		}
	}
	return out, nil
}

func structCalcSize(format string) (int, error) {
	_, items, err := parseStructFormat(format)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, it := range items {
		if it.typ == 's' {
			total += it.count
			continue
		}
		total += structTypeSize(it.typ)
	}
	return total, nil
}

func toInt64(v any) (int64, error) {
	switch n := v.(type) {
	case int:
		return int64(n), nil
	case int8:
		return int64(n), nil
	case int16:
		return int64(n), nil
	case int32:
		return int64(n), nil
	case int64:
		return n, nil
	case uint:
		return int64(n), nil
	case uint8:
		return int64(n), nil
	case uint16:
		return int64(n), nil
	case uint32:
		return int64(n), nil
	case uint64:
		return int64(n), nil
	case float32:
		return int64(n), nil
	case float64:
		return int64(n), nil
	case bool:
		if n {
			return 1, nil
		}
		return 0, nil
	case string:
		var out int64
		if _, err := fmt.Sscanf(strings.TrimSpace(n), "%d", &out); err == nil {
			return out, nil
		}
		return 0, fmt.Errorf("cannot parse %q as integer", n)
	}
	return 0, fmt.Errorf("cannot use %T as integer", v)
}

func toUint64(v any) (uint64, error) {
	switch n := v.(type) {
	case int:
		return uint64(n), nil
	case int8:
		return uint64(n), nil
	case int16:
		return uint64(n), nil
	case int32:
		return uint64(n), nil
	case int64:
		return uint64(n), nil
	case uint:
		return uint64(n), nil
	case uint8:
		return uint64(n), nil
	case uint16:
		return uint64(n), nil
	case uint32:
		return uint64(n), nil
	case uint64:
		return n, nil
	case float32:
		return uint64(n), nil
	case float64:
		return uint64(n), nil
	case bool:
		if n {
			return 1, nil
		}
		return 0, nil
	case string:
		var out uint64
		if _, err := fmt.Sscanf(strings.TrimSpace(n), "%d", &out); err == nil {
			return out, nil
		}
		return 0, fmt.Errorf("cannot parse %q as unsigned integer", n)
	}
	return 0, fmt.Errorf("cannot use %T as unsigned integer", v)
}
