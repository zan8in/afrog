package runner

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/zan8in/oobadapter/pkg/oobadapter"

	"github.com/dlclark/regexp2"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	"github.com/zan8in/afrog/v3/pkg/proto"
	"github.com/zan8in/afrog/v3/pkg/utils"
)

var (
	NewProgramOptions = []cel.ProgramOption{
		cel.Functions(
			// string
			&functions.Overload{
				Operator: "string_icontains_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to contains", lhs.Type())
					}
					v2, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to contains", rhs.Type())
					}
					return types.Bool(strings.Contains(strings.ToLower(string(v1)), strings.ToLower(string(v2))))
				},
			},
			&functions.Overload{
				Operator: "substr_string_int_int",
				Function: func(values ...ref.Val) ref.Val {
					if len(values) == 3 {
						str, ok := values[0].(types.String)
						if !ok {
							return types.NewErr("invalid string to 'substr'")
						}
						start, ok := values[1].(types.Int)
						if !ok {
							return types.NewErr("invalid start to 'substr'")
						}
						length, ok := values[2].(types.Int)
						if !ok {
							return types.NewErr("invalid length to 'substr'")
						}
						runes := []rune(str)
						if start < 0 || length < 0 || int(start+length) > len(runes) {
							return types.NewErr("invalid start or length to 'substr'")
						}
						return types.String(runes[start : start+length])
					} else {
						return types.NewErr("too many arguments to 'substr'")
					}
				},
			},
			&functions.Overload{
				Operator: "substr_bytes_int_int",
				Function: func(values ...ref.Val) ref.Val {
					if len(values) == 3 {
						b, ok := values[0].(types.Bytes)
						if !ok {
							return types.NewErr("invalid bytes to 'substr'")
						}
						start, ok := values[1].(types.Int)
						if !ok {
							return types.NewErr("invalid start to 'substr'")
						}
						length, ok := values[2].(types.Int)
						if !ok {
							return types.NewErr("invalid length to 'substr'")
						}
						if start < 0 || length < 0 || int(start+length) > len(b) {
							return types.NewErr("invalid start or length to 'substr'")
						}
						return types.Bytes(b[start : start+length])
					} else {
						return types.NewErr("too many arguments to 'substr'")
					}
				},
			},
			&functions.Overload{
				Operator: "replaceAll_string_string_string",
				Function: func(values ...ref.Val) ref.Val {
					s, ok := values[0].(types.String)
					if !ok {
						return types.ValOrErr(s, "unexpected type '%v' passed to replaceAll", s.Type())
					}
					old, ok := values[1].(types.String)
					if !ok {
						return types.ValOrErr(old, "unexpected type '%v' passed to replaceAll", old.Type())
					}
					new, ok := values[2].(types.String)
					if !ok {
						return types.ValOrErr(new, "unexpected type '%v' passed to replaceAll", new.Type())
					}

					return types.String(strings.ReplaceAll(string(s), string(old), string(new)))
				},
			},
			&functions.Overload{
				Operator: "printable_string",
				Unary: func(value ref.Val) ref.Val {
					s, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(s, "unexpected type '%v' passed to printable", s.Type())
					}

					clean := strings.Map(func(r rune) rune {
						if unicode.IsPrint(r) {
							return r
						}
						return -1
					}, string(s))

					return types.String(clean)
				},
			},
			&functions.Overload{
				Operator: "toUintString_string_string",
				Function: func(values ...ref.Val) ref.Val {
					s1, ok := values[0].(types.String)
					s := string(s1)
					if !ok {
						return types.ValOrErr(s1, "unexpected type '%v' passed to toUintString", s1.Type())
					}
					direction, ok := values[1].(types.String)
					if !ok {
						return types.ValOrErr(direction, "unexpected type '%v' passed to toUintString", direction.Type())
					}
					if direction == "<" {
						s = utils.ReverseString(s)
					}
					if _, err := strconv.Atoi(s); err == nil {
						return types.String(s)
					} else {
						return types.NewErr("%v", err)
					}
				},
			},
			&functions.Overload{
				Operator: "toUpper_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to toUpper_string", value.Type())
					}

					return types.String(strings.ToUpper(string(v)))
				},
			},
			&functions.Overload{
				Operator: "toUpper_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to toUpper_bytes", value.Type())
					}

					return types.Bytes(bytes.ToUpper(v))
				},
			},
			&functions.Overload{
				Operator: "toLower_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to toLower_string", value.Type())
					}

					return types.String(strings.ToLower(string(v)))
				},
			},
			&functions.Overload{
				Operator: "toUtf8_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to toUtf8_string", value.Type())
					}
					return types.String(utils.Str2UTF8(string(v)))
				},
			},
			&functions.Overload{
				Operator: "toUtf8_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to toUtf8_bytes", value.Type())
					}
					return types.String(utils.Str2UTF8(string(v)))
				},
			},
			&functions.Overload{
				Operator: "toBytes_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to toBytes_string", value.Type())
					}
					return types.Bytes([]byte(v))
				},
			},

			// []byte
			&functions.Overload{
				Operator: "bytes_bcontains_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bcontains", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bcontains", rhs.Type())
					}
					return types.Bool(bytes.Contains(v1, v2))
				},
			},
			&functions.Overload{
				Operator: "bytes_ibcontains_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bcontains", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bcontains", rhs.Type())
					}
					return types.Bool(bytes.Contains(bytes.ToLower(v1), bytes.ToLower(v2)))
				},
			},
			&functions.Overload{
				Operator: "bytes_bstartsWith_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bstartsWith", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bstartsWith", rhs.Type())
					}
					return types.Bool(bytes.HasPrefix(v1, v2))
				},
			},
			// encode
			&functions.Overload{
				Operator: "md5_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to md5_string", value.Type())
					}
					return types.String(fmt.Sprintf("%x", md5.Sum([]byte(v))))
				},
			},
			&functions.Overload{
				Operator: "sha1_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to sha1_string", value.Type())
					}
					return types.String(fmt.Sprintf("%x", sha1.Sum([]byte(v))))
				},
			},
			&functions.Overload{
				Operator: "sha1_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to sha1_bytes", value.Type())
					}
					return types.String(fmt.Sprintf("%x", sha1.Sum(v)))
				},
			},
			&functions.Overload{
				Operator: "hex_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to hex_bytes", value.Type())
					}
					return types.String(hex.EncodeToString(v))
				},
			},
			&functions.Overload{
				Operator: "hex_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to hex_string", value.Type())
					}
					return types.String(hex.EncodeToString([]byte(v)))
				},
			},
			&functions.Overload{
				Operator: "pkcs7Pad_string_int",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					text, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to pkcs7Pad", lhs.Type())
					}
					bs, ok := rhs.(types.Int)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to pkcs7Pad", rhs.Type())
					}
					blockSize := int(bs)
					if blockSize <= 0 {
						return types.NewErr("invalid block size")
					}
					raw := []byte(text)
					padding := blockSize - (len(raw) % blockSize)
					if padding == 0 {
						padding = blockSize
					}
					pad := bytes.Repeat([]byte{byte(padding)}, padding)
					return types.Bytes(append(raw, pad...))
				},
			},
			&functions.Overload{
				Operator: "pkcs7Pad_bytes_int",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					raw, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to pkcs7Pad", lhs.Type())
					}
					bs, ok := rhs.(types.Int)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to pkcs7Pad", rhs.Type())
					}
					blockSize := int(bs)
					if blockSize <= 0 {
						return types.NewErr("invalid block size")
					}
					padding := blockSize - (len(raw) % blockSize)
					if padding == 0 {
						padding = blockSize
					}
					pad := bytes.Repeat([]byte{byte(padding)}, padding)
					return types.Bytes(append(raw, pad...))
				},
			},
			&functions.Overload{
				Operator: "zeroPad_string_int",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					text, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to zeroPad", lhs.Type())
					}
					bs, ok := rhs.(types.Int)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to zeroPad", rhs.Type())
					}
					blockSize := int(bs)
					if blockSize <= 0 {
						return types.NewErr("invalid block size")
					}
					raw := []byte(text)
					padLen := (blockSize - (len(raw) % blockSize)) % blockSize
					if padLen == 0 {
						return types.Bytes(raw)
					}
					return types.Bytes(append(raw, make([]byte, padLen)...))
				},
			},
			&functions.Overload{
				Operator: "zeroPad_bytes_int",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					raw, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to zeroPad", lhs.Type())
					}
					bs, ok := rhs.(types.Int)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to zeroPad", rhs.Type())
					}
					blockSize := int(bs)
					if blockSize <= 0 {
						return types.NewErr("invalid block size")
					}
					padLen := (blockSize - (len(raw) % blockSize)) % blockSize
					if padLen == 0 {
						return types.Bytes(raw)
					}
					return types.Bytes(append(raw, make([]byte, padLen)...))
				},
			},
			&functions.Overload{
				Operator: "base64_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64_string", value.Type())
					}
					return types.String(base64.StdEncoding.EncodeToString([]byte(v)))
				},
			},
			&functions.Overload{
				Operator: "base64_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64_bytes", value.Type())
					}
					return types.String(base64.StdEncoding.EncodeToString(v))
				},
			},
			&functions.Overload{
				Operator: "base64Decode_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64Decode_string", value.Type())
					}
					decodeBytes, err := base64.StdEncoding.DecodeString(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeBytes)
				},
			},
			&functions.Overload{
				Operator: "base64Decode_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64Decode_bytes", value.Type())
					}
					decodeBytes, err := base64.StdEncoding.DecodeString(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeBytes)
				},
			},
			&functions.Overload{
				Operator: "urlencode_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_string", value.Type())
					}
					return types.String(url.QueryEscape(string(v)))
				},
			},
			&functions.Overload{
				Operator: "urlencode_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_bytes", value.Type())
					}
					return types.String(url.QueryEscape(string(v)))
				},
			},
			&functions.Overload{
				Operator: "urldecode_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urldecode_string", value.Type())
					}
					decodeString, err := url.QueryUnescape(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeString)
				},
			},
			&functions.Overload{
				Operator: "urldecode_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urldecode_bytes", value.Type())
					}
					decodeString, err := url.QueryUnescape(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeString)
				},
			},
			&functions.Overload{
				Operator: "faviconHash_stringOrBytes",
				Unary: func(value ref.Val) ref.Val {
					b, ok := value.(types.Bytes)
					if !ok {
						bStr, ok := value.(types.String)
						b = []byte(bStr)
						if !ok {
							return types.ValOrErr(bStr, "unexpected type '%v' passed to faviconHash", bStr.Type())
						}
					}

					return types.Int(utils.Mmh3Hash32(utils.Base64Encode(b)))
				},
			},
			&functions.Overload{
				Operator: "hexdecode_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to hexdecode_string", value.Type())
					}
					dst := make([]byte, hex.DecodedLen(len(v)))
					n, err := hex.Decode(dst, []byte(v))
					if err != nil {
						return types.ValOrErr(value, "unexpected type '%s' passed to hexdecode_string", err.Error())
					}
					return types.String(string(dst[:n]))
				},
			},
			// random
			&functions.Overload{
				Operator: "randomInt_int_int",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					from, ok := lhs.(types.Int)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to randomInt", lhs.Type())
					}
					to, ok := rhs.(types.Int)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to randomInt", rhs.Type())
					}
					min, max := int(from), int(to)
					return types.Int(rand.Intn(max-min) + min)
				},
			},
			&functions.Overload{
				Operator: "randomLowercase_int",
				Unary: func(value ref.Val) ref.Val {
					n, ok := value.(types.Int)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to randomLowercase", value.Type())
					}
					return types.String(utils.RandLetters(int(n)))
				},
			},
			// regex
			&functions.Overload{
				Operator: "string_bmatches_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					var isMatch = false
					var err error

					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bmatches", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bmatches", rhs.Type())
					}
					re := regexp2.MustCompile(string(v1), 0)
					raw := string([]byte(v2))
					if isMatch, err = re.MatchString(raw); err != nil {
						return types.NewErr("%v", err)
					}
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.Bool(isMatch)
				},
			},
			&functions.Overload{
				Operator: "string_bcount_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bcount", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bcount", rhs.Type())
					}

					re := regexp2.MustCompile(string(v1), 0)
					raw := string([]byte(v2))
					rawRunes := []rune(raw)
					rawLen := len(rawRunes)

					var (
						count   int64
						startAt int
					)
					for startAt <= rawLen {
						m, err := re.FindRunesMatchStartingAt(rawRunes, startAt)
						if err != nil {
							return types.NewErr("%v", err)
						}
						if m == nil {
							break
						}
						count++

						next := m.Index + m.Length
						if m.Length == 0 {
							next = m.Index + 1
						}
						if next <= startAt {
							next = startAt + 1
						}
						startAt = next
					}

					return types.Int(count)
				},
			},
			&functions.Overload{
				Operator: "string_rmatches_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					var isMatch = false
					var err error

					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to rmatches", lhs.Type())
					}
					v2, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to rmatches", rhs.Type())
					}
					re := regexp2.MustCompile(string(v1), 0)
					if isMatch, err = re.MatchString(string(v2)); err != nil {
						return types.NewErr("%v", err)
					}
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.Bool(isMatch)
				},
			},
			&functions.Overload{
				Operator: "string_rcount_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to rcount", lhs.Type())
					}
					v2, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to rcount", rhs.Type())
					}

					re := regexp2.MustCompile(string(v1), 0)
					raw := string(v2)
					rawRunes := []rune(raw)
					rawLen := len(rawRunes)

					var (
						count   int64
						startAt int
					)
					for startAt <= rawLen {
						m, err := re.FindRunesMatchStartingAt(rawRunes, startAt)
						if err != nil {
							return types.NewErr("%v", err)
						}
						if m == nil {
							break
						}
						count++

						next := m.Index + m.Length
						if m.Length == 0 {
							next = m.Index + 1
						}
						if next <= startAt {
							next = startAt + 1
						}
						startAt = next
					}

					return types.Int(count)
				},
			},
			// reverse
			// &functions.Overload{
			// 	Operator: "reverse_wait_int",
			// 	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
			// 		reverse, ok := lhs.Value().(*proto.Reverse)
			// 		if !ok {
			// 			return types.ValOrErr(lhs, "unexpected type '%v' passed to 'wait'", lhs.Type())
			// 		}
			// 		timeout, ok := rhs.Value().(int64)
			// 		if !ok {
			// 			return types.ValOrErr(rhs, "unexpected type '%v' passed to 'wait'", rhs.Type())
			// 		}
			// 		return types.Bool(reverseCheck(reverse, timeout))
			// 	},
			// },
			// &functions.Overload{
			// 	Operator: "reverse_jndi_int",
			// 	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
			// 		reverse, ok := lhs.Value().(*proto.Reverse)
			// 		if !ok {
			// 			return types.ValOrErr(lhs, "unexpected type '%v' passed to 'wait'", lhs.Type())
			// 		}
			// 		timeout, ok := rhs.Value().(int64)
			// 		if !ok {
			// 			return types.ValOrErr(rhs, "unexpected type '%v' passed to 'wait'", rhs.Type())
			// 		}
			// 		return types.Bool(jndiCheck(reverse, timeout))
			// 	},
			// },
			&functions.Overload{
				Operator: "oobCheck_oob_string_int",
				Function: func(values ...ref.Val) ref.Val {
					oob, ok := values[0].Value().(*proto.OOB)
					if !ok {
						return types.ValOrErr(values[0], "unexpected type '%v' passed to toUintString", values[0].Type())
					}
					filterType, ok := values[1].(types.String)
					if !ok {
						return types.ValOrErr(values[1], "unexpected type '%v' passed to toUintString", values[1].Type())
					}
					timeout, ok := values[2].(types.Int)
					if !ok {
						return types.ValOrErr(values[2], "unexpected type '%v' passed to toUintString", values[2].Type())
					}
					return types.Bool(oobCheck(oob, string(filterType), int64(timeout)))
				},
			},
			// other
			&functions.Overload{
				Operator: "sleep_int",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Int)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to sleep", value.Type())
					}
					time.Sleep(time.Duration(v) * time.Second)
					return nil
				},
			},
			// year
			&functions.Overload{
				Operator: "year_string",
				Unary: func(value ref.Val) ref.Val {
					year := time.Now().Format("2006")
					return types.String(year)
				},
			},
			&functions.Overload{
				Operator: "shortyear_string",
				Unary: func(value ref.Val) ref.Val {
					year := time.Now().Format("06")
					return types.String(year)
				},
			},
			&functions.Overload{
				Operator: "month_string",
				Unary: func(value ref.Val) ref.Val {
					month := time.Now().Format("01")
					return types.String(month)
				},
			},
			&functions.Overload{
				Operator: "day_string",
				Unary: func(value ref.Val) ref.Val {
					day := time.Now().Format("02")
					return types.String(day)
				},
			},
			&functions.Overload{
				Operator: "timestamp_second",
				Function: func(values ...ref.Val) ref.Val {
					if len(values) != 0 {
						return types.NewErr("too many arguments to 'timestamp_second'")
					}
					timestamp := strconv.FormatInt(time.Now().Unix(), 10)
					return types.String(timestamp)
				},
			},
			&functions.Overload{
				Operator: "timestamp_milli",
				Function: func(values ...ref.Val) ref.Val {
					if len(values) != 0 {
						return types.NewErr("too many arguments to 'timestamp_milli'")
					}
					timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
					return types.String(timestamp)
				},
			},
			&functions.Overload{
				Operator: "versionCompare_string_string_string",
				Function: func(values ...ref.Val) ref.Val {
					if len(values) != 3 {
						return types.Bool(false)
					}
					v1, ok := values[0].(types.String)
					if !ok {
						return types.ValOrErr(v1, "unexpected type '%v' passed to versionCompare", v1.Type())
					}
					operator, ok := values[1].(types.String)
					if !ok {
						return types.ValOrErr(operator, "unexpected type '%v' passed to versionCompare", operator.Type())
					}
					v2, ok := values[2].(types.String)
					if !ok {
						return types.ValOrErr(v2, "unexpected type '%v' passed to versionCompare", v2.Type())
					}

					return types.Bool(utils.Compare(string(v1), string(operator), string(v2)))
				},
			},
			&functions.Overload{
				Operator: "ysoserial_string_string_string",
				Function: func(values ...ref.Val) ref.Val {
					payload, ok := values[0].(types.String)
					if !ok {
						return types.ValOrErr(payload, "unexpected type '%v' passed to versionCompare", payload.Type())
					}
					command, ok := values[1].(types.String)
					if !ok {
						return types.ValOrErr(command, "unexpected type '%v' passed to versionCompare", command.Type())
					}
					encodeType, ok := values[2].(types.String)
					if !ok {
						return types.ValOrErr(encodeType, "unexpected type '%v' passed to versionCompare", encodeType.Type())
					}
					return types.String(utils.GetYsoserial(string(payload), string(command), string(encodeType)))
				},
			},
			&functions.Overload{
				Operator: "aesCBC_string_string_string",
				Function: func(values ...ref.Val) ref.Val {
					text, ok := values[0].(types.String)
					if !ok {
						return types.ValOrErr(text, "unexpected type '%v' passed to versionCompare", text.Type())
					}
					key, ok := values[1].(types.String)
					if !ok {
						return types.ValOrErr(key, "unexpected type '%v' passed to versionCompare", key.Type())
					}
					iv, ok := values[2].(types.String)
					if !ok {
						return types.ValOrErr(iv, "unexpected type '%v' passed to versionCompare", iv.Type())
					}

					plainText := utils.Pkcs5padding([]byte(text), aes.BlockSize, len(text))
					block, _ := aes.NewCipher([]byte(key))
					ciphertext := make([]byte, len(plainText))
					mode := cipher.NewCBCEncrypter(block, []byte(iv))
					mode.CryptBlocks(ciphertext, plainText)

					return types.String(ciphertext)
				},
			},
			&functions.Overload{
				Operator: "aesECB_string_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					text, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to aesECB", lhs.Type())
					}
					key, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to aesECB", rhs.Type())
					}

					plainText := utils.Pkcs5padding([]byte(text), aes.BlockSize, len([]byte(text)))
					block, err := aes.NewCipher([]byte(key))
					if err != nil {
						return types.NewErr("%v", err)
					}

					ciphertext := make([]byte, len(plainText))
					blockSize := block.BlockSize()
					for i := 0; i < len(plainText); i += blockSize {
						block.Encrypt(ciphertext[i:i+blockSize], plainText[i:i+blockSize])
					}
					return types.Bytes(ciphertext)
				},
			},
			&functions.Overload{
				Operator: "aesECB_bytes_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					text, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to aesECB", lhs.Type())
					}
					key, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to aesECB", rhs.Type())
					}

					plainText := utils.Pkcs5padding([]byte(text), aes.BlockSize, len([]byte(text)))
					block, err := aes.NewCipher([]byte(key))
					if err != nil {
						return types.NewErr("%v", err)
					}

					ciphertext := make([]byte, len(plainText))
					blockSize := block.BlockSize()
					for i := 0; i < len(plainText); i += blockSize {
						block.Encrypt(ciphertext[i:i+blockSize], plainText[i:i+blockSize])
					}
					return types.Bytes(ciphertext)
				},
			},
			&functions.Overload{
				Operator: "aesECB_bytes_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					text, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to aesECB", lhs.Type())
					}
					key, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to aesECB", rhs.Type())
					}

					plainText := utils.Pkcs5padding([]byte(text), aes.BlockSize, len([]byte(text)))
					block, err := aes.NewCipher([]byte(key))
					if err != nil {
						return types.NewErr("%v", err)
					}

					ciphertext := make([]byte, len(plainText))
					blockSize := block.BlockSize()
					for i := 0; i < len(plainText); i += blockSize {
						block.Encrypt(ciphertext[i:i+blockSize], plainText[i:i+blockSize])
					}
					return types.Bytes(ciphertext)
				},
			},
			&functions.Overload{
				Operator: "aesECB_string_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					text, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to aesECB", lhs.Type())
					}
					key, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to aesECB", rhs.Type())
					}

					plainText := utils.Pkcs5padding([]byte(text), aes.BlockSize, len([]byte(text)))
					block, err := aes.NewCipher([]byte(key))
					if err != nil {
						return types.NewErr("%v", err)
					}

					ciphertext := make([]byte, len(plainText))
					blockSize := block.BlockSize()
					for i := 0; i < len(plainText); i += blockSize {
						block.Encrypt(ciphertext[i:i+blockSize], plainText[i:i+blockSize])
					}
					return types.Bytes(ciphertext)
				},
			},
			&functions.Overload{
				Operator: "aesECBNoPad_string_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					text, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to aesECBNoPad", lhs.Type())
					}
					key, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to aesECBNoPad", rhs.Type())
					}

					raw := []byte(text)
					if len(raw) == 0 || len(raw)%aes.BlockSize != 0 {
						return types.NewErr("aesECBNoPad requires input length multiple of 16")
					}
					block, err := aes.NewCipher([]byte(key))
					if err != nil {
						return types.NewErr("%v", err)
					}

					ciphertext := make([]byte, len(raw))
					blockSize := block.BlockSize()
					for i := 0; i < len(raw); i += blockSize {
						block.Encrypt(ciphertext[i:i+blockSize], raw[i:i+blockSize])
					}
					return types.Bytes(ciphertext)
				},
			},
			&functions.Overload{
				Operator: "aesECBNoPad_bytes_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					raw, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to aesECBNoPad", lhs.Type())
					}
					key, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to aesECBNoPad", rhs.Type())
					}

					if len(raw) == 0 || len(raw)%aes.BlockSize != 0 {
						return types.NewErr("aesECBNoPad requires input length multiple of 16")
					}
					block, err := aes.NewCipher([]byte(key))
					if err != nil {
						return types.NewErr("%v", err)
					}

					ciphertext := make([]byte, len(raw))
					blockSize := block.BlockSize()
					for i := 0; i < len(raw); i += blockSize {
						block.Encrypt(ciphertext[i:i+blockSize], raw[i:i+blockSize])
					}
					return types.Bytes(ciphertext)
				},
			},
			&functions.Overload{
				Operator: "aesECBNoPad_bytes_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					raw, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to aesECBNoPad", lhs.Type())
					}
					key, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to aesECBNoPad", rhs.Type())
					}

					if len(raw) == 0 || len(raw)%aes.BlockSize != 0 {
						return types.NewErr("aesECBNoPad requires input length multiple of 16")
					}
					block, err := aes.NewCipher([]byte(key))
					if err != nil {
						return types.NewErr("%v", err)
					}

					ciphertext := make([]byte, len(raw))
					blockSize := block.BlockSize()
					for i := 0; i < len(raw); i += blockSize {
						block.Encrypt(ciphertext[i:i+blockSize], raw[i:i+blockSize])
					}
					return types.Bytes(ciphertext)
				},
			},
			&functions.Overload{
				Operator: "aesECBNoPad_string_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					text, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to aesECBNoPad", lhs.Type())
					}
					key, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to aesECBNoPad", rhs.Type())
					}

					raw := []byte(text)
					if len(raw) == 0 || len(raw)%aes.BlockSize != 0 {
						return types.NewErr("aesECBNoPad requires input length multiple of 16")
					}
					block, err := aes.NewCipher([]byte(key))
					if err != nil {
						return types.NewErr("%v", err)
					}

					ciphertext := make([]byte, len(raw))
					blockSize := block.BlockSize()
					for i := 0; i < len(raw); i += blockSize {
						block.Encrypt(ciphertext[i:i+blockSize], raw[i:i+blockSize])
					}
					return types.Bytes(ciphertext)
				},
			},
			&functions.Overload{
				Operator: "repeat_string_int",
				Binary: func(v1 ref.Val, v2 ref.Val) ref.Val {
					str, ok := v1.(types.String)
					if !ok {
						return types.ValOrErr(v1, "unexpected type '%v' passed to randomLowercase", v1.Type())
					}
					count, ok := v2.(types.Int)
					if !ok {
						return types.ValOrErr(v2, "unexpected type '%v' passed to randomLowercase", v2.Type())
					}

					return types.String(strings.Repeat(string(str), int(count)))
				},
			},
			&functions.Overload{
				Operator: "decimal_string_string",
				Binary: func(v1 ref.Val, v2 ref.Val) ref.Val {
					input, ok := v1.(types.String)
					if !ok {
						return types.ValOrErr(v1, "unexpected type '%v' passed to randomLowercase", v1.Type())
					}
					delimiter, ok := v2.(types.String)
					if !ok {
						return types.ValOrErr(v2, "unexpected type '%v' passed to randomLowercase", v2.Type())
					}

					var str []string
					for _, char := range string(input) {
						str = append(str, fmt.Sprintf("%d", char))
					}

					return types.String(strings.Join(str, string(delimiter)))
				},
			},
			&functions.Overload{
				Operator: "length_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)

					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to length_string", value.Type())
					}
					return types.Int(len(v))
				},
			},
			&functions.Overload{
				Operator: "length_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)

					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to length_bytes", value.Type())
					}
					return types.Int(len(v))
				},
			},
			// trim
			&functions.Overload{
				Operator: "trim_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)

					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to trim_string", value.Type())
					}
					return types.String(strings.TrimSpace(string(v)))
				},
			},
		),
	}
)

func ReadProgramOptions(reg ref.TypeRegistry) []cel.ProgramOption {
	allProgramOpitons := []cel.ProgramOption{
		cel.Functions(
			&functions.Overload{
				Operator: "string_submatch_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					var (
						resultMap = make(map[string]string)
					)

					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to submatch", lhs.Type())
					}
					v2, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to submatch", rhs.Type())
					}

					// re := regexp2.MustCompile(string(v1), regexp2.RE2)
					// matches, err := re.FindStringMatch(string(v2))
					// for err == nil && matches != nil {
					// 	gps := matches.Groups()
					// 	for n, gp := range gps {
					// 		if n == 0 {
					// 			continue
					// 		}
					// 		resultMap[gp.Name] += matches.GroupByName(gp.Name).String() + ";"
					// 	}
					// 	matches, err = re.FindNextMatch(matches)
					// }

					// for k, v := range resultMap {
					// 	resultMap[k] = strings.TrimSuffix(v, ";")
					// }

					re := regexp2.MustCompile(string(v1), regexp2.RE2)
					if m, _ := re.FindStringMatch(string(v2)); m != nil {
						gps := m.Groups()
						for n, gp := range gps {
							if n == 0 {
								continue
							}
							resultMap[gp.Name] = gp.String()
						}
					}

					return types.NewStringStringMap(reg, resultMap)
				},
			},
			&functions.Overload{
				Operator: "string_bsubmatch_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					var (
						resultMap = make(map[string]string)
					)

					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bsubmatch", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bsubmatch", rhs.Type())
					}

					// re := regexp2.MustCompile(string(v1), regexp2.RE2)
					// matches, err := re.FindStringMatch(string([]byte(v2)))
					// for err == nil && matches != nil {
					// 	gps := matches.Groups()
					// 	for n, gp := range gps {
					// 		if n == 0 {
					// 			continue
					// 		}
					// 		fmt.Printf("%s Value: %s\n", gp.Name, matches.GroupByName(gp.Name).String())
					// 		resultMap[gp.Name] += matches.GroupByName(gp.Name).String() + ";"
					// 	}
					// 	matches, err = re.FindNextMatch(matches)
					// }

					// for k, v := range resultMap {
					// 	resultMap[k] = strings.TrimSuffix(v, ";")
					// }

					re := regexp2.MustCompile(string(v1), regexp2.RE2)
					raw := string([]byte(v2))
					m, _ := re.FindStringMatch(raw)

					if m != nil {
						gps := m.Groups()
						for n, gp := range gps {
							if n == 0 {
								continue
							}
							resultMap[gp.Name] = gp.String()
						}
					}

					return types.NewStringStringMap(reg, resultMap)
				},
			},
		),
	}
	allProgramOpitons = append(allProgramOpitons, NewProgramOptions...)
	return allProgramOpitons
}

// func reverseCheck(r *proto.Reverse, timeout int64) bool {
// 	if r == nil || (len(r.Domain) == 0 && len(r.Ip) == 0) {
// 		return false
// 	}

// 	time.Sleep(time.Second * time.Duration(timeout))

// 	// 使用反连平台优先权逻辑如下：
// 	// 自建eye反连平台 > ceye反连平台 > eyes.sh反连平台
// 	// @edit 2021.11.29 21:50
// 	// 关联代码 checker.go line-345
// 	// sub := strings.Split(r.Domain, ".")[0]
// 	// if config.ReverseEyeShLive && config.ReverseEyeHost != "eyes.sh" {
// 	// 	// 自建eye反连平台
// 	// 	domain := strings.Split(r.Domain, ".")[1]
// 	// 	if !eyeshDnsCheck(domain, sub) {
// 	// 		return eyesWebCheck(domain, sub)
// 	// 	}
// 	// 	return true

// 	// } else if config.ReverseCeyeLive {
// 	// 	// ceye反连平台
// 	// 	return ceyeioCheck(sub)

// 	// } else if config.ReverseEyeShLive {
// 	// 	// eyes.sh反连平台
// 	// 	domain := strings.Split(r.Domain, ".")[1]
// 	// 	if !eyeshDnsCheck(domain, sub) {
// 	// 		return eyesWebCheck(domain, sub)
// 	// 	}
// 	// 	return true
// 	// }

// 	return false
// }

// func eyeshDnsCheck(domain, sub string) bool {
// 	urlStr := fmt.Sprintf("http://%s/api/dns/%s/%s/?token=%s", config.ReverseEyeHost, domain, sub, config.ReverseEyeToken)
// 	resp, err := retryhttpclient.ReverseGet(urlStr)
// 	if err != nil {
// 		return false
// 	}

// 	if bytes.Contains(resp, []byte("True")) {
// 		return true
// 	}

// 	return false
// }

// func eyesWebCheck(domain, sub string) bool {
// 	urlStr := fmt.Sprintf("http://%s/api/web/%s/%s/?token=%s", config.ReverseEyeHost, domain, sub, config.ReverseEyeToken)
// 	resp, err := retryhttpclient.ReverseGet(urlStr)
// 	if err != nil {
// 		return false
// 	}

// 	if bytes.Contains(resp, []byte("True")) {
// 		return true
// 	}

// 	return false
// }

// func ceyeioCheck(sub string) bool {
// 	// urlStr := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns&filter=%s", config.ReverseCeyeApiKey, sub)
// 	// 解决 &filter=xxxx 经常显示 500 问题导致漏报问题 @2024/01/06
// 	urlStr := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns", config.ReverseCeyeApiKey)
// 	resp, err := retryhttpclient.ReverseGet(urlStr)
// 	if err != nil {
// 		return false
// 	}
// 	if strings.Contains(strings.ToLower(string(resp)), strings.ToLower(sub+".")) {
// 		return true
// 	}

// 	return false
// }

func oobCheck(oob *proto.OOB, filterType string, timeout int64) bool {
	if oob == nil || OOB == nil || !OOBAlive || len(oob.Filter) == 0 {
		return false
	}

	if len(filterType) == 0 {
		filterType = oobadapter.DnslogcnDNS
	}

	if timeout == 0 {
		timeout = 3
	}

	time.Sleep(time.Second * time.Duration(timeout))

	result := OOB.ValidateResult(oobadapter.ValidateParams{
		Filter:     oob.Filter,
		FilterType: filterType,
	})

	return result.IsVaild
}

// func jndiCheck(reverse *proto.Reverse, timeout int64) bool {
// 	// if len(config.ReverseJndi) == 0 && len(config.ReverseApiPort) == 0 {
// 	// 	return false
// 	// }

// 	// if !config.ReverseJndiLive {
// 	// 	return false
// 	// }

// 	// time.Sleep(time.Second * time.Duration(timeout))

// 	// urlStr := fmt.Sprintf("http://%s:%s/?api=%s", reverse.Url.Domain, config.ReverseApiPort, reverse.Url.Path[1:])

// 	// resp, err := retryhttpclient.ReverseGet(urlStr)
// 	// if err != nil {
// 	// 	return false
// 	// }

// 	// if strings.Contains(string(resp), "yes") {

// 	// 	return true
// 	// }

// 	return false
// }
