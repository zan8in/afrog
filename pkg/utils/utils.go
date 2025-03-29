package utils

import (
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zan8in/afrog/v3/pkg/proto"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

func IsBlank(value string) bool {
	return strings.TrimSpace(value) == ""
}

func IsNotBlank(value string) bool {
	return !IsBlank(value)
}

// IsURL tests a string to determine if it is a well-structured url or not.
func IsURL(input string) bool {
	_, err := url.ParseRequestURI(input)
	if err != nil {
		return false
	}

	u, err := url.Parse(input)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}

// ReadFromPathOrURL reads and returns the contents of a file or url.
func ReadFromPathOrURL(templatePath string) (data []byte, err error) {
	if IsURL(templatePath) {
		resp, err := http.Get(templatePath)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		data, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
	} else {
		f, err := os.Open(templatePath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		data, err = io.ReadAll(f)
		if err != nil {
			return nil, err
		}
	}
	return
}

// StringSliceContains checks if a string slice contains a string.
func StringSliceContains(slice []string, item string) bool {
	for _, i := range slice {
		if strings.EqualFold(i, item) {
			return true
		}
	}
	return false
}

func UrlTypeToString(u *proto.UrlType) string {
	var buf strings.Builder
	if u.Scheme != "" {
		buf.WriteString(u.Scheme)
		buf.WriteByte(':')
	}
	if u.Scheme != "" || u.Host != "" {
		if u.Host != "" || u.Path != "" {
			buf.WriteString("//")
		}
		if h := u.Host; h != "" {
			buf.WriteString(u.Host)
		}
	}
	path := u.Path
	if path != "" && path[0] != '/' && u.Host != "" {
		buf.WriteByte('/')
	}
	if buf.Len() == 0 {
		if i := strings.IndexByte(path, ':'); i > -1 && strings.IndexByte(path[:i], '/') == -1 {
			buf.WriteString("./")
		}
	}
	buf.WriteString(path)

	if u.Query != "" {
		buf.WriteByte('?')
		buf.WriteString(u.Query)
	}
	if u.Fragment != "" {
		buf.WriteByte('#')
		buf.WriteString(u.Fragment)
	}
	return buf.String()
}

func ParseUrl(u *url.URL) *proto.UrlType {
	nu := &proto.UrlType{}
	nu.Scheme = u.Scheme
	nu.Domain = u.Hostname()
	nu.Host = u.Host
	nu.Port = u.Port()
	nu.Path = u.EscapedPath()
	nu.Query = u.RawQuery
	nu.Fragment = u.Fragment
	return nu
}

func ReverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func IsSeverityMatchingCvssScore(severity string, score float64) string {
	if score == 0.0 {
		return ""
	}
	var expected string

	if score >= 0.1 && score <= 3.9 {
		expected = "low"
	} else if score >= 4.0 && score <= 6.9 {
		expected = "medium"
	} else if score >= 7.0 && score <= 8.9 {
		expected = "high"
	} else if score >= 9.0 && score <= 10.0 {
		expected = "critical"
	}
	if expected != "" && expected != severity {
		return expected
	}
	return ""
}

func GetNowDateTime() string {
	now := time.Now()
	return now.Format("01-02 15:04:05")
}

func GetNowDate() string {
	now := time.Now()
	return now.Format("2006-01-02")
}

func GetNowDateTimeReportName() string {
	now := time.Now()
	return now.Format("20060102-150405")
}

func GetNumberText(number int) string {
	num := strconv.Itoa(number)
	if len(num) == 1 {
		num = "00" + num
	} else if len(num) == 2 {
		num = "0" + num
	}
	return num
}

// 16进制解码
func HexDecode(s string) []byte {
	dst := make([]byte, hex.DecodedLen(len(s))) //申请一个切片, 指明大小. 必须使用hex.DecodedLen
	n, err := hex.Decode(dst, []byte(s))        //进制转换, src->dst
	if err != nil {
		log.Fatal(err)
		return nil
	}
	return dst[:n] //返回0:n的数据.
}

// 字符串转为16进制
func HexEncode(s string) []byte {
	dst := make([]byte, hex.EncodedLen(len(s))) //申请一个切片, 指明大小. 必须使用hex.EncodedLen
	n := hex.Encode(dst, []byte(s))             //字节流转化成16进制
	return dst[:n]
}

// 字符串转 utf 8
func Str2UTF8(str string) string {
	if len(str) == 0 {
		return ""
	}
	if !utf8.ValidString(str) {
		utf8Bytes, _ := io.ReadAll(transform.NewReader(
			strings.NewReader(str),
			simplifiedchinese.GBK.NewDecoder(),
		))
		return string(utf8Bytes)
	}
	return str
}

// 增强版URL特征提取
func ExtractHost(target string) string {
	// 预处理特殊格式
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}

	// 处理没有协议的URL
	if !strings.Contains(target, "://") {
		target = "tcp://" + target
	}

	u, err := url.Parse(target)
	if err != nil {
		// 降级处理非法URL
		if strings.Contains(target, ":") {
			return strings.Split(target, ":")[0]
		}
		return target
	}

	// 处理包含用户信息的host
	host := u.Hostname()

	// 处理IPv6地址
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}

	return host
}

// 新增函数：清理非法文件名字符
func SanitizeFilename(s string) string {
	// 保留常见安全字符：字母、数字、下划线、连字符、点号
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-' || r == '_' || r == '.':
			return r
		default:
			return '_'
		}
	}, s)

	// 限制最大长度（保留扩展名部分的完整性）
	maxLength := 50
	if len(s) > maxLength {
		s = s[:maxLength]
	}

	// 去除前后多余的点号
	s = strings.Trim(s, ".")

	return s
}

func IsUnicodeSupported() bool {
	// Windows 特殊处理
	if runtime.GOOS == "windows" {
		// 检测是否为 Windows Terminal 或配置了 UTF-8 的终端
		if os.Getenv("WT_SESSION") != "" || os.Getenv("ConEmuANSI") == "ON" {
			return true
		}
		return false
	}
	// Linux/macOS 默认支持
	return true
}
