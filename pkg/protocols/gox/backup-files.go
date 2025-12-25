package gox

import (
	"bytes"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/remeh/sizedwaitgroup"
	"github.com/zan8in/afrog/v3/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/gologger"
	iputil "github.com/zan8in/pins/ip"
	urlutil "github.com/zan8in/pins/url"
)

var (
	filenames = []string{
		"{{FQDN}}",            // www.example.com
		"{{RDN}}",             // example.com
		"{{DN}}",              // example
		"{{SD}}",              // www
		"{{date_time('%Y')}}", // 2023
		"backup",
		"bak",
		"bin",
		"old",
		"db",
		"data",
		"database",
		"dump",
		"sql",
		"index",
		"conf",
		"conf/conf",
		"config",
		"admin",
		"upload",
		"package",
		"temp",
		"tmp",
		"ROOT", // tomcat
		"wwwroot",
		"webroot",
		"htdocs",
		"www",
		"web",
		"public",
		"pc",
		"website",
		"test",
		"release",
		"Release",
	}
	exts = []string{
		"zip",
		"7z",
		"rar",
		"tar.gz",
		"tgz",
		// "war",
		"db",
		// "sqlite",
		// "sqlitedb",
		"sql",
		// "sql.gz",
		// "sql.zip",
	}

	csize = 20

	maxSize = 4096

	timeout = 30 * time.Second
)

func uniqueStringsPreserveOrder(input []string) []string {
	seen := make(map[string]struct{}, len(input))
	output := make([]string, 0, len(input))
	for _, v := range input {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		output = append(output, v)
	}
	return output
}

func getBaseTargets(target string) []string {
	target = strings.TrimRight(target, "/")
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return []string{target}
	}
	root := u.Scheme + "://" + u.Host
	return uniqueStringsPreserveOrder([]string{target, root})
}

func joinURL(base string, path string) string {
	base = strings.TrimRight(base, "/")
	path = strings.TrimLeft(path, "/")
	if path == "" {
		return base
	}
	return base + "/" + path
}

func getFilenames(target string) []string {
	defer func() {
		if r := recover(); r != nil {
			gologger.Error().Msgf("[backup_files:getFilenames] error: %v", r)
		}
	}()

	result := []string{}

	for _, v := range filenames {
		if v == "{{FQDN}}" {
			if d, err := urlutil.Hostname(target); err == nil {
				result = append(result, d)
			}
		} else if v == "{{RDN}}" {
			if d, err := urlutil.Domain(target); err == nil && !iputil.IsIP(d) {
				result = append(result, d)
			}
		} else if v == "{{DN}}" {
			if d, err := urlutil.Domain(target); err == nil && !iputil.IsIP(d) {
				result = append(result, strings.Split(d, ".")[0])
			}
		} else if v == "{{SD}}" {
			if d, err := urlutil.Domain(target); err == nil && !iputil.IsIP(d) {
				sd := strings.Split(d, ".")
				if len(sd) > 2 {
					result = append(result, sd[0])
				}
			}
		} else if v == "{{date_time('%Y')}}" {
			y, _ := strconv.Atoi(time.Now().Format("2006"))

			result = append(result, strconv.Itoa(y))
			result = append(result, strconv.Itoa(y-1))
			result = append(result, strconv.Itoa(y-2))
			result = append(result, strconv.Itoa(y-3))
			result = append(result, strconv.Itoa(y-4))
			result = append(result, strconv.Itoa(y-5))
		} else {
			result = append(result, v)
		}
	}

	return uniqueStringsPreserveOrder(result)
}

func processData(target string, shouldStop chan string, found *atomic.Bool) {
	defer func() {
		if r := recover(); r != nil {
			gologger.Error().Msgf("[backup_files:processData] error: %v", r)
		}
	}()

	if found.Load() {
		return
	}
	body := GetBackupFile(target)
	if len(body) > 0 {
		if found.CompareAndSwap(false, true) {
			select {
			case shouldStop <- target:
			default:
			}
		}
	}

}

func backup_files(target string, variableMap map[string]any) error {
	defer func() {
		if r := recover(); r != nil {
			gologger.Error().Msgf("[backup_files] error: %v", r)
		}
	}()

	shouldStop := make(chan string, 1)
	found := &atomic.Bool{}

	baseTargets := getBaseTargets(target)
	filenames := getFilenames(target)
	exts := uniqueStringsPreserveOrder(exts)

	workerCount := csize
	if rl := retryhttpclient.GetReqLimitPerTarget(); rl > 0 && rl < workerCount {
		workerCount = rl
	}
	if workerCount <= 0 {
		workerCount = 1
	}
	swg := sizedwaitgroup.New(workerCount)
	for _, baseTarget := range baseTargets {
		for _, filename := range filenames {
			for _, ext := range exts {
				if found.Load() {
					break
				}
				swg.Add()
				go func(baseTarget, filename, ext string) {
					defer swg.Done()
					processData(joinURL(baseTarget, filename+"."+ext), shouldStop, found)
				}(baseTarget, filename, ext)
			}
			if found.Load() {
				break
			}
		}
		if found.Load() {
			break
		}
	}
	go func() {
		swg.Wait()
		close(shouldStop)
	}()

	resultUrl := <-shouldStop
	if len(resultUrl) > 0 {
		_, err := DoHTTPWithTimeout(timeout, http.MethodGet, resultUrl, nil, nil, false, variableMap)
		if err != nil {
			return err
		}
		setTarget(target, variableMap)
		setFullTarget(resultUrl, variableMap)

		return nil
	}

	return nil

}

func init() {
	funcMap["backup-files"] = backup_files
}

func GetBackupFile(target string) string {
	defer func() {
		if r := recover(); r != nil {
			gologger.Error().Msgf("[backup_files:GetBackupFile] error: %v", r)
		}
	}()

	data, status, _, err := FetchLimited(http.MethodGet, target, nil, nil, false, timeout, int64(maxSize), nil)
	// fmt.Println("err: ", err)
	// fmt.Println("status: ", status)
	// fmt.Println("data: ", string(data))
	if err != nil {
		return ""
	}
	if status != 200 && status != 206 {
		return ""
	}

	dd := data
	if len(dd) == 0 {
		return ""
	}

	// 7z 压缩包文件头: 37 7A BC AF 27 1C ("7z\xBC\xAF\x27\x1C")
	if bytes.HasPrefix(dd, []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}) {
		return target
	}
	// bzip2 文件头: "BZh"，流内也常见 "1AY&SY" (31 41 59 26 53 59)
	if bytes.HasPrefix(dd, []byte("BZh")) || bytes.Contains(dd, []byte{0x31, 0x41, 0x59, 0x26, 0x53, 0x59}) {
		return target
	}
	// gzip 文件头: 1F 8B
	if bytes.HasPrefix(dd, []byte{0x1F, 0x8B}) {
		return target
	}
	// rar 文件头: "Rar!\x1A\x07\x00" 或 "Rar!\x1A\x07\x01\x00"
	if bytes.HasPrefix(dd, []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}) || bytes.HasPrefix(dd, []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}) {
		return target
	}
	// xz 文件头: FD 37 7A 58 5A 00 00
	if bytes.HasPrefix(dd, []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00}) {
		return target
	}
	// zip 文件头: "PK\x03\x04"（本地文件头）/"PK\x05\x06"（空归档结束）/"PK\x07\x08"（数据描述符）
	if bytes.HasPrefix(dd, []byte{0x50, 0x4B, 0x03, 0x04}) || bytes.HasPrefix(dd, []byte{0x50, 0x4B, 0x05, 0x06}) || bytes.HasPrefix(dd, []byte{0x50, 0x4B, 0x07, 0x08}) {
		return target
	}
	// SQLite 数据库文件头: "SQLite format 3\x00"
	if bytes.HasPrefix(dd, []byte("SQLite format 3\x00")) {
		return target
	}
	// tar 归档标识: header 偏移 257 开始的 "ustar"
	if len(dd) >= 262 && bytes.Equal(dd[257:262], []byte("ustar")) {
		return target
	}
	// SQL dump 特征: 包含 CREATE TABLE / INSERT INTO 等，且不是 HTML 页面
	if (bytes.Contains(dd, []byte("CREATE TABLE")) || bytes.Contains(dd, []byte("create table")) ||
		bytes.Contains(dd, []byte("INSERT INTO")) || bytes.Contains(dd, []byte("insert into"))) &&
		!(bytes.Contains(dd, []byte("<html")) || bytes.Contains(dd, []byte("<HTML")) ||
			bytes.Contains(dd, []byte("<!DOCTYPE")) || bytes.Contains(dd, []byte("<!doctype"))) {
		return target
	}

	return ""
}
