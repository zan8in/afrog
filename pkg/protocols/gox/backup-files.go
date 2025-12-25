package gox

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/remeh/sizedwaitgroup"
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
		"old",
		"ROOT", // tomcat
		"wwwroot",
		"htdocs",
		"www",
		"html",
		"web",
		"webapps",
		"public",
		"public_html",
		"uploads",
		"website",
		"api",
		"test",
		"app",
		"bin",
		"release",
		"Release",
	}
	exts = []string{
		"zip",
		"7z",
		"rar",
		"tar.gz",
		"bz2",
		"gz",
		"lz",
		"tar.bz2",
		"xz",
		"tar.z",
		"z",
		"war",
		"db",
		"sqlite",
		"sqlitedb",
		"sql.7z",
		"sql.bz2",
		"sql.gz",
		"sql.lz",
		"sql.rar",
		"sql.tar.gz",
		"sql.xz",
		"sql.zip",
		"sql.z",
		"sql.tar.z",
	}

	csize = 20

	maxSize = 500

	timeout = 10 * time.Second
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

	filenames := getFilenames(target)
	exts := uniqueStringsPreserveOrder(exts)

	swg := sizedwaitgroup.New(csize)
	for _, filename := range filenames {
		for _, ext := range exts {
			if found.Load() {
				break
			}
			swg.Add()
			go func(filename, ext string) {
				defer swg.Done()
				processData(target+"/"+filename+"."+ext, shouldStop, found)
			}(filename, ext)
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

	return fmt.Errorf("err")

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
	if err != nil {
		return ""
	}
	if status != 200 {
		return ""
	}

	dd := data
	if len(dd) == 0 {
		return ""
	}

	if bytes.HasPrefix(dd, []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}) {
		return target
	}
	if bytes.HasPrefix(dd, []byte("BZh")) || bytes.Contains(dd, []byte{0x31, 0x41, 0x59, 0x26, 0x53, 0x59}) {
		return target
	}
	if bytes.HasPrefix(dd, []byte{0x1F, 0x8B}) {
		return target
	}
	if bytes.HasPrefix(dd, []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}) || bytes.HasPrefix(dd, []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}) {
		return target
	}
	if bytes.HasPrefix(dd, []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00}) {
		return target
	}
	if bytes.HasPrefix(dd, []byte{0x1F, 0x9D}) || bytes.HasPrefix(dd, []byte{0x1F, 0xA0}) {
		return target
	}
	if bytes.HasPrefix(dd, []byte("LZIP")) {
		return target
	}
	if bytes.HasPrefix(dd, []byte{0x50, 0x4B, 0x03, 0x04}) || bytes.HasPrefix(dd, []byte{0x50, 0x4B, 0x05, 0x06}) || bytes.HasPrefix(dd, []byte{0x50, 0x4B, 0x07, 0x08}) {
		return target
	}
	if bytes.HasPrefix(dd, []byte("SQLite format 3\x00")) {
		return target
	}

	return ""
}
