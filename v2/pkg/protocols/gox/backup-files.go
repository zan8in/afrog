package gox

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/remeh/sizedwaitgroup"
	"github.com/zan8in/afrog/v2/pkg/protocols/http/retryhttpclient"
	"github.com/zan8in/afrog/v2/pkg/utils"
	iputil "github.com/zan8in/pins/ip"
	urlutil "github.com/zan8in/pins/url"
	"github.com/zan8in/retryablehttp"
)

var (
	filenames = []string{
		"{{FQDN}}",            // www.example.com
		"{{RDN}}",             // example.com
		"{{DN}}",              // example
		"{{SD}}",              // www
		"{{date_time('%Y')}}", // 2023
		"ROOT",                // tomcat
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
		"backup",
		"bin",
		"bak",
		"old",
		"Release",
	}
	exts = []string{
		"7z",
		"bz2",
		"gz",
		"lz",
		"rar",
		"tar.gz",
		"tar.bz2",
		"xz",
		"zip",
		"z",
		"tar.z",
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
		"war",
	}

	binaries = []string{
		"377ABCAF271C",                     // 7z
		"314159265359",                     // bz2
		"53514C69746520666F726D6174203300", // SQLite format 3.
		"1F8B",                             // gz tar.gz
		"526172211A0700",                   // rar RAR archive version 1.50
		"526172211A070100",                 // rar RAR archive version 5.0
		"FD377A585A0000",                   // xz tar.xz
		"1F9D",                             // z tar.z
		"1FA0",                             // z tar.z
		"4C5A4950",                         // lz
		"504B0304",                         // zip
	}

	csize = 50

	maxSize = 500

	timeout = 10 * time.Second

	respBody string
)

func getFilenames(target string) []string {
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

	return result
}

func processData(target string, wg *sizedwaitgroup.SizedWaitGroup, shouldStop chan string) {
	wg.Add()
	defer wg.Done()

	body := GetBackupFile(target)
	if len(body) > 0 {
		respBody = body
		shouldStop <- target
	}

}

func backup_files(target string, variableMap map[string]any) error {
	setRequest(target, variableMap)

	shouldStop := make(chan string)

	filenames := getFilenames(target)

	swg := sizedwaitgroup.New(csize)
	go func() {
		for _, filename := range filenames {
			for _, ext := range exts {
				go func(filename, ext string) {
					processData(target+"/"+filename+"."+ext, &swg, shouldStop)
				}(filename, ext)
			}
		}

		go func() {
			swg.Wait()
			close(shouldStop)
		}()
	}()

	select {
	case resultUrl := <-shouldStop:
		if len(resultUrl) > 0 {
			setResponse(respBody+"\r\n\r\nbackup-file-url: "+resultUrl, variableMap)
			setRequest(resultUrl, variableMap)
			setTarget(target, variableMap)
			setFullTarget(resultUrl, variableMap)

			return nil
		}

	}

	return fmt.Errorf("err")

}

func init() {
	funcMap["backup-files"] = backup_files
}

func GetBackupFile(target string) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return ""
	}

	resp := &http.Response{}
	resp, err = retryhttpclient.RtryNoRedirect.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}

	reader := io.LimitReader(resp.Body, int64(maxSize))
	respBody, err := io.ReadAll(reader)
	if err != nil {
		resp.Body.Close()
		return ""
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	hexBody := strings.ToUpper(string(utils.HexEncode(string(respBody))))

	for _, r := range binaries {
		if strings.Contains(hexBody, r) {
			return hexBody
		}
	}

	return ""
}
