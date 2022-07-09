package gopoc

import (
	"bytes"
	"errors"

	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/proto"
	"github.com/zan8in/afrog/pkg/utils"
)

var (
	memcachePort       = "11211"
	memcacheUnAuthName = "memcache-unauth"
)

func memcacheUnAuth(args *GoPocArgs) (Result, error) {
	poc := poc.Poc{
		Id: memcacheUnAuthName,
		Info: poc.Info{
			Name:        "Memcache 未授权访问",
			Author:      "zan8in",
			Severity:    "critical",
			Description: "Memcached是一套分布式的高速缓存系统。它以Key-Value（键值对）形式将数据存储在内存中，由于memcached安全设计缺陷，客户端连接memcached服务器后 无需认证就 可读取、修改服务器缓存内容。",
			Reference: []string{
				"http://wiki.peiqi.tech/redteam/vulnerability/unauthorized/Memcache%2011211%E7%AB%AF%E5%8F%A3.html",
			},
		},
	}
	args.SetPocInfo(poc)
	result := Result{Gpa: args, IsVul: false}

	if len(args.Host) == 0 {
		return result, errors.New("no host")
	}

	if len(args.Port) > 0 && args.Port != "80" && args.Port != "443" {
		addr := args.Host + ":" + args.Port
		payload := []byte("stats\n")

		resp, err := utils.Tcp(addr, payload)
		if err != nil {
			return result, err
		}

		if bytes.Contains(resp, []byte("STAT pid")) {
			result.IsVul = true
			url := proto.UrlType{Host: addr, Port: args.Port}
			result.SetAllPocResult(true, &url, payload, resp)
			return result, nil
		}
	}

	addr := args.Host + ":" + memcachePort
	payload := []byte("stats\n")

	resp, err := utils.Tcp(addr, payload)
	if err != nil {
		return result, err
	}

	if bytes.Contains(resp, []byte("STAT pid")) {
		result.IsVul = true
		url := proto.UrlType{Host: addr, Port: memcachePort}
		result.SetAllPocResult(true, &url, payload, resp)
		return result, nil
	}

	return result, errors.New("check result: no vul")
}

func init() {
	GoPocRegister(memcacheUnAuthName, memcacheUnAuth)
}
