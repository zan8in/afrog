package gopoc

import (
	"bytes"
	"errors"

	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/proto"
	"github.com/zan8in/afrog/pkg/utils"
)

var (
	redisPort       = "6379"
	redisUnAuthName = "redis-unauth"
)

func redisUnAuth(args *GoPocArgs) (Result, error) {
	poc := poc.Poc{
		Id: redisUnAuthName,
		Info: poc.Info{
			Name:        "Redis 未授权访问",
			Author:      "zan8in",
			Severity:    "critical",
			Description: "Redis因为配置不当，会导致未授权访问，在一定条件成立的情况下，Redis服务器以root身份运行，黑客就能够给root账户写入SSH公钥文件，然后直接通过SSH登录目标受害的服务器，就能够直接提权目标服务器，然后进行一系列的数据增删查改操作，甚至是泄露信息，勒索加密等等，会对日常业务造成恶劣的影响。",
			Reference: []string{
				"https://developer.aliyun.com/article/515894",
			},
		},
	}
	args.SetPocInfo(poc)
	result := Result{Gpa: args, IsVul: false}

	if len(args.Host) == 0 {
		return result, errors.New("no host")
	}

	// if len(args.Port) > 0 && args.Port != "80" && args.Port != "443" {
	// 	addr := args.Host + ":" + args.Port
	// 	payload := []byte("*1\r\n$4\r\ninfo\r\n")

	// 	resp, err := utils.Tcp(addr, payload)
	// 	if err != nil {
	// 		return result, err
	// 	}

	// 	if bytes.Contains(resp, []byte("redis_version")) {
	// 		result.IsVul = true
	// 		url := proto.UrlType{Host: addr, Port: args.Port}
	// 		result.SetAllPocResult(true, &url, payload, resp)
	// 		return result, nil
	// 	}
	// }

	addr := args.Host + ":" + redisPort
	payload := []byte("*1\r\n$4\r\ninfo\r\n")

	resp, err := utils.Tcp(addr, payload)
	if err != nil {
		return result, err
	}

	if bytes.Contains(resp, []byte("redis_version")) {
		result.IsVul = true
		url := proto.UrlType{Host: addr, Port: redisPort}
		result.SetAllPocResult(true, &url, payload, resp)
		return result, nil
	}

	return result, errors.New("check result: no vul")
}

func init() {
	GoPocRegister(redisUnAuthName, redisUnAuth)
}
