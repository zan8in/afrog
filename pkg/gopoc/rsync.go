package gopoc

import (
	"bytes"
	"errors"

	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/proto"
	"github.com/zan8in/afrog/pkg/utils"
)

var (
	rsyncPort = "873"
	// rsyncUnAuthName = "rsync-unauth"
	rsyncUnAuthName = ""
)

func rsyncUnAuth(args *GoPocArgs) (Result, error) {
	poc := poc.Poc{
		Id: rsyncUnAuthName,
		Info: poc.Info{
			Name:        "Rsync 未授权访问",
			Author:      "zan8in",
			Severity:    "critical",
			Description: "Rsync为Linux下实现远程同步功能的软件，能同步更新两处计算机的文件及目录。在同步文件时，可以保持源文件的权限、时间、软硬链接等附加信息。常被用于在内网进行源代码的分发及同步更新，因此使用人群多为开发人员；而开发人员安全意识薄弱、安全技能欠缺往往是导致rsync出现相关漏洞的根源。rsync默认配置文件为/etc/rsyncd.conf，常驻模式启动命令rsync –daemon，启动成功后默认监听于TCP端口873，可通过rsync-daemon及ssh两种方式进行认证",
			Reference: []string{
				"http://wiki.peiqi.tech/redteam/vulnerability/unauthorized/Rsync%20873%E7%AB%AF%E5%8F%A3.html",
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
	// 	payload := []byte("info\r\n")

	// 	resp, err := utils.Tcp(addr, payload)
	// 	if err != nil {
	// 		return result, err
	// 	}

	// 	if bytes.Contains(resp, []byte("@RSYNCD")) {
	// 		result.IsVul = true
	// 		url := proto.UrlType{Host: addr, Port: args.Port}
	// 		result.SetAllPocResult(true, &url, payload, resp)
	// 		return result, nil
	// 	}
	// }

	addr := args.Host + ":" + rsyncPort
	payload := []byte("info\r\n")

	resp, err := utils.Tcp(addr, payload)
	if err != nil {
		return result, err
	}

	if bytes.Contains(resp, []byte("@RSYNCD")) {
		result.IsVul = true
		url := proto.UrlType{Host: addr, Port: rsyncPort}
		result.SetAllPocResult(true, &url, payload, resp)
		return result, nil
	}

	return result, errors.New("check result: no vul")
}

func init() {
	GoPocRegister(rsyncUnAuthName, rsyncUnAuth)
}
