package poc

import (
	"github.com/zan8in/afrog/utils"
	"gopkg.in/yaml.v2"
)

// https://docs.xray.cool/#/guide/poc/v2

type Sets map[string]interface{}
type Poc struct {
	Name       string   `yaml:"name"`      //  脚本名称 poc-yaml-example-com
	Transport  string   `yaml:"transport"` // 传输方式，该字段用于指定发送数据包的协议，该字段用于指定发送数据包的协议:①tcp ②udp ③http
	Set        Sets     `yaml:"set"`       // 全局变量定义，该字段用于定义全局变量。比如随机数，反连平台等
	Payloads   Payloads `yaml:"payloads"`
	Rules      Rules    `yaml:"rules"`
	Expression string   `yaml:"expression"`
	Detail     Detail   `yaml:"detail"`
}

type Payloadss = map[string]Sets
type Payloads struct {
	Continue bool      `yaml:"continue"`
	Payloads Payloadss `yaml:"payloads"`
}

// 以下是 脚本部分
type Rules map[string]Rule
type Outputs yaml.MapSlice
type Rule struct {
	Request    RuleRequest `yaml:"request"`
	Expression string      `yaml:"expression"`
	Output     Outputs     `yaml:"output"`
}

// http/tcp/udp cache 是否使用缓存的请求，如果该选项为 true，那么如果在一次探测中其它脚本对相同目标发送过相同请求，那么便使用之前缓存的响应，而不发新的数据包
// content 用于tcp/udp请求，请求内容，比如：content: "request"
// read_timeout 用于tcp/udp请求，发送请求之后的读取超时时间（注 实际是一个 int， 但是为了能够变量渲染，设置为 string）
// connection_id 用于tcp/udp请求，连接 id ,同一个连接 id 复用连接(注 不允许用0； cache 为 true 的时候可能会导致请求不会发送，所以如果有特殊需求记得 cache: false)
type RuleRequest struct {
	Cache           bool              `yaml:"cache"`
	Content         string            `yaml:"content"`       // tcp/udp专用
	ReadTimeout     string            `yaml:"read_timeout"`  // tcp/udp专用
	ConnectionId    string            `yaml:"connection_id"` // tcp/udp专用
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	FollowRedirects bool              `yaml:"follow_redirects"`
}

// 以下开始是 信息部分
// 信息部分：主要是用来声明该脚本的一些信息，包括输出内容
type Detail struct {
	Author        string        `yaml:"author"`
	Links         []string      `yaml:"links"`
	Fingerprint   Fingerprint   `yaml:"fingerprint"`
	Vulnerability Vulnerability `yaml:"vulnerability"`
}

// 指纹信息
type Fingerprint struct {
	Infos    []Info   `yaml:"infos"`
	HostInfo HostInfo `yaml:"host_info"`
}

// 指纹信息
type Info struct {
	Id         string `yaml:"id"`         // 长亭指纹库 ID
	Name       string `yaml:"name"`       // 名称
	Version    string `yaml:"version"`    // string 版本号
	Type       string `yaml:"type"`       // string 指纹类型，有以下可选值： operating_system, hardware, system_bin, web_application, dependency
	Confidence int    `yaml:"confidence"` // int 取值范围（1-100）
}

// 主机信息
type HostInfo struct {
	Hostname string `yaml:"hostname"` // 主机信息
}

// 漏洞信息
type Vulnerability struct {
	Id    string `yaml:"id"`    // 长亭楼漏洞库 ID
	Match string `yaml:"match"` // 证明漏洞存在的一些信息
}

// 以下是 poc 操作函数
// 解析一个poc.yml文件
func ParseYamlFile(pocyml string) (*Poc, error) {
	var poc *Poc
	yamlFile, err := utils.ReadFromFile(pocyml)
	if err != nil {
		return poc, err
	}
	err = yaml.Unmarshal(yamlFile, &poc)
	if err != nil {
		return poc, err
	}
	return poc, nil
}
