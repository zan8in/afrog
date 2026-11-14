// Package ref 定义 Agent-Native 架构里的全局引用与内容寻址规则。
//
// 设计约束：同一个 canonical 值在任何节点、任何进程、任何任务里都必须得到同一个
// ID。这样 Agent 重试、集群多节点回传、跨任务复扫时天然可比较、可去重，不需要
// 再引入一套中心化的 ID 分配服务。
package ref

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Kind 是可引用对象的种类。
type Kind string

const (
	KindAsset       Kind = "asset"
	KindEndpoint    Kind = "endpoint"
	KindParam       Kind = "param"
	KindPoc         Kind = "poc"
	KindObservation Kind = "obs"
	KindEvidence    Kind = "evd"
	KindFinding     Kind = "fnd"
)

// shortLen 是内容寻址后缀的长度。128 bit 摘要截到 80 bit，足够避免碰撞，
// 又能让 ID 在日志与 UI 里保持可读。
const shortLen = 16

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Digest 返回 canonical 的 sha256 十六进制摘要，带算法前缀，便于将来换算法。
func Digest(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Make 生成内容寻址 ID：<kind>_<base32(sha256(canonical))[:16]>。
func Make(kind Kind, canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	enc := strings.ToLower(b32.EncodeToString(sum[:]))
	if len(enc) > shortLen {
		enc = enc[:shortLen]
	}
	return string(kind) + "_" + enc
}

// NormalizeEndpoint 把 URL 归一化成 scheme://host[:port]/path。
//
// 只用于生成稳定 ID，不改变实际请求：小写 scheme/host、去掉默认端口、丢弃
// query / fragment / userinfo，并去掉路径末尾多余的斜杠（根路径保留 "/"）。
func NormalizeEndpoint(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if scheme == "" || host == "" {
		return "", fmt.Errorf("ref: not an absolute url: %q", raw)
	}

	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	hostport := host
	if port != "" {
		hostport = net.JoinHostPort(host, port)
	}

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}
	if path == "" {
		path = "/"
	}
	return scheme + "://" + hostport + path, nil
}

// Endpoint 返回一个端点的内容寻址 ID；入参不是绝对 URL 时返回空串。
func Endpoint(raw string) string {
	canonical, err := NormalizeEndpoint(raw)
	if err != nil {
		return ""
	}
	return Make(KindEndpoint, canonical)
}
