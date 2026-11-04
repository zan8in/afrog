package recon

import (
	"net/url"
	"strings"
)

// 本文件是 recon 规则的校验器与语境钩子。它们只回答一个问题：这条命中是「真的资产
// 线索」还是「随手就能撞上的噪声」。信息收集的噪声量极大，这一层是精度的关键。

// noiseHosts 是「到处都出现、却没有资产价值」的域名（XML 命名空间、规范链接、
// 语法定义等）。它们会在几乎每个 HTML/SVG/XML 响应里出现，必须整体剔除。
var noiseHosts = map[string]struct{}{
	"w3.org":              {},
	"www.w3.org":          {},
	"ns.adobe.com":        {},
	"purl.org":            {},
	"schema.org":          {},
	"xmlsoap.org":         {},
	"schemas.xmlsoap.org": {},
	"openoffice.org":      {},
	"xmlns.com":           {},
	"ogp.me":              {},
	"localhost":           {},
	"example.com":         {},
	"example.org":         {},
	"example.net":         {},
}

// noiseHostSuffixes 是按后缀剔除的噪声域名（覆盖 www.w3.org 之类任意子域）。
var noiseHostSuffixes = []string{".w3.org"}

// staticAssetExts 是静态资源后缀。指向它们的 URL/路径对信息收集没有价值，
// 且数量极大（前端产物里满是 bundle.js / sprite.png），必须剔除。
var staticAssetExts = map[string]struct{}{
	"js": {}, "mjs": {}, "cjs": {}, "css": {}, "map": {},
	"png": {}, "jpg": {}, "jpeg": {}, "gif": {}, "svg": {}, "webp": {}, "bmp": {}, "ico": {},
	"woff": {}, "woff2": {}, "ttf": {}, "otf": {}, "eot": {},
	"mp3": {}, "mp4": {}, "webm": {}, "wav": {}, "ogg": {}, "avi": {}, "mov": {},
}

// validEmail 校验邮箱：结构合法、域名有后缀、且不在噪声名单内。
func validEmail(v string) bool {
	at := strings.LastIndexByte(v, '@')
	if at <= 0 || at == len(v)-1 {
		return false
	}
	local := v[:at]
	domain := strings.ToLower(v[at+1:])
	if len(local) > 64 || len(domain) > 253 {
		return false
	}
	// 本地部分必须至少含一个字母或数字，排除 `----@x.com` 这类纯符号噪声。
	if !hasAlphaNum(local) {
		return false
	}
	if strings.Contains(domain, "..") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	if _, bad := noiseHosts[domain]; bad {
		return false
	}
	for _, s := range noiseHostSuffixes {
		if strings.HasSuffix(domain, s) {
			return false
		}
	}
	// `foo@2x.png` 这类「域名其实是个文件名」的情况：交给静态资源后缀拦截。
	if isStaticAsset(domain) {
		return false
	}
	return true
}

// validURL 校验绝对 URL：主机合法、非噪声域名、且不指向静态资源。
func validURL(v string) bool {
	u, err := url.Parse(v)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || !strings.Contains(host, ".") {
		return false
	}
	if _, bad := noiseHosts[host]; bad {
		return false
	}
	for _, s := range noiseHostSuffixes {
		if strings.HasSuffix(host, s) {
			return false
		}
	}
	return !isStaticAsset(u.Path)
}

// validAPIPath 校验接口路径：不是静态资源、也不含路径穿越式的乱码。
func validAPIPath(v string) bool {
	if len(v) < 5 { // 至少 /api/ 长度
		return false
	}
	if strings.Contains(v, "..") {
		return false
	}
	return !isStaticAsset(v)
}

// apiPathContext 要求接口关键字（/api、/rest、/graphql）之后是路径边界。
//
// 这是必要的一道闸：正则里关键字后的子路径是可选的，于是 `/apiaries` 会先匹配到
// `/api`。若命中区间的下一个字符仍是字母/数字/下划线，说明它只是更长单词的前缀，
// 应当丢弃。这样既保住了 `/api`（后接边界）又能正确地提取 `/api/v1/users`。
func apiPathContext(content []byte, start, end int) bool {
	if end < 0 || end > len(content) {
		return false
	}
	if end == len(content) {
		return true
	}
	return !isWordByte(content[end])
}

// isStaticAsset 判断路径/域名的最终后缀是否属于静态资源。
func isStaticAsset(p string) bool {
	i := strings.LastIndexByte(p, '.')
	if i < 0 || i == len(p)-1 {
		return false
	}
	ext := strings.ToLower(p[i+1:])
	_, bad := staticAssetExts[ext]
	return bad
}

// hasAlphaNum 判断字符串是否至少含一个 ASCII 字母或数字。
func hasAlphaNum(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			return true
		}
	}
	return false
}

// isWordByte 判定字节是否属于「词内字符」（字母/数字/下划线）。
func isWordByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '_':
		return true
	}
	return false
}
