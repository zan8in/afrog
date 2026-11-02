package sqli

import (
	"strings"

	"github.com/zan8in/afrog/v3/pkg/passive"
)

// 本文件负责「数据库方言指纹」：在付出时间盲注流量之前，尽量用零成本或已有信息
// 把方言认准，据此收敛时间盲注候选的顺序。目的有两个：
//   - 少花请求：命中方言排前面，本来要试 4 个方言才中，现在第一个就中；
//   - 结论可溯：结果里的 dialect 不再是「试了一圈碰巧成了」，而是有指认依据。
//
// 只调序、不裁剪候选：指纹猜错时最多多花几次请求，而裁剪会直接造成漏报。

// inferDBMSHint 从响应里推断数据库方言，返回方言与依据。
//
// 只采信强信号：数据库报错特征（数据库自己报了名），以及 IIS / ASP.NET 这类与
// SQL Server 强绑定的服务端标识。会话 Cookie、PHP 之类弱信号一律不用——猜错只是
// 浪费一次请求，但把猜测写进证据链是不可接受的。
func inferDBMSHint(res *passive.CapturedResponse) (string, string) {
	if res == nil {
		return "", ""
	}
	if dialect, marker := reportError(res.Body); marker != "" {
		return dialect, "响应出现 " + dialect + " 报错特征「" + marker + "」"
	}
	h := res.Headers
	if h == nil {
		return "", ""
	}
	if strings.Contains(strings.ToLower(h.Get("X-Powered-By")), "asp.net") {
		return "mssql", "X-Powered-By 标示 ASP.NET"
	}
	if srv := strings.TrimSpace(h.Get("Server")); strings.Contains(strings.ToLower(srv), "iis") {
		return "mssql", "Server 标示 " + srv
	}
	return "", ""
}

// orderByDialectHint 把命中方言的候选提到最前，其余保持原有顺序。
func orderByDialectHint(pairs []boolPair, hint string) []boolPair {
	if hint == "" {
		return pairs
	}
	out := make([]boolPair, 0, len(pairs))
	for _, p := range pairs {
		if p.dialect == hint {
			out = append(out, p)
		}
	}
	for _, p := range pairs {
		if p.dialect != hint {
			out = append(out, p)
		}
	}
	return out
}
