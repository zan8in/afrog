package recon

import (
	"regexp"

	"github.com/zan8in/afrog/v3/pkg/passive"
	"github.com/zan8in/afrog/v3/pkg/passive/detectors/rulekit"
)

// 规则分类，供面板分组展示。
const (
	catBucket   = "cloud-bucket"
	catEmail    = "email"
	catEndpoint = "endpoint"
)

// defaultRules 是内置规则表：信息收集的高精度子集。
//
// 全部规则严重级别为 info——它们是「资产线索」，不是漏洞。命中的价值在于把分散在
// JS/接口响应里的横向入口（其它域名、存储桶、邮箱、API）聚到一处，供后续渗透决策。
var defaultRules = []rulekit.Rule{
	{
		ID:       "cloud-bucket",
		Category: catBucket,
		Title:    "云存储桶",
		Severity: "info",
		Conf:     passive.ConfidenceCertain,
		// 各云厂商的存储域名是公开且唯一的，命中即认定。锚点先按域名秒筛。
		Anchors: []string{"amazonaws.com", "aliyuncs.com", "myqcloud.com", "core.windows.net", "storage.googleapis.com"},
		// 覆盖 AWS S3 / 阿里云 OSS / 腾讯云 COS / Azure Blob / GCS 五种主机式引用。
		Re:    regexp.MustCompile(`\b((?:[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com|[a-z0-9][a-z0-9\-]{1,61}\.oss-[a-z0-9\-]+\.aliyuncs\.com|[a-z0-9][a-z0-9\-]{1,61}\.cos\.[a-z0-9\-]+\.myqcloud\.com|[a-z0-9][a-z0-9\-]{1,61}\.blob\.core\.windows\.net|storage\.googleapis\.com/[A-Za-z0-9._\-]{1,80}))\b`),
		Group: 1,
	},
	{
		ID:       "cloud-bucket-uri",
		Category: catBucket,
		Title:    "云存储桶（URI 形式）",
		Severity: "info",
		Conf:     passive.ConfidenceCertain,
		// 配置文件里常见的 s3://bucket / gs://bucket / oss://bucket 引用。
		Anchors: []string{"s3://", "gs://", "oss://"},
		Re:      regexp.MustCompile(`\b((?:s3|gs|oss)://[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])`),
		Group:   1,
	},
	{
		ID:       "email",
		Category: catEmail,
		Title:    "邮箱地址",
		Severity: "info",
		Conf:     passive.ConfidenceProbable,
		// 邮箱不挑面：既可能是接口响应里的联系人，也可能是请求 URL 的查询参数。
		Anchors:  []string{"@"},
		Re:       regexp.MustCompile(`\b([A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?){0,4}\.[A-Za-z]{2,24})\b`),
		Group:    1,
		Validate: validEmail,
	},
	{
		ID:       "api-path",
		Category: catEndpoint,
		Title:    "接口路径",
		Severity: "info",
		Conf:     passive.ConfidenceProbable,
		// 只认 /api、/rest、/graphql 这三个明确的接口前缀，不做「任意斜杠路径」的泛匹配，
		// 否则会把 CSS/JS 里的相对路径全量吐出来。同样只扫响应体。
		Sources:  []rulekit.Source{rulekit.SourceBody},
		Anchors:  []string{"/api", "/rest", "/graphql"},
		Re:       regexp.MustCompile(`((?:/api|/rest|/graphql)(?:/[A-Za-z0-9_\-./{}:$%~+]{0,180})?)`),
		Group:    1,
		Validate: validAPIPath,
		Context:  apiPathContext,
	},
}
