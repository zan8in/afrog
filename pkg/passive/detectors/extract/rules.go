package extract

import (
	"regexp"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/passive"
	"github.com/zan8in/afrog/v3/pkg/passive/detectors/rulekit"
)

// 规则分类，供面板分组展示。
const (
	catPrivateKey = "private-key"
	catCloudKey   = "cloud-credential"
	catAPIKey     = "api-key"
	catToken      = "token"
	catDatabase   = "database"
	catPII        = "pii"
	catSecret     = "secret"
)

// defaultRules 是内置规则表。
//
// 取值口径刻意偏保守：宁可提取不到，也不产生需要人工逐条排除的噪声。所有涉及
// 「凭据」的规则都要求带厂商专属前缀（AKIA / LTAI / xox / sk_live_ …），这些前缀
// 是厂商公开的、唯一对应到具体服务的标识，几乎不可能出现在正常文本里。
//
// 规则结构与三道保险（Anchors / Validate / Context）的语义见 rulekit.Rule。
var defaultRules = []rulekit.Rule{
	{
		ID:       "private-key",
		Category: catPrivateKey,
		Title:    "私钥文件（PEM）",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"-----BEGIN"},
		// 覆盖 RSA / EC / DSA / OPENSSH / ENCRYPTED / PGP 等全部 PEM 私钥头。
		Re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`),
	},
	{
		ID:       "aws-access-key-id",
		Category: catCloudKey,
		Title:    "AWS Access Key ID",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"AKIA", "ASIA"},
		Re:       regexp.MustCompile(`\b((?:AKIA|ASIA)[0-9A-Z]{16})\b`),
		Group:    1,
	},
	{
		ID:       "aliyun-access-key-id",
		Category: catCloudKey,
		Title:    "阿里云 AccessKey ID",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"LTAI"},
		Re:       regexp.MustCompile(`\b(LTAI[0-9A-Za-z]{12,20})\b`),
		Group:    1,
	},
	{
		ID:       "tencent-secret-id",
		Category: catCloudKey,
		Title:    "腾讯云 SecretId",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"AKID"},
		Re:       regexp.MustCompile(`\b(AKID[0-9A-Za-z]{13,36})\b`),
		Group:    1,
	},
	{
		ID:       "google-api-key",
		Category: catAPIKey,
		Title:    "Google API Key",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"AIza"},
		Re:       regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{35})\b`),
		Group:    1,
	},
	{
		ID:       "github-token",
		Category: catToken,
		Title:    "GitHub Token",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
		Re:       regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{82})\b`),
		Group:    1,
	},
	{
		ID:       "slack-token",
		Category: catToken,
		Title:    "Slack Token",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"xox"},
		Re:       regexp.MustCompile(`\b(xox[abprs]-[0-9A-Za-z-]{10,72})\b`),
		Group:    1,
	},
	{
		ID:       "stripe-secret-key",
		Category: catAPIKey,
		Title:    "Stripe Secret Key",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"sk_live_", "rk_live_"},
		Re:       regexp.MustCompile(`\b((?:sk|rk)_live_[0-9A-Za-z]{16,99})\b`),
		Group:    1,
	},
	{
		ID:       "sendgrid-api-key",
		Category: catAPIKey,
		Title:    "SendGrid API Key",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"SG."},
		Re:       regexp.MustCompile(`\b(SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43})\b`),
		Group:    1,
	},
	{
		ID:       "twilio-account-key",
		Category: catAPIKey,
		Title:    "Twilio API Key / Account SID",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		// 前缀 AC / SK 过于通用，做锚点没有筛选价值，改用整段 32 位十六进制的强结构。
		Re:    regexp.MustCompile(`\b((?:AC|SK)[0-9a-f]{32})\b`),
		Group: 1,
	},
	{
		ID:       "openai-api-key",
		Category: catAPIKey,
		Title:    "OpenAI API Key",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"sk-"},
		Re:       regexp.MustCompile(`\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,200})\b`),
		Group:    1,
		Validate: func(v string) bool { return !strings.HasPrefix(v, "sk-ant-") },
	},
	{
		ID:       "anthropic-api-key",
		Category: catAPIKey,
		Title:    "Anthropic API Key",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"sk-ant-"},
		Re:       regexp.MustCompile(`\b(sk-ant-[A-Za-z0-9_\-]{20,200})\b`),
		Group:    1,
	},
	{
		ID:       "digitalocean-token",
		Category: catToken,
		Title:    "DigitalOcean Token",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"dop_v1_", "doo_v1_"},
		Re:       regexp.MustCompile(`\b((?:dop|doo)_v1_[0-9a-f]{64})\b`),
		Group:    1,
	},
	{
		ID:       "shopify-token",
		Category: catToken,
		Title:    "Shopify Access Token",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"shpat_", "shpca_", "shppa_"},
		Re:       regexp.MustCompile(`\b(shp(?:at|ca|pa)_[0-9a-fA-F]{32})\b`),
		Group:    1,
	},
	{
		ID:       "npm-token",
		Category: catToken,
		Title:    "npm Access Token",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"npm_"},
		Re:       regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`),
		Group:    1,
	},
	{
		ID:       "mailgun-api-key",
		Category: catAPIKey,
		Title:    "Mailgun API Key",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"key-"},
		Re:       regexp.MustCompile(`\b(key-[0-9a-f]{32})\b`),
		Group:    1,
	},
	{
		ID:       "jwt",
		Category: catToken,
		Title:    "JSON Web Token (JWT)",
		Severity: "medium",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"eyJ"},
		// 三段点分、前两段以 eyJ 开头（{" 的 base64url），交给 JWTValid 解码确证。
		Re:       regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{10,1000}\.eyJ[A-Za-z0-9_\-]{10,1000}\.[A-Za-z0-9_\-]{10,1000})`),
		Group:    1,
		Validate: rulekit.JWTValid,
	},
	{
		ID:       "connection-string",
		Category: catDatabase,
		Title:    "含凭据的连接串",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"://"},
		Re:       regexp.MustCompile(`((?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp|mssql|oracle|ftp):\/\/[^\s"'<>\\)\]}]{2,64}:[^\s"'<>\\)\]}]{2,64}@[^\s"'<>\\)\]}]{2,255})`),
		Group:    1,
	},
	{
		ID:       "gcp-service-account",
		Category: catCloudKey,
		Title:    "GCP 服务账号密钥文件",
		Severity: "high",
		Conf:     passive.ConfidenceCertain,
		Anchors:  []string{"service_account"},
		Re:       regexp.MustCompile(`("type"\s*:\s*"service_account")`),
		Group:    1,
	},
	{
		ID:       "chinese-id-card",
		Category: catPII,
		Title:    "中国大陆身份证号",
		Severity: "medium",
		Conf:     passive.ConfidenceCertain,
		// 无固定前缀，靠「18 位 + 出生日期合法 + 校验位」三重约束确认。
		Re:       regexp.MustCompile(`\b([1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx])\b`),
		Group:    1,
		Validate: rulekit.CNIDCard,
	},
	{
		ID:       "bank-card",
		Category: catPII,
		Title:    "银行卡号",
		Severity: "medium",
		Conf:     passive.ConfidenceProbable,
		// 三种形态，从严到宽：
		//   1) 印刷体卡号 —— 数字被空格/连字符成组分隔（4111 1111 1111 1111 / 4-4-4-4-3）。
		//      分组本身就是极强的「人类书写」信号，雪花 ID、订单号、时间戳不会长成这样；
		//   2) 4-6-5（American Express 15 位）；
		//   3) 裸数字串 —— 结构上毫无独特性，必须靠 context 要求近旁出现卡片语境词。
		// 最坏的一道闸是 bankCardValid 里的 BIN 白名单 + Luhn：即便前两道都被绕过，
		// 「恰好满足 Luhn 的 16–19 位业务编号」也几乎不可能同时落在真实发卡行号段内。
		Re:       regexp.MustCompile(`\b(\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}(?:[ -]\d{3})?|\d{4}[ -]\d{6}[ -]\d{5}|\d{13,19})\b`),
		Group:    1,
		Context:  bankCardContext,
		Validate: bankCardValid,
	},
	{
		ID:       "secret-assignment",
		Category: catSecret,
		Title:    "可疑的密钥赋值",
		Severity: "medium",
		Conf:     passive.ConfidenceProbable,
		// 兜底规则：无固定前缀，靠「键名 + 分隔符 + 值形态」三重约束。键名大小写
		// 不定（password / Password / PASSWORD），因此不做字面锚点、直接跑正则。
		Re:       regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|secret[_-]?key|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']?([A-Za-z0-9!@#$%^&*_\-\.\+/]{6,100})`),
		Group:    1,
		Validate: looseSecret,
	},
}
