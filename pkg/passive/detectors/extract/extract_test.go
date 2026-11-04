package extract

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/zan8in/afrog/v3/pkg/passive"
	"github.com/zan8in/afrog/v3/pkg/passive/detectors/rulekit"
)

func tx(t *testing.T, rawURL string, body []byte, headers http.Header) *passive.CapturedTransaction {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	if headers == nil {
		headers = make(http.Header)
	}
	return &passive.CapturedTransaction{
		ID:       "t1",
		Request:  &passive.CapturedRequest{Method: "GET", URL: u, Headers: make(http.Header)},
		Response: &passive.CapturedResponse{Status: 200, Headers: headers, Body: body, Duration: 12 * time.Millisecond},
	}
}

func rulesOf(exts []passive.Extraction) map[string][]string {
	out := make(map[string][]string)
	for _, e := range exts {
		out[e.Rule] = append(out[e.Rule], e.Value)
	}
	return out
}

func TestExtractStrongPrefixedKeys(t *testing.T) {
	e := New(DefaultOptions())
	body := []byte(`var cfg = { aws: "AKIAIOSFODNN7REALKEY", g: "AIzaSyD9k2mQ7pR4tV1wX3yZ5aB6cD8eF0gH2jK" };`)
	got := rulesOf(e.Extract(tx(t, "https://a.example.com/app.js", body, nil)))

	if v := got["aws-access-key-id"]; len(v) != 1 || v[0] != "AKIAIOSFODNN7REALKEY" {
		t.Fatalf("aws key: %#v", v)
	}
	if len(got["google-api-key"]) != 1 {
		t.Fatalf("google key: %#v", got["google-api-key"])
	}
}

func TestExtractPrivateKeyHeader(t *testing.T) {
	e := New(DefaultOptions())
	body := []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----")
	got := rulesOf(e.Extract(tx(t, "https://a.example.com/key.txt", body, nil)))
	if len(got["private-key"]) != 1 {
		t.Fatalf("private key: %#v", got)
	}
}

func TestExtractPlaceholderRejected(t *testing.T) {
	e := New(DefaultOptions())
	// AWS 官方文档示例密钥含 EXAMPLE，必须被丢弃。
	body := []byte(`key = "AKIAIOSFODNN7EXAMPLE"`)
	if got := e.Extract(tx(t, "https://a.example.com/x.js", body, nil)); len(got) != 0 {
		t.Fatalf("placeholder should be dropped, got %#v", got)
	}
}

// 「可疑的密钥赋值」不能把代码引用当成密钥：值含点号（成员访问）一律丢弃。
func TestExtractSecretAssignmentRejectsCodeReference(t *testing.T) {
	e := New(DefaultOptions())
	body := []byte(`{key:n,phoneNumber:r,password:this.formData.passwordSj?this.formData.passwordSj:""}
Time:!1,loading:!1,phoneCodeLoading:!1,password:Object.assign({},i),patientRules:{oldValue:[{required:!0`)
	got := rulesOf(e.Extract(tx(t, "https://a.example.com/app.js", body, nil)))
	if list := got["secret-assignment"]; len(list) != 0 {
		t.Fatalf("code reference must not be reported: %#v", list)
	}
}

// 收紧后仍要保住真正的字面量密钥；值里带键名关键字的自引用（password: password123）要丢。
func TestExtractSecretAssignmentKeepsLiteralOnly(t *testing.T) {
	e := New(DefaultOptions())
	body := []byte(`{"apiKey":"aB3xY9kLm2Qz","password":"Tr0ub4dor&3x","clientSecret":"password123"}`)
	got := rulesOf(e.Extract(tx(t, "https://a.example.com/", body, nil)))
	values := got["secret-assignment"]
	if len(values) != 2 {
		t.Fatalf("want 2 literal secrets, got %#v", values)
	}
	for _, v := range values {
		if v == "password123" {
			t.Fatalf("self-referential value must be dropped: %#v", values)
		}
	}
}

func TestExtractJWT(t *testing.T) {
	e := New(DefaultOptions())
	token := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	got := rulesOf(e.Extract(tx(t, "https://a.example.com/", []byte("token="+token), nil)))
	if len(got["jwt"]) != 1 || got["jwt"][0] != token {
		t.Fatalf("jwt: %#v", got["jwt"])
	}
}

func TestExtractIDCardChecksum(t *testing.T) {
	e := New(DefaultOptions())
	valid := "11010519491231002X"   // 校验位正确
	invalid := "110105194912310021" // 校验位错误
	body := []byte("id1=" + valid + " id2=" + invalid)
	got := rulesOf(e.Extract(tx(t, "https://a.example.com/", body, nil)))
	if len(got["chinese-id-card"]) != 1 || got["chinese-id-card"][0] != valid {
		t.Fatalf("id card: %#v", got["chinese-id-card"])
	}
}

func TestExtractBankCardLuhn(t *testing.T) {
	e := New(DefaultOptions())
	body := []byte("card=4111111111111111 bad=4111111111111112")
	got := rulesOf(e.Extract(tx(t, "https://a.example.com/", body, nil)))
	if len(got["bank-card"]) != 1 || got["bank-card"][0] != "4111111111111111" {
		t.Fatalf("bank card: %#v", got["bank-card"])
	}
}

func TestExtractBankCardSnowflakeNotReported(t *testing.T) {
	e := New(DefaultOptions())
	// 真实 JSON 响应里的雪花 ID / traceId：既不该落在 BIN 号段，也不该满足语境佐证。
	body := []byte(`"125825","faviconId":"2360401497788514304","id":"2328610674055315458"},"traceId":"99d3d857cdff4cd9bd46475b50fc083f"}`)
	if n := len(rulesOf(e.Extract(tx(t, "https://a.example.com/", body, nil)))["bank-card"]); n != 0 {
		t.Fatalf("snowflake id must not be reported as bank card, got %d", n)
	}
}

func TestExtractBankCardRequiresContext(t *testing.T) {
	e := New(DefaultOptions())
	// 同一个合法 Visa 号（BIN + Luhn 都通过）：没有卡片语境词时必须被丢弃，
	// 否则任何 16 位业务编号都会因为 1/10 的 Luhn 通过率被误报成卡号。
	bare := rulesOf(e.Extract(tx(t, "https://a.example.com/", []byte(`"id":"4111111111111111"`), nil)))
	if n := len(bare["bank-card"]); n != 0 {
		t.Fatalf("bare card without context must be dropped, got %d", n)
	}
	// 近旁出现语境词时必须提取。
	ctx := rulesOf(e.Extract(tx(t, "https://a.example.com/", []byte(`"cardNumber":"4111111111111111"`), nil)))
	if n := len(ctx["bank-card"]); n != 1 {
		t.Fatalf("card with context must be kept, got %d", n)
	}
}

func TestExtractBankCardGrouped(t *testing.T) {
	e := New(DefaultOptions())
	// 印刷体分组卡号自带书写信号，无需语境词即可提取。
	got := rulesOf(e.Extract(tx(t, "https://a.example.com/", []byte("4111 1111 1111 1111"), nil)))
	if len(got["bank-card"]) != 1 || got["bank-card"][0] != "4111 1111 1111 1111" {
		t.Fatalf("grouped bank card: %#v", got["bank-card"])
	}
}

func TestBankCardIssuerAndContext(t *testing.T) {
	if !bankCardIssuer("4111111111111111") {
		t.Fatal("Visa 16 位应通过 BIN 白名单")
	}
	if bankCardIssuer("2360401497788514304") {
		t.Fatal("雪花 ID 不应落在 BIN 号段")
	}
	// 语境词前界必须是词边界：card 命中 cardNumber，但不该命中 discard。
	if !nearbyAny([]byte("cardNumber=4111111111111111"), 11, 27, bankContextWords) {
		t.Fatal("cardNumber 应被识别为卡片语境")
	}
	if nearbyAny([]byte("discard=4111111111111111"), 8, 24, bankContextWords) {
		t.Fatal("discard 不该被识别为卡片语境")
	}
}

func TestExtractScansHeadersAndURL(t *testing.T) {
	e := New(DefaultOptions())
	h := make(http.Header)
	h.Set("X-Amz-Credential", "AKIAIOSFODNN7REALKEY")
	u := "https://a.example.com/p?k=AIzaSyD9k2mQ7pR4tV1wX3yZ5aB6cD8eF0gH2jK"
	got := e.Extract(tx(t, u, nil, h))

	locs := map[string]string{}
	for _, ex := range got {
		locs[ex.Rule] = ex.Location
	}
	if locs["aws-access-key-id"] != "response-header" {
		t.Fatalf("header rule location: %#v", locs)
	}
	if locs["google-api-key"] != "url" {
		t.Fatalf("url rule location: %#v", locs)
	}
}

func TestExtractSkipsBinaryBody(t *testing.T) {
	e := New(DefaultOptions())
	body := []byte{0x89, 'P', 'N', 'G', 0x00, 'A', 'K', 'I', 'A', 'I', 'O', 'S', 'F', 'O', 'D', 'N', 'N', '7', 'R', 'E', 'A', 'L', 'K', 'E', 'Y'}
	if got := e.Extract(tx(t, "https://a.example.com/logo.png", body, nil)); len(got) != 0 {
		t.Fatalf("binary body should be skipped, got %#v", got)
	}
}

func TestExtractDedupWithinTransaction(t *testing.T) {
	e := New(DefaultOptions())
	body := []byte("a=AKIAIOSFODNN7REALKEY b=AKIAIOSFODNN7REALKEY")
	got := rulesOf(e.Extract(tx(t, "https://a.example.com/", body, nil)))
	if len(got["aws-access-key-id"]) != 1 {
		t.Fatalf("dup not collapsed: %#v", got["aws-access-key-id"])
	}
}

func TestValidators(t *testing.T) {
	if !rulekit.CNIDCard("11010519491231002X") || rulekit.CNIDCard("110105194912310021") {
		t.Fatal("cnIDCard")
	}
	if !rulekit.Luhn("4111111111111111") || rulekit.Luhn("4111111111111112") {
		t.Fatal("luhn")
	}
	if !rulekit.JWTValid("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c") {
		t.Fatal("jwtValid should accept a real-shaped token")
	}
	if rulekit.JWTValid("eyJhbGciOiJIUzI1NiJ9.notbase64!!.sig") {
		t.Fatal("jwtValid should reject non-base64 payload")
	}
	if rulekit.GenericSecret("admin") || !rulekit.GenericSecret("hunter2pass") {
		t.Fatal("genericSecret")
	}
	if !rulekit.IsPlaceholder("AKIAIOSFODNN7EXAMPLE") || rulekit.IsPlaceholder("AKIAIOSFODNN7REALKEY") {
		t.Fatal("isPlaceholder")
	}
}
