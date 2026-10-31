package portscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestFingerprinter(t *testing.T, dir string) *Fingerprinter {
	t.Helper()
	fp, err := NewFingerprinter(dir)
	if err != nil {
		t.Fatalf("NewFingerprinter(%q): %v", dir, err)
	}
	return fp
}

func TestIsWebService(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"http", true},
		{"https", true},
		{"https-alt", true},
		{"squid-http", true},
		{"whm", true},
		{"HTTP", true},
		{" http ", true},
		{"webmail", true},
		{"infoweb", true},
		{"mysql", false},
		{"ssh", false},
		{"redis", false},
		{"ajp13", false},
		{"rtsp", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsWebService(tt.in); got != tt.want {
			t.Fatalf("IsWebService(%q)=%v want=%v", tt.in, got, tt.want)
		}
	}
}

func TestIdentifyBuiltinBanners(t *testing.T) {
	fp := newTestFingerprinter(t, "")

	cases := []struct {
		name        string
		port        int
		probe       string
		data        string
		wantService string
		wantProduct string
		wantVersion string
		wantConf    Confidence
		wantRule    string
	}{
		{
			name: "openssh", port: 22, probe: DefaultProbeID,
			data:        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n",
			wantService: "ssh", wantProduct: "OpenSSH", wantVersion: "8.9p1",
			wantConf: ConfidenceCertain, wantRule: "ssh",
		},
		{
			name: "dropbear", port: 22, probe: DefaultProbeID,
			data:        "SSH-2.0-dropbear_2022.83\r\n",
			wantService: "ssh", wantProduct: "dropbear", wantVersion: "2022.83",
			wantConf: ConfidenceCertain, wantRule: "ssh",
		},
		{
			name: "nginx", port: 80, probe: DefaultProbeID,
			data:        "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n",
			wantService: "http", wantProduct: "nginx", wantVersion: "1.25.3",
			wantConf: ConfidenceCertain, wantRule: "http",
		},
		{
			name: "mysql", port: 3306, probe: DefaultProbeID,
			data:        "\x2b\x00\x00\x00\x0a8.0.34\x00abcdefgh",
			wantService: "mysql", wantProduct: "MySQL", wantVersion: "8.0.34",
			wantConf: ConfidenceCertain, wantRule: "mysql",
		},
		{
			name: "redis-info", port: 6379, probe: "RedisInfo",
			data:        "# Server\r\nredis_version:7.0.11\r\n",
			wantService: "redis", wantProduct: "Redis", wantVersion: "7.0.11",
			wantConf: ConfidenceCertain, wantRule: "redis",
		},
		{
			name: "telnet-softmatch", port: 23, probe: DefaultProbeID,
			data:        "Ubuntu 22.04 LTS\r\nlogin: ",
			wantService: "telnet", wantConf: ConfidenceProbable, wantRule: "telnet",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := fp.Identify(tc.port, []Observation{{ProbeID: tc.probe, Data: []byte(tc.data)}})
			if info.Service != tc.wantService {
				t.Errorf("Service = %q, want %q", info.Service, tc.wantService)
			}
			if info.Product != tc.wantProduct {
				t.Errorf("Product = %q, want %q", info.Product, tc.wantProduct)
			}
			if info.Version != tc.wantVersion {
				t.Errorf("Version = %q, want %q", info.Version, tc.wantVersion)
			}
			if info.Confidence != tc.wantConf {
				t.Errorf("Confidence = %s, want %s", info.Confidence, tc.wantConf)
			}
			if info.RuleID != tc.wantRule {
				t.Errorf("RuleID = %q, want %q", info.RuleID, tc.wantRule)
			}
			if info.Banner == "" {
				t.Error("Banner is empty")
			}
		})
	}
}

// TestIdentifyMQTTBinary 验证 binary 规则按 latin-1 逐字节匹配，且 \xNN 能对上原始字节。
func TestIdentifyMQTTBinary(t *testing.T) {
	fp := newTestFingerprinter(t, "")
	info := fp.Identify(1883, []Observation{{
		ProbeID: "MQTTConnect",
		Data:    []byte{0x20, 0x02, 0x00, 0x00},
	}})
	if info.Service != "mqtt" {
		t.Fatalf("Service = %q, want mqtt", info.Service)
	}
	if info.Product != "MQTT" {
		t.Errorf("Product = %q, want MQTT", info.Product)
	}
	if info.Confidence != ConfidenceCertain {
		t.Errorf("Confidence = %s, want certain", info.Confidence)
	}
}

// TestIdentifyProtocolFingerprints 验证新增的协议结构指纹：命中真实响应，
// 且不会把普通 HTTP/JSON 响应误判成专用协议。
func TestIdentifyProtocolFingerprints(t *testing.T) {
	fp := newTestFingerprinter(t, "")

	cassandra := []byte{
		0x84, 0x00, 0x00, 0x01, 0x06, 0x00, 0x00, 0x00, 0x18,
		0x00, 0x01, 0x00, 0x0b,
		'C', 'Q', 'L', '_', 'V', 'E', 'R', 'S', 'I', 'O', 'N',
		0x00, 0x01, 0x00, 0x05, '3', '.', '4', '.', '5',
	}
	mssql := []byte{0x04, 0x01, 0x00, 0x38, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x15, 0x00, 0x06}
	nfs := []byte{
		0x80, 0x00, 0x00, 0x1c,
		0x12, 0x34, 0x56, 0x78,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	cases := []struct {
		name        string
		port        int
		obs         Observation
		wantService string
		wantProduct string
		wantVersion string
		wantRule    string
	}{
		{"jdwp", 5005, Observation{ProbeID: "JDWPHandshake", Data: []byte("JDWP-Handshake")},
			"jdwp", "JDWP", "", "jdwp"},
		{"nats", 4222, Observation{ProbeID: DefaultProbeID,
			Data: []byte(`INFO {"server_id":"ND123","server_name":"n","version":"2.10.7","proto":1}` + "\r\n")},
			"nats", "NATS", "2.10.7", "nats"},
		{"cassandra", 9042, Observation{ProbeID: "CassandraOptions", Data: cassandra},
			"cql", "Cassandra", "", "cassandra"},
		{"mssql", 1433, Observation{ProbeID: "MSSQLPreLogin", Data: mssql},
			"ms-sql-s", "Microsoft SQL Server", "", "mssql"},
		{"oracle", 1521, Observation{ProbeID: "OracleConnect",
			Data: []byte("(DESCRIPTION=(VSNNUM=0x169)(VERSION=19.3.0.0.0))")},
			"oracle", "Oracle TNS Listener", "", "oracle"},
		{"nfs", 2049, Observation{ProbeID: "NFSNull", Data: nfs},
			"nfs", "NFS", "", "nfs"},
		{"cups", 631, Observation{ProbeID: "GetRequest",
			Data: []byte("HTTP/1.1 200 OK\r\nServer: CUPS/2.4.2 IPP/2.1\r\n\r\n")},
			"ipp", "CUPS", "2.4.2", "cups"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := fp.Identify(tc.port, []Observation{tc.obs})
			if info.Service != tc.wantService {
				t.Errorf("Service = %q, want %q", info.Service, tc.wantService)
			}
			if info.Product != tc.wantProduct {
				t.Errorf("Product = %q, want %q", info.Product, tc.wantProduct)
			}
			if info.Version != tc.wantVersion {
				t.Errorf("Version = %q, want %q", info.Version, tc.wantVersion)
			}
			if info.Confidence != ConfidenceCertain {
				t.Errorf("Confidence = %s, want certain", info.Confidence)
			}
			if info.RuleID != tc.wantRule {
				t.Errorf("RuleID = %q, want %q", info.RuleID, tc.wantRule)
			}
		})
	}

	// 泛化 JSON 不能被当作 NATS：server_id 是 NATS INFO 的必填字段。
	info := fp.Identify(4222, []Observation{{ProbeID: DefaultProbeID, Data: []byte(`INFO {"foo":1}`)}})
	if info.RuleID != "" {
		t.Errorf("generic INFO JSON matched rule %q", info.RuleID)
	}

	// 协议探针只能发往其专用端口，避免污染通用 HTTP 端口。
	active80 := probeIDs(fp.Probes(80, ProbeModeActive))
	for _, id := range []string{"JDWPHandshake", "CassandraOptions", "MSSQLPreLogin", "OracleConnect", "NFSNull"} {
		if contains(active80, id) {
			t.Errorf("probe %s must not be sent to port 80", id)
		}
	}
	if !contains(probeIDs(fp.Probes(1433, ProbeModeActive)), "MSSQLPreLogin") {
		t.Error("MSSQLPreLogin must be sent to port 1433")
	}
	if !contains(probeIDs(fp.Probes(2049, ProbeModeActive)), "NFSNull") {
		t.Error("NFSNull must be sent to port 2049")
	}
}

// TestTightenedPortRulesAreProbable 验证收紧后的弱判据不再以 certain 输出。
func TestTightenedPortRulesAreProbable(t *testing.T) {
	fp := newTestFingerprinter(t, "")

	info := fp.Identify(8123, []Observation{{
		ProbeID: "GetRequest",
		Data:    []byte("Ok."),
	}})
	if info.RuleID != "clickhouse" || info.Confidence != ConfidenceProbable {
		t.Errorf("clickhouse rule = %q/%s, want clickhouse/probable", info.RuleID, info.Confidence)
	}

	info = fp.Identify(7001, []Observation{{
		ProbeID: "GetRequest",
		Data:    []byte("HTTP/1.0 404 Not Found\r\n\r\n<html><title>Error 404--Not Found</title></html>"),
	}})
	if info.Product != "Oracle WebLogic" {
		t.Errorf("Product = %q, want Oracle WebLogic", info.Product)
	}
	if info.RuleID == "weblogic" && info.Confidence == ConfidenceCertain {
		t.Error("WebLogic 404 title must not be reported as certain")
	}
}

// TestIdentifyPortPriorOnly 验证没有任何探针证据时只给端口惯例推测。
func TestIdentifyPortPriorOnly(t *testing.T) {
	fp := newTestFingerprinter(t, "")
	info := fp.Identify(22, nil)
	if info.Service != "ssh" {
		t.Errorf("Service = %q, want ssh", info.Service)
	}
	if info.Confidence != ConfidencePortOnly {
		t.Errorf("Confidence = %s, want port", info.Confidence)
	}
	if info.RuleID != "" {
		t.Errorf("RuleID = %q, want empty", info.RuleID)
	}
}

// TestIdentifyEvidenceBeatsPrior 验证实证（banner 命中）优先于端口惯例，
// 并且端口先验的 TLS 标记会保留在结果里。
func TestIdentifyEvidenceBeatsPrior(t *testing.T) {
	fp := newTestFingerprinter(t, "")
	info := fp.Identify(443, []Observation{{
		ProbeID: DefaultProbeID,
		Data:    []byte("SSH-2.0-OpenSSH_9.0\r\n"),
	}})
	if info.Service != "ssh" {
		t.Errorf("Service = %q, want ssh (evidence overrides the https prior)", info.Service)
	}
	if info.Confidence != ConfidenceCertain {
		t.Errorf("Confidence = %s, want certain", info.Confidence)
	}
	if !info.TLS {
		t.Error("TLS = false, want true (kept from the port prior)")
	}
}

func TestProbesByModeAndPort(t *testing.T) {
	fp := newTestFingerprinter(t, "")

	passive := probeIDs(fp.Probes(80, ProbeModePassive))
	if !contains(passive, DefaultProbeID) || !contains(passive, "TLS") {
		t.Errorf("passive probes for 80 = %v, want to contain %q and TLS", passive, DefaultProbeID)
	}
	if contains(passive, "GetRequest") {
		t.Errorf("passive probes for 80 = %v, must not contain the active GetRequest probe", passive)
	}

	active := probeIDs(fp.Probes(80, ProbeModeActive))
	if !contains(active, "GetRequest") {
		t.Errorf("active probes for 80 = %v, want to contain GetRequest", active)
	}

	// ports 限制：RedisPing 只应在 6379 系列端口上出现。
	if contains(probeIDs(fp.Probes(80, ProbeModeActive)), "RedisPing") {
		t.Error("RedisPing must not be sent to port 80")
	}
	if !contains(probeIDs(fp.Probes(6379, ProbeModeActive)), "RedisPing") {
		t.Error("RedisPing must be sent to port 6379")
	}
}

func TestTLSPort(t *testing.T) {
	fp := newTestFingerprinter(t, "")
	if !fp.TLSPort(443) {
		t.Error("TLSPort(443) = false, want true")
	}
	if fp.TLSPort(80) {
		t.Error("TLSPort(80) = true, want false")
	}
}

func TestLoadFingerprintDBMergesDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "services.yaml"), `
- id: ssh
  service: ssh-custom
  probes: ["NULL"]
  match:
    - pattern: '(?i)^SSH-'
      info: "custom ssh rule"
- id: my-http
  service: my-http
  probes: ["NULL"]
  match:
    - pattern: 'MYHTTP'
      info: "custom http rule"
`)
	writeFile(t, filepath.Join(dir, "probes.yaml"), `
- id: MyProbe
  desc: custom probe
  mode: passive
`)

	db, err := LoadFingerprintDB(dir)
	if err != nil {
		t.Fatalf("LoadFingerprintDB: %v", err)
	}

	// 同 id 覆盖：内置 ssh 规则被替换，而不是变成两条。
	sshCount := 0
	for _, r := range db.Rules {
		if r.ID == "ssh" {
			sshCount++
			if r.Service != "ssh-custom" {
				t.Errorf("ssh rule service = %q, want ssh-custom", r.Service)
			}
		}
	}
	if sshCount != 1 {
		t.Errorf("ssh rules = %d, want 1 (same id overrides the built-in rule)", sshCount)
	}

	// 外置规则整体排在内置规则之前，保证 specific 规则不被内置通用规则抢命中。
	if db.Rules[0].ID != "ssh" || db.Rules[1].ID != "my-http" {
		t.Errorf("first rules = %q, %q; want the external rules first", db.Rules[0].ID, db.Rules[1].ID)
	}

	// 新探针 id 被追加，内置探针仍然保留。
	ids := probeIDs(db.Probes)
	if !contains(ids, "MyProbe") {
		t.Errorf("probes = %v, want to contain the custom MyProbe", ids)
	}
	if !contains(ids, DefaultProbeID) {
		t.Errorf("probes = %v, want to keep the built-in %q probe", ids, DefaultProbeID)
	}
}

func TestIdentifyWithCustomDirOverridesBuiltinRule(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "services.yaml"), `
- id: my-ssh
  service: my-ssh
  probes: ["NULL"]
  match:
    - pattern: '(?i)^SSH-'
      info: "custom ssh"
`)

	fp := newTestFingerprinter(t, dir)
	info := fp.Identify(22, []Observation{{
		ProbeID: DefaultProbeID,
		Data:    []byte("SSH-2.0-OpenSSH_9.0\r\n"),
	}})
	if info.Service != "my-ssh" {
		t.Errorf("Service = %q, want my-ssh (external rules win on tie)", info.Service)
	}
	if info.RuleID != "my-ssh" {
		t.Errorf("RuleID = %q, want my-ssh", info.RuleID)
	}
}

func TestLoadFingerprintDBRejectsUnknownProbe(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "services.yaml"), `
- id: broken
  service: broken
  probes: ["NOPE"]
  match:
    - pattern: 'x'
      info: "broken"
`)

	if _, err := NewFingerprinter(dir); err == nil {
		t.Fatal("NewFingerprinter accepted a rule referencing an unknown probe")
	}
}

func TestSanitizeBanner(t *testing.T) {
	got := sanitizeBanner([]byte("hello\x00world\xff"))
	if strings.ContainsRune(got, '\x00') {
		t.Errorf("sanitizeBanner kept a NUL byte: %q", got)
	}
	if !strings.HasPrefix(got, "hello.world") {
		t.Errorf("sanitizeBanner = %q, want it to start with hello.world", got)
	}

	long := make([]byte, maxBannerBytes+512)
	for i := range long {
		long[i] = 'a'
	}
	if n := len(sanitizeBanner(long)); n > maxBannerBytes {
		t.Errorf("sanitizeBanner length = %d, want <= %d", n, maxBannerBytes)
	}
}

func probeIDs(probes []*Probe) []string {
	out := make([]string, 0, len(probes))
	for _, p := range probes {
		out = append(out, p.ID)
	}
	return out
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
