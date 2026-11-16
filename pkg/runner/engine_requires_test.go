package runner

import (
	"testing"

	"github.com/zan8in/afrog/v3/pkg/assetgraph"
	"github.com/zan8in/afrog/v3/pkg/portscan"
)

// addWebTechFacts 把 -w 的技术栈写入画像：站点根与带路径的目标都要覆盖，
// 无关目标不能凭空多出条目。
func TestAddWebTechFacts(t *testing.T) {
	metas := map[string]WebMeta{
		"127.0.0.1:8080": {URL: "http://127.0.0.1:8080", Technologies: []WebTech{
			{Name: "WordPress", Version: "6.4.2", Category: "cms", RuleID: "wordpress", Confidence: "certain"},
			{Name: "Apache Shiro", Category: "framework", RuleID: "apache-shiro", Confidence: "probable"},
		}},
		// 没有技术栈的探测结果不应产生标识词。
		"127.0.0.1:9090": {URL: "http://127.0.0.1:9090"},
	}
	targets := []string{
		"http://127.0.0.1:8080",
		"http://127.0.0.1:8080/wp-login.php",
		"http://127.0.0.1:9090",
	}
	ps := assetgraph.NewProfiles()
	addWebTechFacts(ps, targets, metas)

	for _, key := range []string{"127.0.0.1:8080", "127.0.0.1:8080/wp-login.php"} {
		set := ps.RequiresTokens(key)
		if len(set) == 0 {
			t.Fatalf("missing entry for %s", key)
		}
		for _, want := range []string{"wordpress", "cms", "apache-shiro", "apache shiro", "framework"} {
			if _, ok := set[want]; !ok {
				t.Fatalf("key %s missing token %q: %v", key, want, set)
			}
		}
		// 版本要随标识词一起带出，供版本约束门控使用。
		if set["wordpress"] != "6.4.2" {
			t.Fatalf("key %s wordpress version = %q, want 6.4.2", key, set["wordpress"])
		}
		// 可信度要透传：否定证据只采信 certain 级事实。
		certain := ps.CertainTokens(key)
		if _, ok := certain["wordpress"]; !ok {
			t.Fatalf("key %s: wordpress (certain) should be a certain token: %v", key, certain)
		}
		if _, ok := certain["apache-shiro"]; ok {
			t.Fatalf("key %s: probable apache-shiro must not be a certain token: %v", key, certain)
		}
	}
	if ps.RequiresTokens("127.0.0.1:9090") != nil {
		t.Fatalf("target without technologies should not appear")
	}

	// 空输入不应写入任何内容。
	empty := assetgraph.NewProfiles()
	addWebTechFacts(empty, nil, metas)
	addWebTechFacts(empty, targets, nil)
	if empty.Len() != 0 {
		t.Fatalf("expected no profiles for empty input, got %d", empty.Len())
	}
}

// FactsByHost 把 per host:port 的端口指纹结论按主机聚合，供门控把
// 主机级结论分发给同一主机上的任意目标。
func TestOpenPortsCollectorFactsByHost(t *testing.T) {
	c := newOpenPortsCollector()
	c.AddResult(&portscan.ScanResult{Host: "10.0.0.1", Port: 6379, ServiceInfo: portscan.ServiceInfo{Service: "redis", Product: "Redis", Version: "7.0.11"}})
	c.AddResult(&portscan.ScanResult{Host: "10.0.0.1", Port: 3306, ServiceInfo: portscan.ServiceInfo{Service: "mysql", Product: "MySQL", Version: "8.0.34"}})
	c.AddResult(&portscan.ScanResult{Host: "10.0.0.2", Port: 22, ServiceInfo: portscan.ServiceInfo{Service: "ssh"}})

	got := c.FactsByHost()
	if len(got) != 2 {
		t.Fatalf("FactsByHost hosts = %d, want 2: %v", len(got), got)
	}
	if len(got["10.0.0.1"]) != 2 {
		t.Fatalf("10.0.0.1 facts = %d, want 2", len(got["10.0.0.1"]))
	}
	if len(got["10.0.0.2"]) != 1 {
		t.Fatalf("10.0.0.2 facts = %d, want 1", len(got["10.0.0.2"]))
	}

	var nilCollector *openPortsCollector
	if nilCollector.FactsByHost() != nil {
		t.Fatal("expected nil for a nil collector")
	}
}

// addPortServiceFacts 把端口指纹写入画像：该主机上任意目标（URL 或 host:port）
// 都能取到主机级服务结论，无结论的主机不产出词条。
func TestAddPortServiceFacts(t *testing.T) {
	c := newOpenPortsCollector()
	c.AddResult(&portscan.ScanResult{Host: "10.0.0.1", Port: 6379, ServiceInfo: portscan.ServiceInfo{Service: "redis", Product: "Redis", Version: "7.0.11", Confidence: portscan.ConfidenceCertain}})
	c.AddResult(&portscan.ScanResult{Host: "10.0.0.1", Port: 3306, ServiceInfo: portscan.ServiceInfo{Service: "mysql", Product: "MySQL Server", Version: "8.0.34"}})

	targets := []string{
		"10.0.0.1:6379",
		"http://10.0.0.1:8080",
		"10.0.0.9:6379",
	}
	ps := assetgraph.NewProfiles()
	addPortServiceFacts(ps, targets, c)

	set := ps.RequiresTokens("10.0.0.1:6379")
	if len(set) == 0 {
		t.Fatalf("missing entry for 10.0.0.1:6379")
	}
	for _, want := range []string{"redis", "mysql", "mysql server", "mysql-server"} {
		if _, ok := set[want]; !ok {
			t.Fatalf("missing token %q: %v", want, set)
		}
	}
	if set["redis"] != "7.0.11" {
		t.Fatalf("redis version = %q, want 7.0.11", set["redis"])
	}
	// certain 级端口事实进入高置信视图，供否定证据使用。
	if _, ok := ps.CertainTokens("10.0.0.1:6379")["redis"]; !ok {
		t.Fatalf("certain redis token missing: %v", ps.CertainTokens("10.0.0.1:6379"))
	}
	// URL 目标按 host 归一后同样继承主机级端口结论。
	urlSet := ps.RequiresTokens("10.0.0.1:8080")
	if urlSet["redis"] != "7.0.11" {
		t.Fatalf("URL target should inherit host facts: %v", urlSet)
	}
	if ps.RequiresTokens("10.0.0.9:6379") != nil {
		t.Fatalf("host without facts should not appear")
	}

	// 空输入不应写入任何内容。
	empty := assetgraph.NewProfiles()
	addPortServiceFacts(empty, nil, c)
	addPortServiceFacts(empty, targets, nil)
	if empty.Len() != 0 {
		t.Fatalf("expected no profiles for empty input, got %d", empty.Len())
	}
}
