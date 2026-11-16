package assetgraph

import "testing"

// 三源事实汇入同一份画像，requires 词表要能同时命中端口服务、Web 技术栈与指纹 PoC 的 id。
func TestProfilesRequiresTokens(t *testing.T) {
	ps := NewProfiles()
	ps.AddService("10.0.0.1:6379", ServiceFact{Service: "redis", Product: "Redis", Version: "7.0.11"})
	ps.AddTech("10.0.0.1:8080", TechFact{Name: "WordPress", RuleID: "wordpress", Category: "cms", Version: "6.4.2"})
	ps.AddHit("10.0.0.1:8080", HitFact{ID: "ajp-protocol-detect", Tags: []string{"ajp", "tomcat"}})

	srv := ps.RequiresTokens("10.0.0.1:6379")
	if srv["redis"] != "7.0.11" {
		t.Fatalf("redis token = %q, want 7.0.11", srv["redis"])
	}

	web := ps.RequiresTokens("10.0.0.1:8080")
	for _, want := range []string{"wordpress", "cms", "ajp-protocol-detect", "ajp", "tomcat"} {
		if _, ok := web[want]; !ok {
			t.Fatalf("missing token %q: %v", want, web)
		}
	}
	if web["wordpress"] != "6.4.2" {
		t.Fatalf("wordpress version = %q, want 6.4.2", web["wordpress"])
	}
	// 指纹 PoC 的 id / tag 不带版本。
	if web["ajp-protocol-detect"] != "" {
		t.Fatalf("fingerprint token should have empty version, got %q", web["ajp-protocol-detect"])
	}

	if ps.RequiresTokens("no-such-target") != nil {
		t.Fatal("unrelated target should have no tokens")
	}
}

// 同一标识词先由带版本的事实写入、后被无版本事实覆盖时，已解析出的版本必须保留。
func TestProfilesVersionNotOverwritten(t *testing.T) {
	ps := NewProfiles()
	ps.AddService("h:6379", ServiceFact{Service: "redis", Version: "7.0.11"})
	ps.AddHit("h:6379", HitFact{ID: "redis"})

	if got := ps.RequiresTokens("h:6379")["redis"]; got != "7.0.11" {
		t.Fatalf("version = %q, want 7.0.11 (later empty version must not overwrite)", got)
	}
}

// 指纹标签要过滤空值与 "fingerprint" 占位标签，并汇总成全局标签集。
func TestProfilesTags(t *testing.T) {
	ps := NewProfiles()
	ps.AddHit("a:80", HitFact{ID: "foo", Tags: []string{"Redis", " fingerprint ", "", "mysql"}})

	tags := ps.Tags("a:80")
	for _, want := range []string{"redis", "mysql"} {
		if _, ok := tags[want]; !ok {
			t.Fatalf("missing tag %q: %v", want, tags)
		}
	}
	if _, ok := tags["fingerprint"]; ok {
		t.Fatalf("placeholder tag should be dropped: %v", tags)
	}

	global := ps.GlobalTags()
	if len(global) != 2 {
		t.Fatalf("global tags = %v, want redis+mysql", global)
	}
	if ps.Tags("b:80") != nil {
		t.Fatal("target without hits should have no tags")
	}
}

func TestProfilesHasRequiresAndLen(t *testing.T) {
	ps := NewProfiles()
	if ps.HasRequires() || ps.Len() != 0 {
		t.Fatal("empty profiles should have no requires")
	}
	// build 是一次性记忆化的：事实写入后、查询前不得先触发一次空 build，
	// 故这里用一个新实例验证「写入事实后即 HasRequires」。
	ps2 := NewProfiles()
	ps2.AddService("h:1", ServiceFact{Service: "ssh"})
	if !ps2.HasRequires() {
		t.Fatal("expected HasRequires once a fact is added")
	}
	if ps2.Len() != 1 {
		t.Fatalf("Len = %d, want 1", ps2.Len())
	}
}

// 空 target 不得建画像；nil 接收者调用要安全。
func TestProfilesEmptyTargetAndNilReceiver(t *testing.T) {
	ps := NewProfiles()
	ps.AddService("", ServiceFact{Service: "redis"})
	if ps.Len() != 0 {
		t.Fatalf("empty target should not create a profile, Len = %d", ps.Len())
	}

	var nilPs *Profiles
	if nilPs.HasRequires() || nilPs.Len() != 0 {
		t.Fatal("nil Profiles should be safe and empty")
	}
	if nilPs.RequiresTokens("x") != nil || nilPs.Tags("x") != nil || nilPs.GlobalTags() != nil {
		t.Fatal("nil Profiles should return nil views")
	}
}
