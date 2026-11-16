package gating

import (
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/assetgraph"
	"github.com/zan8in/afrog/v3/pkg/poc"
)

// ---------- requires 硬依赖 ----------

func TestDecide_Requires_Strict_NoFingerprint(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}}}
	d := Decide("127.0.0.1:3306", p, true, nil, Options{})
	if d.Run {
		t.Fatalf("expected skip when strict and no fingerprint tags: %+v", d)
	}
	if d.Source != SourceNegative {
		t.Fatalf("source = %q, want %q", d.Source, SourceNegative)
	}
}

func TestDecide_Requires_Opportunistic_NoFingerprint(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}, RequiresMode: "opportunistic"}}
	d := Decide("127.0.0.1:3306", p, true, nil, Options{})
	if !d.Run || d.Source != SourceFallback {
		t.Fatalf("expected fallback run when opportunistic and no fingerprint tags: %+v", d)
	}
}

func TestDecide_Requires_Strict_Match(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}}}
	ps := assetgraph.NewProfiles()
	ps.AddService("127.0.0.1:3306", assetgraph.ServiceFact{Service: "mysql"})
	d := Decide("127.0.0.1:3306", p, true, ps, Options{})
	if !d.Run || d.Source != SourceRequires {
		t.Fatalf("expected requires run when fingerprint matches: %+v", d)
	}
}

// requires 命中「指纹 PoC 的 id」（而非 tag）时同样放行。
func TestDecide_Requires_MatchFingerprintPocID(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"ajp-protocol-detect"}}}
	ps := assetgraph.NewProfiles()
	ps.AddHit("127.0.0.1:8009", assetgraph.HitFact{ID: "ajp-protocol-detect", Tags: []string{"ajp", "tomcat"}})
	if d := Decide("127.0.0.1:8009", p, true, ps, Options{}); !d.Run {
		t.Fatalf("expected run when requires matches fingerprint poc id: %+v", d)
	}
}

func TestDecide_Requires_Strict_Mismatch(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}}}
	ps := assetgraph.NewProfiles()
	ps.AddService("127.0.0.1:3306", assetgraph.ServiceFact{Service: "redis"})
	if d := Decide("127.0.0.1:3306", p, true, ps, Options{}); d.Run {
		t.Fatalf("expected skip when requires does not match: %+v", d)
	}
}

func TestDecide_Requires_Strict_EmptyKey(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}}}
	ps := assetgraph.NewProfiles()
	ps.AddService("127.0.0.1:3306", assetgraph.ServiceFact{Service: "mysql"})
	if d := Decide("", p, true, ps, Options{}); d.Run {
		t.Fatalf("expected skip when strict and key cannot be resolved: %+v", d)
	}
}

func TestDecide_Requires_VersionConstraint(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"jquery<3.5"}}}
	build := func(version string) *assetgraph.Profiles {
		ps := assetgraph.NewProfiles()
		ps.AddTech("a.example:80", assetgraph.TechFact{Name: "jQuery", Version: version})
		return ps
	}
	if d := Decide("a.example:80", p, false, build("3.4.1"), Options{}); !d.Run {
		t.Fatalf("expected run when version satisfies constraint: %+v", d)
	}
	if d := Decide("a.example:80", p, false, build("3.6.0"), Options{}); d.Run {
		t.Fatalf("expected skip when version violates constraint: %+v", d)
	}
	if d := Decide("a.example:80", p, false, build(""), Options{}); !d.Run {
		t.Fatalf("expected run when version unknown: %+v", d)
	}
	absent := assetgraph.NewProfiles()
	absent.AddTech("a.example:80", assetgraph.TechFact{Name: "nginx", Version: "1.24"})
	if d := Decide("a.example:80", p, false, absent, Options{}); d.Run {
		t.Fatalf("expected skip when tech is absent: %+v", d)
	}
}

func TestDecide_Requires_WithWebAndPortFingerprint(t *testing.T) {
	ps := assetgraph.NewProfiles()
	ps.AddTech("127.0.0.1:8080", assetgraph.TechFact{Name: "WordPress", RuleID: "wordpress", Category: "cms"})
	p := poc.Poc{Info: poc.Info{Requires: []string{"wordpress"}}}
	if d := Decide("127.0.0.1:8080", p, false, ps, Options{}); !d.Run {
		t.Fatalf("expected run when requires matches web fingerprint: %+v", d)
	}
	if d := Decide("127.0.0.1:8081", p, false, ps, Options{}); d.Run {
		t.Fatalf("expected skip when target has no matching web fingerprint: %+v", d)
	}

	port := assetgraph.NewProfiles()
	port.AddService("10.0.0.1:6379", assetgraph.ServiceFact{Service: "redis", Product: "Redis", Version: "7.0.11"})
	rp := poc.Poc{Info: poc.Info{Requires: []string{"redis"}}}
	if d := Decide("10.0.0.1:6379", rp, true, port, Options{}); !d.Run {
		t.Fatalf("expected run when port fingerprint identifies redis: %+v", d)
	}
	if d := Decide("10.0.0.2:6379", rp, true, port, Options{}); d.Run {
		t.Fatalf("expected skip when host has no port fingerprint: %+v", d)
	}
	lt8 := poc.Poc{Info: poc.Info{Requires: []string{"redis<8"}}}
	if d := Decide("10.0.0.1:6379", lt8, true, port, Options{}); !d.Run {
		t.Fatalf("expected run when 7.0.11 satisfies redis<8: %+v", d)
	}
}

func TestDecide_TestMode(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}}}
	if d := Decide("127.0.0.1:3306", p, true, nil, Options{TestMode: true}); !d.Run {
		t.Fatalf("expected run when test mode is enabled: %+v", d)
	}
}

// ---------- 指纹过滤门控 ----------

func fingerprintProfiles() *assetgraph.Profiles {
	ps := assetgraph.NewProfiles()
	ps.AddHit("a.example:80", assetgraph.HitFact{ID: "redis-detect", Tags: []string{"redis"}})
	return ps
}

func TestDecide_FingerprintFilter_Strict_EmptyTargetTags(t *testing.T) {
	p := poc.Poc{Id: "x", Info: poc.Info{Tags: "redis"}}
	d := Decide("b.example:80", p, false, fingerprintProfiles(), Options{FingerprintFilterMode: "strict"})
	if d.Run {
		t.Fatalf("expected skip when strict and target has no fingerprint tags: %+v", d)
	}
}

func TestDecide_FingerprintFilter_Opportunistic_EmptyTargetTags(t *testing.T) {
	p := poc.Poc{Id: "x", Info: poc.Info{Tags: "redis"}}
	d := Decide("b.example:80", p, false, fingerprintProfiles(), Options{FingerprintFilterMode: "opportunistic"})
	if !d.Run {
		t.Fatalf("expected run when opportunistic and target has no fingerprint tags: %+v", d)
	}
}

func TestDecide_FingerprintFilter_MismatchWithEvidence(t *testing.T) {
	ps := assetgraph.NewProfiles()
	ps.AddHit("a.example:80", assetgraph.HitFact{ID: "redis-detect", Tags: []string{"redis"}})
	ps.AddHit("b.example:80", assetgraph.HitFact{ID: "mysql-detect", Tags: []string{"mysql"}})
	p := poc.Poc{Id: "x", Info: poc.Info{Tags: "redis"}}
	d := Decide("b.example:80", p, false, ps, Options{FingerprintFilterMode: "opportunistic"})
	if d.Run {
		t.Fatalf("expected skip when target tags do not match poc tags: %+v", d)
	}
}

func TestDecide_FingerprintFilter_NotAppSpecific(t *testing.T) {
	p := poc.Poc{Id: "x", Info: poc.Info{Tags: "weird"}}
	d := Decide("a.example:80", p, false, fingerprintProfiles(), Options{FingerprintFilterMode: "strict"})
	if !d.Run {
		t.Fatalf("expected run when poc is not app-specific: %+v", d)
	}
}

func TestDecide_FingerprintFilter_NetOnlyBypasses(t *testing.T) {
	p := poc.Poc{Id: "x", Info: poc.Info{Tags: "redis"}}
	d := Decide("b.example:80", p, true, fingerprintProfiles(), Options{FingerprintFilterMode: "strict"})
	if !d.Run {
		t.Fatalf("expected net-only poc to bypass fingerprint filter: %+v", d)
	}
}

// ---------- 推断式否定（applies-to + 互斥矩阵） ----------

func TestDecide_InferredNegative_AppliesToExcluded(t *testing.T) {
	ps := assetgraph.NewProfiles()
	ps.AddTech("h:80", assetgraph.TechFact{Name: "PHP", RuleID: "php", Category: "language", Confidence: "certain"})
	p := poc.Poc{Info: poc.Info{AppliesTo: []string{"weblogic"}}}

	// 默认（safe）：不启用否定时兜底放行。
	if d := Decide("h:80", p, false, ps, Options{}); !d.Run || d.Source != SourceFallback {
		t.Fatalf("expected fallback run when inferred negative disabled: %+v", d)
	}
	// balanced 起：画像高置信识别为 PHP，排除 Java 中间件 weblogic。
	d := Decide("h:80", p, false, ps, Options{Level: LevelBalanced})
	if d.Run || d.Source != SourceNegative {
		t.Fatalf("expected inferred negative skip: %+v", d)
	}
}

func TestDecide_InferredNegative_ProbableDoesNotExclude(t *testing.T) {
	ps := assetgraph.NewProfiles()
	ps.AddTech("h:80", assetgraph.TechFact{Name: "PHP", RuleID: "php", Category: "language", Confidence: "probable"})
	p := poc.Poc{Info: poc.Info{AppliesTo: []string{"weblogic"}}}
	if d := Decide("h:80", p, false, ps, Options{Level: LevelBalanced}); !d.Run {
		t.Fatalf("expected run when only probable evidence exists: %+v", d)
	}
}

func TestDecide_InferredNegative_RequiresRunWins(t *testing.T) {
	ps := assetgraph.NewProfiles()
	ps.AddTech("h:80", assetgraph.TechFact{Name: "PHP", RuleID: "php", Category: "language", Confidence: "certain"})
	// requires 命中是正向证据，压过推断式否定。
	p := poc.Poc{Info: poc.Info{Requires: []string{"php"}, AppliesTo: []string{"weblogic"}}}
	d := Decide("h:80", p, false, ps, Options{Level: LevelBalanced})
	if !d.Run || d.Source != SourceRequires {
		t.Fatalf("expected requires run to win over inferred negative: %+v", d)
	}
}

// 否定证据严格按目标键隔离：一个键被高置信识别为 PHP，不得连坐到同一份画像里
// 另一个没有否定证据的键。这条属性是「误跳=漏报」的唯一防线——否定一旦变成全局
// 判定，多端口主机上无关的 Java 中间件 PoC 会被整片误跳，必须在单测层面钉死。
func TestDecide_InferredNegative_ScopedToKey(t *testing.T) {
	ps := assetgraph.NewProfiles()
	ps.AddTech("php.example:80", assetgraph.TechFact{Name: "PHP", RuleID: "php", Category: "language", Confidence: "certain"})
	ps.AddTech("plain.example:80", assetgraph.TechFact{Name: "nginx", RuleID: "nginx", Category: "server", Confidence: "certain"})
	p := poc.Poc{Info: poc.Info{AppliesTo: []string{"weblogic"}}}

	if d := Decide("php.example:80", p, false, ps, Options{Level: LevelBalanced}); d.Run || d.Source != SourceNegative {
		t.Fatalf("expected php key to skip weblogic poc: %+v", d)
	}
	if d := Decide("plain.example:80", p, false, ps, Options{Level: LevelBalanced}); !d.Run || d.Source != SourceFallback {
		t.Fatalf("expected inferred negative to stay scoped to its own key: %+v", d)
	}
}

func TestDecide_AppliesToAloneNeverRuns(t *testing.T) {
	// applies-to 只做减法：没有 requires、没有否定证据时，只能兜底放行。
	p := poc.Poc{Info: poc.Info{AppliesTo: []string{"weblogic"}}}
	d := Decide("h:80", p, false, assetgraph.NewProfiles(), Options{Level: LevelBalanced})
	if !d.Run || d.Source != SourceFallback {
		t.Fatalf("expected fallback run; applies-to must never itself trigger a run: %+v", d)
	}
}

// ---------- 档位 ----------

// off 档：门控全关，连 requires 硬依赖也不裁剪，退回全量放行。
func TestDecide_LevelOff_RunsEverything(t *testing.T) {
	p := poc.Poc{Id: "x", Info: poc.Info{Requires: []string{"mysql"}, Tags: "redis"}}
	d := Decide("b.example:80", p, false, fingerprintProfiles(), Options{Level: LevelOff, FingerprintFilterMode: "strict"})
	if !d.Run || d.Source != SourceFallback {
		t.Fatalf("expected off level to run everything: %+v", d)
	}
}

// safe 档：既有两道裁决照旧，但不引入新增否定。
func TestDecide_LevelSafe_KeepsExistingGatesOnly(t *testing.T) {
	ps := assetgraph.NewProfiles()
	ps.AddTech("h:80", assetgraph.TechFact{Name: "PHP", RuleID: "php", Category: "language", Confidence: "certain"})
	// 指纹过滤仍生效（strict + 目标无 tag → 跳过）。
	filter := poc.Poc{Id: "x", Info: poc.Info{Tags: "redis"}}
	if d := Decide("b.example:80", filter, false, fingerprintProfiles(), Options{Level: LevelSafe}); d.Run {
		t.Fatalf("expected safe level to keep fingerprint filter: %+v", d)
	}
	// 新增否定不生效（applies-to 被排除也不跳）。
	inferred := poc.Poc{Info: poc.Info{AppliesTo: []string{"weblogic"}}}
	if d := Decide("h:80", inferred, false, ps, Options{Level: LevelSafe}); !d.Run {
		t.Fatalf("expected safe level to skip inferred negative: %+v", d)
	}
}

// CMS 家族互斥只在 aggressive 档生效；balanced 档不启用。
func TestDecide_LevelBalanced_vs_Aggressive_CMS(t *testing.T) {
	ps := assetgraph.NewProfiles()
	ps.AddTech("h:80", assetgraph.TechFact{Name: "WordPress", RuleID: "wordpress", Category: "cms", Confidence: "certain"})
	p := poc.Poc{Info: poc.Info{AppliesTo: []string{"drupal"}}}

	if d := Decide("h:80", p, false, ps, Options{Level: LevelBalanced}); !d.Run {
		t.Fatalf("expected balanced level to keep CMS poc running: %+v", d)
	}
	d := Decide("h:80", p, false, ps, Options{Level: LevelAggressive})
	if d.Run || d.Source != SourceNegative {
		t.Fatalf("expected aggressive level to skip CMS mutual-exclusion: %+v", d)
	}
}

// 空档位归一为 safe：与显式 safe 行为一致。
func TestDecide_EmptyLevelIsSafe(t *testing.T) {
	p := poc.Poc{Info: poc.Info{Requires: []string{"mysql"}}}
	if d := Decide("127.0.0.1:3306", p, true, nil, Options{}); d.Run {
		t.Fatalf("expected empty level to behave like safe (strict skip): %+v", d)
	}
}

// ---------- 归因统计 ----------

func TestStats_RecordAndReport(t *testing.T) {
	s := NewStats()
	s.SetLoaded(3)
	s.Record(Decision{Run: true, Source: SourceRequires})
	s.Record(Decision{Source: SourceNegative, Reason: "requires 未命中(strict): mysql"})
	s.Record(Decision{Source: SourceNegative, Reason: "requires 未命中(strict): mysql"})
	s.Record(Decision{Run: true, Source: SourceFallback})

	if s.Requires() != 1 || s.Negative() != 2 || s.Fallback() != 1 {
		t.Fatalf("counts = (%d,%d,%d), want (1,2,1)", s.Requires(), s.Negative(), s.Fallback())
	}
	if s.Executed() != 2 {
		t.Fatalf("executed = %d, want 2", s.Executed())
	}
	report := s.Report()
	for _, want := range []string{"加载 PoC", "requires 命中放行 : 1", "否定证据跳过      : 2", "兜底放行          : 1", "requires 未命中(strict): mysql"} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
}
