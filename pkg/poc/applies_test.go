package poc

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v2"
)

func caretSet(t *testing.T, got []string) map[string]bool {
	t.Helper()
	m := make(map[string]bool, len(got))
	for _, g := range got {
		m[g] = true
	}
	return m
}

func TestInferAppliesTo_FromTags(t *testing.T) {
	info := Info{Tags: "weblogic,weak-login,rce,cve,cve2020,detect"}
	got := InferAppliesTo("/pocs/afrog-pocs/vulnerability/weblogic-weak-login.yaml", info)
	if !reflect.DeepEqual(got, []string{"weblogic"}) {
		t.Fatalf("want [weblogic], got %v", got)
	}
}

func TestInferAppliesTo_KeenTechTags(t *testing.T) {
	info := Info{Tags: "nacos,derby,rce"}
	got := caretSet(t, InferAppliesTo("/pocs/afrog-pocs/vulnerability/nacos-derby-rce.yaml", info))
	for _, want := range []string{"nacos", "derby"} {
		if !got[want] {
			t.Fatalf("want %q in %v", want, got)
		}
	}
	if got["rce"] {
		t.Fatalf("vuln class tag rce must be dropped: %v", got)
	}
}

func TestInferAppliesTo_FromFilenameWhenTagsAreMetaOnly(t *testing.T) {
	// tags 只有元信息时，用文件名首段兜底。
	info := Info{Tags: "rce,cve,cve2024", Name: "HTTP File Server Template_injection"}
	got := InferAppliesTo("/pocs/afrog-pocs/CVE/2024/CVE-2024-23692.yaml", info)
	if len(got) != 0 {
		t.Fatalf("cve-named file and http-prefixed name should yield nothing, got %v", got)
	}
}

func TestInferAppliesTo_FilenameLeadingToken(t *testing.T) {
	info := Info{Tags: "rce,cve"}
	got := InferAppliesTo("/pocs/afrog-pocs/vulnerability/thinkphp-detect.yaml", info)
	if !reflect.DeepEqual(got, []string{"thinkphp"}) {
		t.Fatalf("want [thinkphp], got %v", got)
	}
}

func TestInferAppliesTo_NameFallback(t *testing.T) {
	// tags 与文件名都拿不到标识时，才用 info.name 兜底。
	info := Info{Tags: "rce,cve,cve2024", Name: "OpenMetadata RCE"}
	got := InferAppliesTo("/pocs/afrog-pocs/CVE/2024/CVE-2024-28255.yaml", info)
	if !reflect.DeepEqual(got, []string{"openmetadata"}) {
		t.Fatalf("want [openmetadata], got %v", got)
	}
}

func TestInferAppliesTo_SpaceVariant(t *testing.T) {
	// 含空格的标签额外补连字符变体，与 requires 门控口径一致。
	info := Info{Tags: "apache shiro,rce"}
	got := caretSet(t, InferAppliesTo("/pocs/x.yaml", info))
	if !got["apache-shiro"] {
		t.Fatalf("want apache-shiro variant in %v", got)
	}
}

func TestInferAppliesTo_NoSignal(t *testing.T) {
	if got := InferAppliesTo("", Info{}); len(got) != 0 {
		t.Fatalf("want empty, got %v", got)
	}
	if got := InferAppliesTo("/pocs/a.yaml", Info{Tags: "weak-login,default-password"}); len(got) != 0 {
		t.Fatalf("want empty for vuln-class-only tags, got %v", got)
	}
}

func TestFillAppliesTo_ExplicitWins(t *testing.T) {
	info := Info{Tags: "weblogic", AppliesTo: []string{"custom-tech"}}
	info.FillAppliesTo("/pocs/weblogic-x.yaml")
	if !reflect.DeepEqual(info.AppliesTo, []string{"custom-tech"}) {
		t.Fatalf("explicit applies-to must win, got %v", info.AppliesTo)
	}
}

func TestFillAppliesTo_Inferred(t *testing.T) {
	info := Info{Tags: "weblogic,weak-login"}
	info.FillAppliesTo("/pocs/afrog-pocs/vulnerability/weblogic-weak-login.yaml")
	if !reflect.DeepEqual(info.AppliesTo, []string{"weblogic"}) {
		t.Fatalf("want [weblogic], got %v", info.AppliesTo)
	}
}

func TestInfoUnmarshalAppliesTo(t *testing.T) {
	raw := []byte("id: demo\ninfo:\n  name: demo\n  severity: low\n  applies-to: Weblogic, weak-login\n")
	var pm PocMeta
	if err := yaml.Unmarshal(raw, &pm); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// normalizeRequires 会小写、去重并排序。
	if !reflect.DeepEqual(pm.Info.AppliesTo, []string{"weak-login", "weblogic"}) {
		t.Fatalf("want [weak-login weblogic], got %v", pm.Info.AppliesTo)
	}
}
