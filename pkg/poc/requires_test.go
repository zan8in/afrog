package poc

import "testing"

func TestParseRequire(t *testing.T) {
	cases := []struct {
		entry    string
		wantTech string
		wantRV   *RequireVersion
	}{
		{"jquery<3.5", "jquery", &RequireVersion{Tech: "jquery", Op: "<", Value: "3.5"}},
		{"thinkphp>=6.0", "thinkphp", &RequireVersion{Tech: "thinkphp", Op: ">=", Value: "6.0"}},
		// 比较符前后允许空格。
		{"nginx <= 1.24", "nginx", &RequireVersion{Tech: "nginx", Op: "<=", Value: "1.24"}},
		// 单个 = 归一化成 ==。
		{"apache shiro = 1.0", "apache shiro", &RequireVersion{Tech: "apache shiro", Op: "==", Value: "1.0"}},
		// 无比较符：行为与加入版本约束之前完全一致。
		{"WordPress", "wordpress", nil},
		{"  MySQL  ", "mysql", nil},
		// 形状不合法：退回无条件约束，保持旧行为。
		{"<3.5", "<3.5", nil},
		{"jquery<", "jquery<", nil},
		{"", "", nil},
	}
	for _, tc := range cases {
		tech, rv := ParseRequire(tc.entry)
		if tech != tc.wantTech {
			t.Fatalf("ParseRequire(%q) tech = %q, want %q", tc.entry, tech, tc.wantTech)
		}
		if (rv == nil) != (tc.wantRV == nil) {
			t.Fatalf("ParseRequire(%q) rv = %+v, want %+v", tc.entry, rv, tc.wantRV)
		}
		if rv != nil && *rv != *tc.wantRV {
			t.Fatalf("ParseRequire(%q) rv = %+v, want %+v", tc.entry, rv, tc.wantRV)
		}
	}
}

func TestRequireVersionSatisfied(t *testing.T) {
	rv := &RequireVersion{Tech: "jquery", Op: "<", Value: "3.5"}
	cases := []struct {
		version string
		want    bool
	}{
		{"3.4.1", true},
		{"3.5", false},
		{"3.6.0", false},
		// 版本未知：命中产品但拿不到版本，放行以免漏报。
		{"", true},
		{"   ", true},
	}
	for _, tc := range cases {
		if got := rv.Satisfied(tc.version); got != tc.want {
			t.Fatalf("Satisfied(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}

	// nil 约束恒成立。
	var nilRV *RequireVersion
	if !nilRV.Satisfied("1.0") {
		t.Fatal("nil RequireVersion should always be satisfied")
	}
}
