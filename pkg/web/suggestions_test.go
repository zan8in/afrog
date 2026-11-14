package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
)

// TestCheckDispatchGuard 锁定集群派发的目标白名单与拒绝语义。
func TestCheckDispatchGuard(t *testing.T) {
	t.Cleanup(func() { SetSecurityConfig(config.Security{}) })

	// 精确 host 只匹配自身，覆盖子域要写成 *.corp.example（与 guard 包口径一致）。
	SetSecurityConfig(config.Security{AllowTargets: []string{"*.corp.example", "10.0.0.0/24"}})

	if reason := checkDispatchGuard(ScanCreateRequest{Targets: []string{"https://api.corp.example/x"}}); reason != "" {
		t.Fatalf("白名单内目标不应被拒绝: %s", reason)
	}
	if reason := checkDispatchGuard(ScanCreateRequest{Targets: []string{"https://evil.example"}}); reason == "" {
		t.Fatalf("白名单外目标必须被拒绝")
	}
	// 无法校验目标时（空目标）一律拒绝：偏安全的一侧。
	if reason := checkDispatchGuard(ScanCreateRequest{}); reason == "" {
		t.Fatalf("未提供目标时，配置了白名单就必须拒绝")
	}

	// deny 模式与白名单无关：即使目标为空也拒绝。
	SetSecurityConfig(config.Security{Actions: map[string]string{"cluster-dispatch": "deny"}})
	if reason := checkDispatchGuard(ScanCreateRequest{Targets: []string{"a.example"}}); reason == "" {
		t.Fatalf("deny 模式下必须拒绝")
	}
	if !strings.Contains(checkDispatchGuard(ScanCreateRequest{Targets: []string{"a.example"}}), "拒绝") {
		t.Fatalf("拒绝原因应可直接展示给调用方")
	}
}

// TestSuggestionRoutesRequireAuth 锁定建议与闸门接口必须登录后访问：
// 前者暴露资产全貌，后者暴露安全策略与裁决记录。
func TestSuggestionRoutesRequireAuth(t *testing.T) {
	h := mustRouter(t)

	for _, path := range []string{"/api/suggestions", "/api/security/policy"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Accept", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s = %d, want 401", path, rec.Code)
		}
	}
}

// TestBuildSuggestions 锁定四条建议规则的数据来源与互斥关系。
func TestBuildSuggestions(t *testing.T) {
	withProjectFixture(t)

	// 从未扫描的资产。
	if _, err := sqlite.CreateAssets("manual", "", nil, []sqlite.AssetInput{
		{Address: "https://never.example", Type: "url"},
		// 脏资产：把端口误存成主机。语法上能入库，但不能出现在「一键扫描」里。
		{Address: "21", Type: "domain"},
	}); err != nil {
		t.Fatalf("CreateAssets: %v", err)
	}
	// 陈旧资产规则由 sqlite 包的 TestSuggestionSources 覆盖：它的时间戳无法通过
	// 公开接口构造，这里只验证 web 层的拼装与互斥。
	// 覆盖空洞：有流量，全部检测器跳过。
	if err := sqlite.UpsertPassiveCoverage([]sqlite.PassiveCoverage{
		{ProjectID: "", Host: "gap.example", Detector: "sqli", State: "skipped", Samples: 1, Skipped: 1},
	}); err != nil {
		t.Fatalf("UpsertPassiveCoverage: %v", err)
	}
	// 未入台账的被动命中。
	if _, _, _, err := sqlite.UpsertPassiveFinding(sqlite.PassiveFinding{
		Fingerprint: "p1", Detector: "sqli", Title: "SQL 注入", Target: "https://never.example/x",
	}); err != nil {
		t.Fatalf("UpsertPassiveFinding: %v", err)
	}

	items := buildSuggestions()
	byID := map[string]suggestion{}
	for _, it := range items {
		byID[it.ID] = it
	}
	for _, id := range []string{"unscanned-assets", "coverage-gap", "unpromoted-findings"} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("缺少建议 %s，实际 = %+v", id, items)
		}
	}

	unscanned := byID["unscanned-assets"]
	if unscanned.Count != 1 || len(unscanned.Action.Targets) != 1 || unscanned.Action.Targets[0] != "https://never.example" {
		t.Fatalf("未扫描资产建议 = %+v，want 只含 never.example", unscanned)
	}
	for _, target := range unscanned.Action.Targets {
		if target == "21" {
			t.Fatalf("脏资产 21 不应进入扫描目标")
		}
	}
	if byID["coverage-gap"].Action.Href == "" {
		t.Fatalf("覆盖空洞建议应给出跳转入口")
	}
}
