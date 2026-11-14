# afrog Agent 原生改造 · 端到端验收回归报告

- 日期：2026-11-14
- 判定依据：设计稿 [afrog-agent-native-architecture.md](file:///Users/zanbin/gowork/github/zan8in/afrog/docs/plan/afrog-agent-native-architecture.md) §12「验收指标」
- 测试入口：[acceptance_test.go](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/mcp/acceptance_test.go)（`TestAgentNativeAcceptanceE2E`）
- 生成命令：`AFROG_ACCEPTANCE_REPORT=/tmp/acceptance-report.json go test ./pkg/mcp/ -run TestAgentNativeAcceptanceE2E -count=1`

## 1. 结论

| 指标（§12） | 目标 | 实测 | 判定 |
|---|---|---|---|
| Agent 端到端成功率（目标 → 可重放证据） | ≥ 90% | 100%（8/8） | 通过 |
| Evidence 重放一致率 | ≥ 99% | 100%（8/8） | 通过 |
| 误报率 | 不高于现有水平 | agent 0 例 / 旧引擎 0 例 | 通过 |
| 旧 CLI / SDK / gRPC 回归 | 零破坏 | 全量 `go test ./...` 全绿 | 通过 |
| 每条确认漏洞的平均 token 成本 | 相比「全自主 agent」下降一个量级 | 无对照基线 | 不可测（不属本回归） |

机器可读结果：

```json
{
  "suite": "afrog agent-native e2e acceptance",
  "generated_at": "2026-11-14T22:45:20+08:00",
  "positives": 8,
  "successes": 8,
  "success_rate": 1,
  "evidences": 8,
  "replays": 8,
  "replay_consistent": 8,
  "replay_rate": 1,
  "negatives": 5,
  "agent_false_positives": 0,
  "legacy_false_positives": 0,
  "success_target": 0.9,
  "replay_target": 0.99
}
```

## 2. 方法

**全离线**：`httptest` 静态靶标 + 临时 `HOME` 下的本地 PoC（`~/.config/afrog/pocs-my/<id>.yaml`），不访问网络、不依赖真实靶机。达标门槛写在测试断言里（低于阈值即失败），不是人工看数。

**语料 13 条**（8 正例 + 5 负例），覆盖：

- 规则形态：GET + 状态码 + 正文匹配、大小写不敏感匹配（`ibcontains`）、POST + 正文匹配、多规则 `r0() && r1()`。
- severity 五档：info / low / medium / high / critical。
- 负例陷阱：正文无 marker、大小写不符、状态码 500（正文有 marker 但状态不匹配）、多规则只命中一条。

**每条正例走完整链路**（与 MCP / REST / gRPC 三面共用的同一套 handler）：

1. 种攻击面图：`EnsureTechGraph(端点 → 技术栈 → 候选 PoC)`；
2. `plan.next` 必须就这条用例给出 `verify.poc` 提议；
3. `verify.poc` 出证据；
4. 落库 `InsertEvidence`；
5. `observe.evidence` 按内容寻址 id 回读，内容必须一致；
6. `verify.replay` 只凭 `evd_` id 复核，必须 `replayed && consistent`。

**误报口径（同语料对比旧引擎）**：同一份正/负例语料，分别走 agent 路径与旧引擎（直连 [pkg/sdk](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/sdk)，即既有 CLI 的检测路径）扫描；负例上 agent 与旧引擎都不得命中，正例上旧引擎必须命中（否则语料不成立，误报对照无意义）。

## 3. 运行时发现并修复的缺陷

回归首跑时 8 条正例**全部**重放不一致（`replay_consistent=0/8`），其余指标已达标。定位为一条真实产品缺陷：

- **现象**：`verify.replay` 对任意非根路径 PoC 都复现不了。
- **根因**：`Evidence.Target` 记的是「命中后的完整 URL」（base + 规则 path），而 `verify.replay` 与落库的 `replay.command` 都拿它当 base **重跑同一个 PoC** → 规则 path 被再拼一次 → `http://host/foo/foo` → 404。
- **定级**：违反设计稿 §4.4 硬要求「`replay.command` 必须真的能跑通；跑不通的 Evidence 视为未完成」，以及 §10 P0 验收「`verify.replay` 能跑通且 digest 一致」。
- **修复**：[evidence.go](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/runner/evidence.go#L30-L41) 的 `buildEvidence` 改用**种子目标**（扫描/verify 传入的 base）作为 `Evidence.Target`；每步精确命中的 URL 继续由 `steps[].Request.URL` 保留，观测信息不丢。
- **影响面**：`Evidence.Target` 语义变化会改变 digest 与 `evd_` id（设计期，无历史数据包袱）；既有测试未断言该字段。
- **此前为何未暴露**：既有 verify 测试的 PoC 都是 `path: /`（[verify_integration_test.go](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/mcp/verify_integration_test.go#L55)），base path 为空，拼接退化为空操作，缺陷被掩盖。

修复后新增断言锁定语义（[evidence_test.go](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/runner/evidence_test.go#L73-L83)）：证据 target 必须等于种子目标、确认步骤 URL 必须等于完整命中 URL、`replay.command` 必须指向种子目标。

## 4. 零破坏验证

| 检查 | 结果 |
|---|---|
| `go build ./...` | 通过 |
| `go vet ./...` | 通过（仅 `pkg/config` 既有测试告警，均为未改动文件） |
| `gofmt -l pkg/ cmd/` | 通过（仅 `pkg/runner/extractor_test.go` 既有，未改动文件） |
| `go test ./...` | 全绿，48 个包 `ok`，无 `FAIL` / panic |

覆盖面含既有回归证据：`pkg/sdk`（SDK）、`pkg/scanapi`（gRPC `AgentService`）、`pkg/web`（REST `/api/v1/call`）、`pkg/mcp`（MCP）、`pkg/evidence`、`pkg/runner`、`pkg/pocsign` 等。

## 5. 复现

```bash
go test ./pkg/mcp/ -run TestAgentNativeAcceptanceE2E -count=1 -v
# 需要机器可读结果时：
AFROG_ACCEPTANCE_REPORT=./acceptance-report.json \
  go test ./pkg/mcp/ -run TestAgentNativeAcceptanceE2E -count=1
```

## 6. 局限与前提

- **token 成本**：设计稿要求「相比全自主 agent 下降一个量级」，本项目当前无该对照基线，故标为不可测，不纳入本回归。
- **语料性质**：为离线合成靶标，用于锁住「端到端链路 + 重放一致性 + 误报不回归」这三条工程契约，不等价于真实 CVE 靶机的检出广度（广度由既有 PoC 套件与对应测试覆盖）。
- **重放前提**：重放一致性依赖靶标对同一路径返回同一响应（设计前提：证据可复核基于目标行为未变）。
