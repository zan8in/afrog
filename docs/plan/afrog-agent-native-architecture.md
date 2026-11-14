# afrog Agent-Native 架构设计

> 定位：把 afrog 从「一个扫描器」重构成「AI 时代可被编排的观测、执行与验证底座」。
> 本文定义**完整的对象契约与分层**，一次定死；实现分期推进，后续不返工。
>
> 关系：本文接续 [afrog-grpc-protocol.md](./afrog-grpc-protocol.md) 的第 15 行遗留事项——该 PRD 已把 MCP 适配层列为「第四层」并预留了公开接口，本文即第四层及其前置的状态面/证据面设计。

## 1. 一句话结论

不再和 ARTEX 比「谁更自主」，而是把 afrog 变成 **agent 唯一可信的手和眼睛**：

- 决策交给模型（可替换）；
- **执行、观测、证据、状态** 留在 afrog（不可替换）。

判断标准只有一条：**Agent 能不能只靠 afrog 的工具，从目标走到一条可重放的证据。** 能，afrog 就不会被时代抛下。

## 2. 现状盘点

### 2.1 已有资产（复用，不重写）

| 层 | 位置 | 现状 |
|---|---|---|
| 检测引擎 | [pkg/runner](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/runner) | PoC 执行、CEL 校验、extractor、OOB、brute、断点续跑 |
| PoC 运行时 | [pkg/protocols](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/protocols) | http / raw / tcp / ssl / gox / javascript |
| 前置阶段 | [pkg/portscan](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/portscan)、[pkg/webscan](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/webscan) | 端口、服务指纹、Web 指纹、TLS、favicon |
| 被动引擎 | [pkg/passive](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/passive) | 代理抓包、两阶段流水线、注入点、相似度、覆盖度 |
| 控制面 | [pkg/scantask](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/scantask)、[pkg/scanapi](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/scanapi) | 任务管理、gRPC、事件流、集群 |
| 数据面 | [pkg/db/sqlite](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/db/sqlite) | result / asset / asset_edge / probe / passive_finding / ledger |
| 对外形态 | CLI、[pkg/sdk](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/sdk)、gRPC、Web 控制台 | 四套入口，语义已基本对齐 |
| 安全底座 | [pkg/guard](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/guard)、[pkg/capability](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/capability) | scope、能力分级（declarative/network/exec） |
| AI | [pkg/web/ai.go](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/web/ai.go) | 研判 / 摘要 / 参数推荐，点击式 |

### 2.2 关键缺口

| # | 缺口 | 后果 |
|---|---|---|
| G1 | 工作单元是「一次扫描」，不是「一个动作」 | Agent 想「只跑这一个 PoC、只打这一个点」做不到 |
| G2 | 证据是字符串/裸报文，没有统一的 ID、摘要和重放能力 | Agent 无法消费，人也无法一键复核 |
| G3 | 状态散落在 7 张表，没有统一的世界模型 | Agent 每次都要重新拼目标结构，贵且飘 |
| G4 | 观测流只存在于内存与 UI，不可订阅、不可回溯 | Agent 拿不到 ground truth |
| G5 | 策略只有 scope，没有按动作/能力的预算与审计 | 不敢让 agent 无人值守 |
| G6 | 没有面向 agent 的稳定契约（schema / 幂等 / 分页） | 每次接入都是一次性适配 |

> G1 是最深的一处：它要求改执行模型。用户已明确「核心功能该改就改」，本文按此前提设计。

## 3. 总体架构：三面一图

```
            ┌──────────────── 决策面（可替换）────────────────┐
            │  Planner · PoC Drafter · Judge   （LLM / 规则）   │
            └───────────────▲───────────────────┬─────────────┘
                 读状态/观测 │                   │ 只产出 Action Proposal
            ┌───────────────┴───────────────────▼─────────────┐
            │              工具面（Tool Surface）              │
            │   MCP  ·  gRPC  ·  REST     统一动词 + 策略门控     │
            └───────────────▲───────────────────┬─────────────┘
                            │                   │
            ┌───────────────┴──────┐   ┌────────▼─────────────┐
            │  状态面（State）       │   │  执行面（Execution）  │
            │  攻击面图 / Finding   │◄──│  runner · portscan    │
            │  Evidence / Ledger    │   │  webscan · passive    │
            └───────────────▲──────┘   └────────┬─────────────┘
                            │                   │
                            └──── 观测面（Observation，append-only）◄┘
```

四条硬规则：

1. **决策面永不直接发包**，只能提交 `Action`；执行面永不判断「是不是漏洞」，只产出 `Observation` 与 `Evidence`。
2. **观测面只追加**，不改写；状态面是观测的投影，可重建。
3. **所有跨面通信走同一套对象契约**，不允许 UI 专用字段或 SDK 专用捷径。
4. **每个动作都有能力等级与预算**，策略门控在执行面之前，不在 UI。

## 4. 核心对象契约（冻结版 v1）

五个对象，全部 JSON 可表达，全部带稳定 ID。

### 4.1 Ref —— 全局引用

```
<kind>_<base32(sha256(canonical))[:16]>
```

| kind | canonical | 说明 |
|---|---|---|
| `asset` | 归一化地址 | 沿用现有 `asset.id` 生成策略，不引入第二套 |
| `endpoint` | `scheme://host:port/path`（不含 query） | 新增 |
| `param` | `endpoint_id + location + name` | 新增 |
| `poc` | `poc.id` | 现有 |
| `obs` | `source + canonical(payload)` 的前 16 字节摘要 | 新增 |
| `evd` | 见 4.4 | 新增 |
| `fnd` | `project_id + subject_ref + vuln_class + fingerprint` | 与现有被动唯一索引同构 |

内容寻址的意义：跨节点、跨进程、跨任务天然可比较、可去重，Agent 重试不会造重复数据。

### 4.2 Observation —— 看到了什么

```json
{
  "id": "obs_...",
  "seq": 10241,
  "ts": "2026-11-14T10:00:00Z",
  "project_id": "p_...",
  "source": "passive|portscan|webscan|http|oob|extract",
  "subject": "asset_...|endpoint_...|param_...",
  "kind": "http_transaction|http_passive|port_open|tech|tls|oob_hit|extraction|dns",
  "payload": { },
  "digest": "sha256:...",
  "action_id": "act_..."
}
```

约束：**原始流量默认不落库**（沿用现有原则），只落元数据 + digest + 命中片段；`payload` 里可含引用到临时存储的句柄。

### 4.3 Action —— 要做什么

```json
{
  "id": "act_...",
  "kind": "probe_http | port_scan | web_fingerprint | run_poc | replay_evidence | brute | oob_wait",
  "target": "endpoint_...",
  "params": { },
  "poc_id": "CVE-2024-XXXXX",
  "capability": "declarative|network|exec",
  "budget": { "requests": 20, "duration_ms": 30000, "tokens": 0 },
  "idempotency_key": "sha256:...",
  "dry_run": false,
  "policy_verdict": { "allow": true, "rule": "safe-mode" },
  "actor": "agent:artex | human:liu | schedule:nightly"
}
```

**这是 G1 的解法**：Action 是原子工作单元，`ScanTask` 退化为 `Batch<Action>`。现有「一次扫描」= 批量生成 N×M 个 `run_poc`，语义不变，行为不变。

> v1 已落地（C3）：`ActionKind` 只取 `run_poc` / `port_scan` / `web_fingerprint` 三种，其余 `probe_http` / `replay_evidence` / `brute` / `oob_wait` 待有对应工具面动作再入枚举。批量内的动作必须同 `Kind`（执行面一次只拉起一个子进程，只能单一模式），且 `run_poc` 批量需构成完整的「目标 × PoC」笛卡尔积，残缺组合直接拒绝。

### 4.4 Evidence —— 凭什么这么说

```json
{
  "id": "evd_...",
  "finding": "fnd_...",
  "poc_id": "...",
  "steps": [
    {
      "role": "baseline|probe|confirm|diff|time_baseline|time_confirm",
      "request": { "method": "...", "url": "...", "headers": "…", "body": "…" },
      "response": { "status": 200, "headers": "…", "body": "…" },
      "matched": true,
      "extracted": { "token": "…" },
      "latency_ms": 183,
      "diff": { "against": 0, "similarity": 0.12 }
    }
  ],
  "judgement": { "technique": "boolean_diff", "dialect": "mysql", "evasion": "none", "construct": "comment" },
  "replay": { "command": "afrog verify --poc ... --target ...", "deterministic": true },
  "digest": "sha256:...",
  "confidence": "certain|probable",
  "created": "..."
}
```

约束：

- Evidence 由**引擎原生产出**，不由 UI 事后拼装；现有 `result.AllPocResult`（request/response 对）、`passive_finding.traces`、SQLi 的 technique/dialect/evasion/construct 全部收敛到这一个结构。
- `digest` = 对 `steps + poc_id + target + judgement` 规范化后取哈希，作为 `idempotency_key` 与去重键。
- `replay.command` 必须真的能跑通；跑不通的 Evidence 视为未完成。

### 4.5 Finding —— 结论及其生命周期

```json
{
  "id": "fnd_...",
  "project_id": "p_...",
  "subject": "endpoint_...",
  "vuln_class": "sqli",
  "severity": "high",
  "title": "...",
  "confidence": "certain|probable",
  "evidence": ["evd_..."],
  "state": "new|present|fixed|regression",
  "source": "active|passive|agent",
  "first_seen": "...", "last_seen": "...", "hit_count": 3
}
```

沿用现有台账语义：`regression` 只能由系统判定；项目间永不去重。

## 5. 工具面

### 5.1 统一动词（三种入口同一份语义）

| 动词 | 语义 | 副作用 | 默认能力 |
|---|---|---|---|
| `observe.*` | 读状态 / 拉观测流 / 查证据 | 无 | 只读 |
| `probe.*` | 轻量探测（单请求、端口、指纹） | 有流量、可逆 | declarative |
| `verify.*` | 跑特定 PoC / 重放证据 | 有流量、可逆 | declarative / network |
| `act.*` | 暴力破解、上传、OOB 触发等 | 可能破坏 | exec，默认关闭 |

### 5.2 工具清单（MCP 同名，REST 走 `/api/v1/*`，gRPC 走 `AgentService`）

| 工具 | 输入 | 输出 |
|---|---|---|
| `observe.state` | project_id, subject, depth | 子图（资产/端点/参数/技术栈） |
| `observe.observations` | since_seq, filter | Observation 流 |
| `observe.findings` | project_id, state, class | Finding 列表 |
| `observe.evidence` | finding_id | Evidence（含 replay） |
| `probe.http` | method,url,headers,body,redirect | 单次事务 + digest |
| `probe.port` | host,ports,timeout | 开放端口 + 服务指纹 |
| `probe.fingerprint` | url | 技术栈 + WAF + TLS |
| `verify.poc` | poc_id,target | Evidence |
| `verify.replay` | evidence_id | 新 Evidence（含一致性比对） |
| `act.brute` | poc_id,target,wordlist | Evidence（受策略约束） |
| `plan.next` | project_id, subject, subject_under, limit | 有依据、可排序的 `Action` 提议列表 |
| `poc.search` | product / cve / fingerprint | PoC 元数据 |
| `poc.draft` | 自然语言 / 流量 / nuclei yaml | 候选 PoC（不入库；可落盘 `~/.config/afrog/drafts`） |
| `poc.submit` | poc_path, target | 受限实跑取证据 → 放入待人工终审队列（`poc_draft` 表，status=pending） |

`poc.submit` 是 Drafter 流水线的收口：它先在一台真实目标上把草稿跑一次（复用 `verify.poc`
的受限单目标实跑：预算 + 超时），**只有拿到证据才允许进入队列**——拿不到证据的候选不配进
终审。它仍然不是判定者：提交只代表「可复现」，是否写进 `~/.config/afrog/pocs-my` 由人工
用 `afrog poc approve` 决定（见 §7）。

`plan.next` 是决策面的**确定性基线**：它不发包、不做策略判定、不推断漏洞状态，只把攻击面图
压成「下一步试什么」并给出依据（同样的图必然得到同样的顺序）。它与 `observe.*` 同属只读，
零预算、可在 readonly 模式使用；提议中的每个 Action 仍需再走一次 `verify.*` / `probe.*` 的
策略与预算门控才可能执行。实现见 `pkg/planner`，MCP 与 `/api/v1/plan/next` 共享同一份语义。

### 5.3 策略与预算

```yaml
policy:
  mode: readonly | safe | full        # 映射 capability 等级
  allow: ["observe.*", "probe.*", "verify.*"]
  deny:  ["act.brute", "act.upload"]
  scope:
    allow_hosts: ["10.0.0.0/8"]
    deny_hosts:  ["10.0.0.1"]
    deny_paths:  ["/logout", "/delete"]
  budget:
    requests: 5000
    duration: 10m
    tokens: 200000
  destructive: false                   # 对应现有非幂等方法护栏
  audit: true
```

执行顺序固定：`解析 → 校验 → 策略判定 → 预算扣减 → 执行 → 写 action_log`。拒绝必须回一条结构化原因（沿用「全链路不静默」原则）。

### 5.4 典型闭环（当前实现可直接跑通）

| 步骤 | 工具 | 产出 |
|---|---|---|
| 1 定位 | `observe.findings` | 命中列表，每条带 `evidence_id` |
| 2 取证 | `observe.evidence` | 可重放证据（steps / digest / replay） |
| 3 假设 | `poc.draft` | 结构校验 + 能力等级 + 请求量估算（不发包） |
| 4 验证 | `verify.poc` | 新证据；同一内容得到同一个 `evd_` |
| 5 复核 | `verify.replay` | 重放同一证据并比对 id/digest，判定是否仍成立 |
| 6 扩展 | `observe.state` | 上下游资产与未覆盖面 |
| 7 提交 | `poc.submit` | 受限实跑取证据，进入待人工终审队列（pending） |
| 8 终审 | `afrog poc approve/reject` | 人批准后写入 `~/.config/afrog/pocs-my`，候选才真正入库 |

分工固定：第 3 步的草稿由模型写，`poc.draft` 只做结构与成本校验；第 4、5 步的判定与
证据只能由 `verify.*` 产生。`observe.observations` 已实现，提供过程事实（开放端口 /
Web 指纹 / Agent 主动发起的 HTTP 往返），契约在 `pkg/observation`，存储与写入点见
[观测流设计说明](./afrog-observations-design.md)。

第 7、8 步是 Drafter 的收口（`pkg/drafter` + `poc_draft` 表）：`poc.submit` 复用受限实跑，
只有拿到证据才入队；入库动作只能由人在 CLI 上发起，模型没有「自己写进 PoC 目录」的路径。

可执行的最小客户端见 `examples/mcp_agent`（`-draft` 即走完第 3、4 步）。

## 6. 状态面：攻击面图

**不新增图数据库**，复用现有 [asset + asset_edge](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/db/sqlite/asset_graph.go)。

- 节点：一切可寻址对象都是 `asset`，用 `type` 区分（现有值 + 新增 `endpoint` / `param`）。
- 边：沿用「父粗 → 子细」，新增可计算的观测边：

| parent → child | kind | 来源 |
|---|---|---|
| asset(host) → asset(port) | `port` | portscan |
| asset(port) → endpoint | `service` | webscan |
| endpoint → param | `param` | passive |
| endpoint → asset(tech) | `tech` | webscan |
| tech → poc | `candidate` | 指纹与 PoC 索引 |
| finding → evidence | `justified_by` | 引擎 |

保留原来的硬约束：**关系必须可由数据计算得出**，不引入 DNS/公共后缀等需要人工纠错的一层。

落地状态（v1）：

- `endpoint` / `param` 已实现为**只写边、不写资产行**的推导节点：`asset_edge` 里存
  `authority → endpoint (kind=service)` 与 `endpoint → param (kind=param)`，读取时按地址
  合成节点、用 `ClassifyAssetAddress` 判型。这样「资产总数 / 未整理」不会被扫描或被动
  流量里看到的上万个 URL 撑大。
- 写入口由 `sqlite.EnsureEndpointGraph(target, location)` 统一收口：被动命中（带参数位置）、
  Web 探测（端点）、MCP `probe.*` / `verify.*`（Agent 主动打过的端点）。
- 端点/参数的命中数按 `passive_finding` 的 `target/location` 归集，不依赖 `asset_id`。
- `tech` / `candidate` 两类边已实现（v1.1）：`endpoint → tech:<名字> (kind=tech)` 来自
  Web 探测与被动指纹提取物；`tech:<名字> → poc:<id> (kind=candidate)` 来自 PoC 的
  `info.requires`——与扫描器的 requires 门控**同一套准入语义**，不另造模糊匹配。
  写入口是 `assetgraph.LinkTechCandidates`。候选只表示「这个技术栈有现成 PoC 值得验证」，
  不是结论；判定仍发生在 verify 阶段。
  覆盖面随 `requires` 声明走（内置库目前约 60 条声明），没有声明的 PoC 不会成为候选——
  这是刻意取舍：宁可少给，也不给靠字符串模糊匹配凑出来的噪声。
- 遍历上限提到 4 层，正好覆盖 `hostport → endpoint → tech → poc` 这条最长推理链。

这样 `observe.state` 就是一次图查询，Agent 拿到的世界模型和 UI 看到的是同一份。

## 7. 决策面：AI 的四个角色与红线

| 角色 | 输入 | 输出 | 能否落地 |
|---|---|---|---|
| Planner | 状态图 + 观测 + 预算 | `Action` 提议列表 | 是（确定性基线已实现，见 `pkg/planner` / `plan.next`），提议落地仍需经策略与人工/自动确认 |
| Drafter | 指纹 + 端点 + 流量 | 候选 PoC（YAML/JS） | 流水线已实现（`pkg/drafter` + `poc.submit` + `afrog poc approve`）：候选必须过 validator + 沙箱实跑取证据才入队；**入库由人在 CLI 终审**，模型没有直接写 PoC 目录的路径 |
| Judge | Evidence | 研判意见（结论/依据/误报/复核步骤） | 已实现契约（`pkg/judge` + `judge.brief` / `judge.record`）：只读证据链、周边观测与子图拼成研判材料，意见存 advisory 表 `judgement`，**不改台账** |
| Learner | 人工终审结果 | 规则/阈值调优建议 | 已实现契约（`pkg/learner` + `learn.brief` / `learn.record` + `afrog learn`）：只读终审流水与流水线指标，建议 diff 存 `learn_suggestion`；`afrog learn accept` **只记录决策、不自动应用 diff** |

**红线**：模型只提议「下一步试什么」，不裁决「是不是漏洞」。判定权永远在确定性引擎 + Evidence。

## 8. 需要改动的核心功能

| # | 位置 | 改动 | 性质 |
|---|---|---|---|
| C1 | [pkg/runner/checker.go](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/runner/checker.go) | 判定时同步构建 Evidence steps（数据已在手，只差组装） | 破坏性小 |
| C2 | [pkg/result/result.go](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/result/result.go) | `PocResult` 增加 `EvidenceRef` / `Digest` / `IdempotencyKey` | 增量 |
| C3 | [pkg/scantask/manager.go](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/scantask/manager.go) | 任务改为 `Batch<Action>`，支持单 Action 提交。已完成：新增 [pkg/scantask/action.go](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/scantask/action.go)（`ActionKind` 取 `run_poc`/`port_scan`/`web_fingerprint`；`Batch{Options, Actions}`）；`Manager.SubmitBatch` 为唯一入口，`Submit(req)` 退化为 `SubmitBatch(Batch{Options: req})`（空 `Actions` 即扫描式批量，动作由引擎在网络阶段按「目标 × PoC」展开，行为不变）；单 Action 提交走完整任务生命周期（事件流/状态/结果/控制）；`Task.Batch()` 只读暴露、`Snapshot` 增 `ActionCount`/`ActionKinds`；异构批量按「齐次性 + 笛卡尔积完整」校验并拒绝（`ErrMixedActionKinds`/`ErrUnknownActionKind`/`ErrActionNoTarget`/`ErrHeterogeneousBatch`）。原子工作单元的 `Action` 让旧控制动作类型更名为 `ControlAction`（与 proto enum 同名同义） | **破坏性，已完成** |
| C4 | [pkg/passive/engine.go](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/passive/engine.go) | 拆出「观测发布」与「检测」，门控池先发观测（已完成：`OnObserved` 在 `Submit` 入口回调，先于门控与短路） | 破坏性中等 |
| C5 | [pkg/passive/types.go](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/passive/types.go) | `CapturedTransaction` 增 `Seq` / `Digest`，由 observe 层包装 | 增量 |
| C6 | [pkg/db/sqlite](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/db/sqlite) | 新增 `observation` / `evidence` / `action_log` / `poc_draft` 四表；`asset.type` 增两类取值 | 增量（沿用 IF NOT EXISTS + ensureColumn） |
| C7 | [pkg/guard/guard.go](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/guard/guard.go) | 升级为 policy 引擎（mode/allow/deny/budget/audit） | 破坏性中等，保留旧 scope 入口 |
| C8 | [proto/afrog/v1/afrog.proto](file:///Users/zanbin/gowork/github/zan8in/afrog/proto/afrog/v1/afrog.proto) | 新增 `AgentService`（`ListTools` / `Invoke`，与 MCP `tools/list` / `tools/call` 同名同义，入参与返回值走 JSON 透传）；`Evidence` 沿用 `native_json`，不镜像 digest/steps/replay/judgement（证据契约只在 `pkg/evidence` 维护一份） | 增量 |
| C9 | [pkg/scanapi](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/scanapi) | 实现 `AgentService`（委托 `pkg/mcp` 工具面，策略/预算/审计共用）；`afrog serve` 从 `agent` 配置装配工具面；旧 `AfrogScanner` 保持不动 | 增量 |
| C10 | [pkg/web/server_routes.go](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/web/server_routes.go) | 新增 `/api/v1/*`，旧 `/api/*` 保留为兼容层（只读面已落地：`observe.*` / `plan.next` / `poc.search`；写动作面已落地 `POST /api/v1/call`，与 MCP 共用同一 `policy.Gate`） | 增量 |

新增包（不侵入现有代码）：

- `pkg/ref` —— ID 与内容寻址
- `pkg/evidence` —— 模型、构建器、重放器、存储
- `pkg/observe` —— 序号、去重、订阅（内存环形 + 持久化元数据）
- `pkg/policy` —— 策略解析与判定
- `pkg/mcp` —— MCP server（stdio + SSE），只做协议翻译

## 9. 兼容策略

| 对象 | 策略 |
|---|---|
| CLI 参数 | 完全不变，新增 `afrog mcp` / `afrog verify` 子命令 |
| SDK `Options` | 只加字段，不改语义；`Scanner` 行为不变 |
| gRPC `AfrogScanner` | 冻结；新能力一律进 `AgentService` |
| Web `/api/*` | 保留，新接口走 `/api/v1/*`，前端逐步迁移 |
| DB | 只加表加列；`result` / `passive_finding` 仍是报告真源，`evidence` 通过 `result_id` 反查，不双写 |
| 集群 | `Action` 天然可派发，节点只需实现 `AgentService` 子集 |

## 10. 分期交付

| 阶段 | 内容 | 验收标准 |
|---|---|---|
| P0 契约 | `pkg/ref`、`pkg/evidence`、`pkg/observe`；C1/C2/C5/C6 落地 | 现有扫描产出的每个命中都有 `evd_*`，`verify.replay` 能跑通且 digest 一致 |
| P1 工具面 | `pkg/policy`、`afrog mcp`、`AgentService`、`verify.poc` 单动作执行（C3/C7/C8/C9）。C3/C7/C8/C9 全部完成：`policy.Gate` 为唯一门控，MCP / REST（`/api/v1/call`）/ gRPC（`AgentService`）三面共用同一份工具注册表与策略、预算、审计；`scantask` 已泛化为 `Batch<Action>` 并支持单 Action 提交 | 外部 agent 仅用 afrog 工具完成「目标 → 一条可重放证据」 |
| P2 状态面 | endpoint/param 入图、`observe.state` / `observe.observations`（C4/C10）。前三项已完成；C4 已完成（被动 `http_passive` 先发观测后进检测）；观测流已扩到 `tls` / `oob_hit`（`dns` 待采集点）；C10 只读面已落地（observe.* / plan.next / poc.search），写动作面已落地 `POST /api/v1/call`（与 MCP 共用同一 `policy.Gate`，`agent.policy` / `agent.audit` 未配置即只读） | agent 一次查询拿到完整目标子图；观测流可断点续订 |
| P3 决策面 | Planner、PoC Drafter 流水线、人工终审回流。Planner 确定性基线已完成（`pkg/planner` / `plan.next`：候选 PoC → `verify.poc`、未知面 → `probe.fingerprint`，按确定性分数排序）；Drafter 流水线已完成（`poc.submit` 受限实跑取证据 → `poc_draft` 待审队列 → `afrog poc approve/reject` 人工终审入库）；终审回流已完成（`Approve`/`Reject` 自动写只追加流水 `poc_review`）；入库率量化已完成（`drafter.GetStats()` + `afrog poc stats`，`IngestRate = approved/(approved+rejected)`，分母不含 pending，无决议渲染 `n/a`）；Judge / Learner 契约已完成（`pkg/judge` 的 `judge.brief`/`judge.record` → `judgement` 表，`pkg/learner` 的 `learn.brief`/`learn.record` + `afrog learn` → `learn_suggestion` 表；两者都是 advisory，模型永不写台账） | Drafter 产出的 PoC 经 validator + 沙箱 + 证据确认后自动入库率可量化（`afrog poc stats` 输出 total/pending/approved/rejected/reviews/ingest_rate，并按 severity/capability 分桶） |

## 11. 非目标

- 不做通用 agent 框架 / 不做模型网关。
- 不做「无人值守全自动打点」；`act.*` 默认关闭且必须显式开关。
- 不让 LLM 参与任何最终判定。
- 不为了统一而重写 runner / portscan / passive 的检测逻辑本身。

## 12. 验收指标

| 指标 | 目标 |
|---|---|
| Agent 端到端成功率（目标→可重放证据） | ≥ 90% |
| Evidence 重放一致率 | ≥ 99% |
| 每条确认漏洞的平均 token 成本 | 相比「全自主 agent」下降一个量级 |
| 误报率 | 不高于现有水平 |
| 旧 CLI / SDK / gRPC 回归 | 零破坏 |
