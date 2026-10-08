# 计划扫描参数配置方案（设计交付文档）

- 模块：afrog Web 控制台 ·「计划扫描」新建/编辑计划 ·「扫描」扫描设置
- 目标：让「新建计划」的扫描参数与「扫描设置」**完全对齐**，并提供分组清晰、可校验、可扩展的配置体验
- 关联代码：
  - 立即扫描设置：[quick-scan.svelte](file:///Users/zanbin/gowork/github/zan8in/afrogweb/src/lib/components/scan/quick-scan.svelte)（`form` / `buildOverrides` / 性能·网络·PoC·预设 四个 Tab）
  - 新建计划：[schedules/+page.svelte](file:///Users/zanbin/gowork/github/zan8in/afrogweb/src/routes/(app)/schedules/+page.svelte)（`Draft` / `buildPayload`）
  - 请求体定义：[types.go `ScanCreateRequest`](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/web/types.go#L91-L146)
  - 计划后端：[schedules.go](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/web/schedules.go)
- 状态：**已实施**（里程碑 ①–④ 完成，⑤ 回归完成）。实施结果、与设计的差异、未做项见第 14 节。
- 增补：第 15 节「项目默认参数统一方案」为新增设计，**已实施**。

---

## 0. 术语与范围

| 术语 | 含义 |
|---|---|
| 立即扫描 | 「扫描」页 Quick Scan，填写目标后立刻起扫 |
| 计划扫描 | 「计划扫描」页创建的计划，到点自动重跑同一份扫描配置 |
| 基线 | 前端 `scanStrategy` 的当前策略（内置默认 + 用户保存的策略） |
| 快照 / overrides | 计划=完整快照（持久化全量）；立即扫描=相对基线（只下发改动项） |
| 项目默认值 | 项目上保存的一组扫描参数，选中该项目起扫时预填表单；稀疏存储（只存与内置默认不同的项），见第 15 节 |

范围：仅参数配置层。不改动扫描引擎、命中模型、通知、资产沉淀逻辑。

---

## 1. 现状与差异

> 本节记录**改造前**的现状与差异，作为问题陈述保留；实际实现见第 13–14 节。

### 1.1 相同点

- 两者最终都落到后端 `ScanCreateRequest`；计划保存在 `Schedule.Scan`（同结构），起跑时原样交给 `launchScan`。
- 两者都复用 `scanStrategy` 的默认值口径（计划目前是"硬编码占位符"，见 1.3）。

### 1.2 「扫描设置」现有参数（完整清单）

来源：`quick-scan.svelte` 的四个 Tab。

| 分组 | 参数 | 请求字段 | 控件 |
|---|---|---|---|
| 性能 | 并发数 / 速率每秒 / 超时秒 / 重试次数 / 单主机错误上限 | `concurrency` / `rate_limit` / `timeout` / `retries` / `max_host_error` | 数字 |
| 性能 | 严重性 | `severity` | 勾选组（high/critical/…） |
| 性能 | 智能并发 | `smart` | 开关 |
| 性能 | 请求节流策略（单目标） | `polite`/`balanced`/`aggressive`/`auto_req_limit`/`req_limit_per_target` | 下拉（互斥五选一） |
| 性能 | 智能任务超时 / 跳过指纹类 PoC / 命中即停 / 实时监控目标 | `task_smart_timeout` / `no_fingerprint` / `breakpoint_on_vuln` / `monitor_targets` | 开关 |
| 性能（进阶） | 爆破请求上限 / 响应体上限(MB) | `brute_max_requests` / `max_resp_body_size` | 数字 |
| 网络 | 代理 | `proxy` | 文本（URL） |
| 网络 | 自定义请求头 | `headers` | 多行文本（`Key: Value`） |
| 网络 | 结果排序 | `sort` | 下拉（a-z / severity） |
| 网络 | Web 指纹识别 | `web_fingerprint` | 开关 |
| 网络 | 端口扫描 + 端口范围 + 跳过主机存活探测 | `port_scan` / `ports` / `skip_host_discovery` | 开关 + 联动 |
| 网络 | OOB 适配器 | `enable_oob` + `oob` | 下拉（6 种） |
| 网络 | OOB 速率 / 并发 | `oob_rate_limit` / `oob_concurrency` | 数字（无适配器时禁用） |
| 网络（进阶） | OOB 轮询间隔 / 命中保留 / 收尾等待 | `oob_poll_interval` / `oob_hit_retention` / `oob_finalize_timeout` | 数字 |
| PoC | 手动选择 PoC（搜索 + 分页 + 多选） | `poc_ids` | 列表多选 |
| 预设 | 扫描策略（保存/新建/复制/重命名/删除/恢复默认） | —（序列化为上述字段） | 下拉 + 菜单 |

### 1.3 「新建计划」现有参数

来源：`schedules/+page.svelte` 的 `Draft` 与「扫描参数」区（平铺、无分组）。

计划名称、启用、执行频率（hourly/daily/weekly）、目标来源（项目/临时目标）、所属实例；
扫描参数：严重性（**自由文本**）、PoC 来源（下拉）、并发、速率、超时、关键字筛选、OOB 适配器（**自由文本**）、端口扫描（开关）、Web 指纹（开关）、智能并发（开关）。

### 1.4 差异矩阵（核心）

图例：✅ 支持；❌ 缺失；⚠️ 存在但口径不一致。

| # | 参数 | 请求字段 | 扫描设置 | 新建计划 | 处理 |
|---|---|---|---|---|---|
| 1 | 并发数 | `concurrency` | ✅ | ✅ | 保留 |
| 2 | 速率/秒 | `rate_limit` | ✅ | ✅ | 保留 |
| 3 | 超时/秒 | `timeout` | ✅ | ✅ | 保留 |
| 4 | 重试次数 | `retries` | ✅ | ❌ | **补** |
| 5 | 单主机错误上限 | `max_host_error` | ✅ | ❌ | **补** |
| 6 | 智能并发 | `smart` | ✅ | ✅ | 保留 |
| 7 | 爆破请求上限 | `brute_max_requests` | ✅ | ❌ | **补** |
| 8 | 响应体上限/MB | `max_resp_body_size` | ✅ | ❌ | **补** |
| 9 | 请求节流策略 | `polite`/`balanced`/`aggressive`/`auto_req_limit` | ✅ | ❌ | **补** |
| 10 | 单目标每秒请求数 | `req_limit_per_target` | ✅ | ❌ | **补** |
| 11 | 智能任务超时 | `task_smart_timeout` | ✅ | ❌ | **补** |
| 12 | 跳过指纹类 PoC | `no_fingerprint` | ✅ | ❌ | **补** |
| 13 | 命中即停 | `breakpoint_on_vuln` | ✅ | ❌ | **补** |
| 14 | 实时监控目标 | `monitor_targets` | ✅ | ❌ | **补** |
| 15 | 代理 | `proxy` | ✅ | ❌ | **补** |
| 16 | 自定义请求头 | `headers` | ✅ | ❌ | **补** |
| 17 | 结果排序 | `sort` | ✅ | ❌ | **补** |
| 18 | Web 指纹识别 | `web_fingerprint` / `webprobe` | ✅ `web_fingerprint` | ⚠️ `webprobe` | **统一字段名** |
| 19 | 端口扫描 | `port_scan` / `portscan` | ✅ `port_scan` | ⚠️ `portscan` | **统一字段名** |
| 20 | 端口范围 | `ports` | ✅ | ❌ | **补（联动）** |
| 21 | 跳过主机存活探测 | `skip_host_discovery` | ✅ | ❌ | **补（联动）** |
| 22 | OOB 适配器 | `enable_oob`+`oob` | ✅ 下拉 | ⚠️ 自由文本 | **改为下拉** |
| 23 | OOB 速率 / 并发 | `oob_rate_limit` / `oob_concurrency` | ✅ | ❌ | **补（联动）** |
| 24 | OOB 轮询 / 保留 / 收尾 | `oob_poll_interval` / `oob_hit_retention` / `oob_finalize_timeout` | ✅ | ❌ | **补（联动）** |
| 25 | 严重性 | `severity` | ✅ 勾选组 | ⚠️ 自由文本 | **改为勾选组** |
| 26 | 手动选择 PoC | `poc_ids` | ✅ | ❌ | **补** |
| 27 | PoC 来源 | `poc_source` | ❌ | ✅ | **扫描设置补上**（对称） |
| 28 | 关键字筛选 | `search` | ❌ | ✅ | **扫描设置补上**（对称） |

> 结论：计划侧缺 **18 项**、口径不一致 **4 项**；扫描设置侧缺 2 项。修复方式不是"逐项往计划表单里搬"，而是**抽一份共享参数表单 + schema**，使两侧永久一致（见第 3 节）。

### 1.5 一句话根因

「扫描设置」和「新建计划」各自维护了一份**平行业务字段表**，任何一侧新增参数都会漂移。这是问题反复出现的结构性原因。

---

## 2. 设计目标与原则

| 目标 | 对应要求 | 设计手段 |
|---|---|---|
| 参数完整性 | 1 | 共享 `ScanParamsForm` + 字段 schema，两侧同一份 |
| 清晰界面 | 2 | 4 大分组 + 组内折叠"高级"，默认收敛 |
| 流程顺畅 | 3 | 单页分区 + 顶部步骤锚点；不改"一屏可保存" |
| 用户体验 | 4 | 默认值 + 字段说明 + 联动 + 实时校验 |
| 时间计划 | 5 | 频率新增"每月"；结构化字段 + 预留 Cron |
| 一致性 | 6 | 统一字段名 + 统一序列化函数 + 统一后端入口 |
| 可扩展 | 7 | schema 驱动 + `schema_version` 兼容迁移 |
| 可测试 | 8 | 覆盖矩阵 + 快照一致性 + 边界/联动用例 |

**UX 原则**：默认可用（不打开"高级"也能建计划）＞ 信息完整；口径一致 ＞ 局部便利；显式可预期（计划=快照）＞ 隐式继承。

---

## 3. 总体方案

### 3.1 结构

```
        ┌───────────────────────────────┐
        │  scan-params.schema.ts (字段)  │  ← 单一事实来源
        │  key/label/group/control/     │
        │  default/hint/visibleIf/      │
        │  validate/serializeMode       │
        └───────────────┬───────────────┘
                        │ 驱动
                ┌───────┴────────┐
                │ ScanParamsForm │  ← 共享 Svelte 组件（分组渲染 + 校验 + 联动）
                └───┬────────┬───┘
        ┌───────────┘        └────────────┐
┌───────┴────────┐              ┌────────┴─────────┐
│ 扫描设置抽屉    │              │ 新建/编辑计划抽屉 │
│ (立即扫描)      │              │ (计划扫描)        │
└───────┬────────┘              └────────┬─────────┘
        │ buildOverrides(base)            │ toSnapshot()
        │ 相对基线，仅改动项               │ 绝对快照，全量持久化
        ▼                                 ▼
   一次扫描请求                      计划落库 → 到点起跑
```

### 3.2 双序列化模式（关键设计）

| | 立即扫描 | 计划扫描 |
|---|---|---|
| 意图 | 用户在场，其余项交给 `afrog-config.yaml` | 无人值守，必须可复现 |
| 策略 | **相对基线**：与基线相同的数值不下发 | **绝对快照**：全量持久化 |
| 开关类 | 按表单显式下发 | 按表单显式下发 |
| 后果 | 尊重全局配置 | 结果可预期、跨重启稳定 |

> 现有 `buildOverrides` 已经是"相对基线"；计划的 `buildPayload` 是"部分显式"。方案统一为同一份表单模型 + 两个导出函数，保证**同一份输入产出语义等价的执行参数**（测试用例 T-03）。

### 3.3 顺带修复的一致性缺陷

1. `web_fingerprint` vs `webprobe` → 统一用 **`web_fingerprint`**。
2. `port_scan` vs `portscan` → 统一用 **`port_scan`**（后端 `ScanCreateRequest` 两者并存，serializer 只写 `port_scan`）。
3. 严重性：自由文本 → 与扫描设置一致的**勾选组**。
4. OOB 适配器：自由文本 → **枚举下拉**。
5. 计划写入改为经由**同一 serializer**，避免再出现"计划下发 A 字段、立即扫描下发 B 字段"。

---

## 4. 统一参数模型与序列化（数据结构）

### 4.1 前端模型

```ts
// src/lib/scan/scan-params.types.ts
export interface ScanParams {
  // 性能与并发
  concurrency: number; rateLimit: number; timeout: number;
  retries: number; maxHostError: number;
  smart: boolean; bruteMaxRequests: number; maxRespBodySize: number;
  // 节流与容错
  throttle: 'none'|'auto'|'polite'|'balanced'|'aggressive'|'custom';
  reqLimitPerTarget: number;
  taskSmartTimeout: boolean; noFingerprint: boolean;
  breakpointOnVuln: boolean; monitorTargets: boolean;
  // 网络与请求
  proxy: string; headers: string; sort: ''|'a-z'|'severity'; // headers 存多行文本，序列化时拆成数组
  webFingerprint: boolean;
  portScan: boolean; ports: string; skipHostDiscovery: boolean;
  // OOB
  oobAdapter: string; oobRateLimit: number; oobConcurrency: number;
  oobPollInterval: number; oobHitRetention: number; oobFinalizeTimeout: number;
  // PoC
  severity: string[]; pocSource: string; pocIds: string[]; search: string;
}
```

### 4.2 序列化

```ts
// 立即扫描：相对基线，只下发改动项
function toScanOverrides(p: ScanParams, base: ScanParams): Partial<ScanCreateRequest>;

// 计划扫描：绝对快照，全量下发（含开关的 false 显式态）
function toScanSnapshot(p: ScanParams): ScanCreateRequest['scan'];
```

两函数共用同一份 `FIELD_MAP`（见 4.3），只是 `omit-if-equal-to-base` 开关不同。**任何新字段只改 `FIELD_MAP`。**

### 4.3 字段表（`FIELD_MAP` 摘录）

| 模型字段 | 请求字段 | 类型 | 默认 | 范围/枚举 | 序列化 |
|---|---|---|---|---|---|
| concurrency | `concurrency` | int | 25 | 1–500 | 数值·等基线则省略 |
| rateLimit | `rate_limit` | int | 150 | 1–5000 | 数值·等基线则省略 |
| timeout | `timeout` | int | 50 | 1–600 | 数值·等基线则省略 |
| retries | `retries` | int | 1 | 0–10 | 数值·等基线则省略 |
| maxHostError | `max_host_error` | int | 3 | 0–100 | 数值·等基线则省略 |
| smart | `smart` | bool | false | — | 开关·显式 |
| bruteMaxRequests | `brute_max_requests` | int | 5000 | 0–1e7 | 数值·等基线则省略 |
| maxRespBodySize | `max_resp_body_size` | int | 2 | 0–64 | 数值·等基线则省略 |
| throttle | `polite`/`balanced`/`aggressive`/`auto_req_limit` | enum | none | 五选一 | 互斥，只写选中 |
| reqLimitPerTarget | `req_limit_per_target` | int | 0 | 1–100 | 仅 custom |
| taskSmartTimeout | `task_smart_timeout` | bool | true | — | 开关·显式 |
| noFingerprint | `no_fingerprint` | bool | false | — | 开关·显式 |
| breakpointOnVuln | `breakpoint_on_vuln` | bool | false | — | 开关·显式 |
| monitorTargets | `monitor_targets` | bool | false | — | 开关·显式 |
| proxy | `proxy` | str | '' | http(s)/socks5 URL | 非空下发 |
| headers | `headers` | str[] | [] | `Key: Value` | 非空下发 |
| sort | `sort` | enum | '' | a-z/severity | 非空下发 |
| webFingerprint | `web_fingerprint` | bool | false | — | 开关·显式 |
| portScan | `port_scan` | bool | false | — | 开关·显式 |
| ports | `ports` | str | '' | 端口表达式 | 仅 portScan |
| skipHostDiscovery | `skip_host_discovery` | bool | false | — | 仅 portScan |
| oobAdapter | `enable_oob`+`oob` | enum | ''（关） | 6 种适配器 | 非空则 enable_oob=true |
| oobRateLimit | `oob_rate_limit` | int | 25 | 1–200 | 仅启用 OOB |
| oobConcurrency | `oob_concurrency` | int | 25 | 1–200 | 仅启用 OOB |
| oobPollInterval | `oob_poll_interval` | int | 2 | 1–60 | 仅启用 OOB |
| oobHitRetention | `oob_hit_retention` | int | 10 | 1–1440 | 仅启用 OOB |
| oobFinalizeTimeout | `oob_finalize_timeout` | int | -1 | -1/0/N | 仅启用 OOB |
| severity | `severity` | str[] | [] | high/… | 非空则 join |
| pocSource | `poc_source` | enum | '' | curated/my | 非空下发 |
| pocIds | `poc_ids` | str[] | [] | — | 非空下发 |
| search | `search` | str | '' | — | 非空下发 |

---

## 5. 界面设计

### 5.1 新建/编辑计划抽屉（信息架构）

```
┌ 新建计划 ─────────────────────────────┐
│ ① 基本信息   计划名称 · 启用 · 所属实例 │
│ ② 扫描目标   目标来源(项目/临时) · 目标  │
│ ③ 时间计划   频率 · 间隔/时间/星期/日    │
│ ④ 扫描参数   [5 个分组折叠区]           │
│ ⑤ 预设策略   套用/另存为策略（可选）      │
│───────────────────────────────────────│
│                        取消   保存      │
└───────────────────────────────────────┘
```

- 顶部保留**步骤锚点条**（①–⑤），点击滚动定位；不做强制分步，**一屏到底**，避免打断熟练用户。
- ④「扫描参数」默认只展开最常用的组，其余折叠；折叠状态记忆到本地。

### 5.2 ④ 扫描参数分组

| 分组 | 默认 | 字段 |
|---|---|---|
| 性能与并发 | 展开 | 并发数、速率/秒、超时/秒、智能并发；**高级**：重试次数、单主机错误上限、爆破请求上限、响应体上限 |
| 节流与容错 | 折叠 | 请求节流策略（+自定义值）、智能任务超时、跳过指纹类 PoC、命中即停、实时监控目标 |
| 网络与请求 | 折叠 | 代理、自定义请求头、结果排序、Web 指纹识别、端口扫描（含端口范围/跳过存活） |
| OOB 带外检测 | 折叠 | 适配器；启用后：速率、并发；**高级**：轮询间隔、命中保留、收尾等待 |
| PoC 与范围 | 折叠 | 严重性（勾选组）、PoC 来源、手动选择 PoC、关键字筛选 |

### 5.3 字段呈现规范（每条字段）

```
┌ 并发数                 [默认] ⓘ ┐
│ [   25   ]                     │   标签 · 默认徽标 · 说明气泡
│ 同时进行的最大主机数，越高越快 │   一行说明（12px）
└────────────────────────────────┘
```

- **默认徽标**（**已实施**）：字段值与基线一致时，标签旁显示灰色小徽标「默认」，提示该项未被改动。基线口径见 §0 术语表：立即扫描=当前策略（`scanStrategy.getActiveMerged()`），计划扫描=内置默认值（`SCAN_PARAMS_BASELINE`），由 `ScanParamsForm` 的 `baseline` 属性传入。
- **说明**：每字段一行 12px 灰字；复杂项（节流、收尾等待）用 ⓘ 悬浮补充。
- **错误态**：输入框红框 + 下方红字，与校验规则同步。
- **高级折叠**：进阶项收进「高级」`Collapsible`，降低首屏噪音。

### 5.4 与扫描设置的关系

- 扫描设置抽屉改为直接渲染共享组件 `ScanParamsForm`，保留原有 4 Tab 外观（Tab = 分组映射）。
  实际实现中组件**没有 `mode` 参数**：它只负责「按 schema 渲染 + 实时校验」，序列化口径由调用方决定（扫描设置调 `toScanOverrides`，计划调 `toScanSnapshot`）。
- 计划抽屉渲染同一个组件并传全部分组（`groups={['perf','throttle','net','oob','poc']}`），保存时走 `toScanSnapshot`。
- 两侧"预设策略"入口共用；计划可选"跟随当前策略保存"（尚未实现入口，计划新建时默认取基线）。

---

## 6. 交互流程

**新建计划（主流程）**

1. 点「新建计划」→ 抽屉打开，④ 组按默认值预填（来源于基线），① 名称空、③ 频率默认「每天 09:00」。
2. 填名称 → 选目标来源 → 选项目/填目标。
3. 设时间计划（频率联动：每小时→间隔；每天→时间；每周→星期+时间；每月→第 N 天+时间）。
4. 需要时展开 ④ 分组微调；联动项（端口范围、OOB 调优、自定义节流）随开关出现/禁用。
5. 保存前做**汇总校验**（第 7 节）→ 通过则 `toSnapshot()` 落库；不通过则滚动定位第一个错误字段并高亮。
6. 编辑：回填时把快照反序列化回 `ScanParams`；缺失字段用默认值补齐（老计划兼容）。

**联动示例（端口扫描）**：`端口扫描` 关闭 → 隐藏且不下发 `ports` / `skip_host_discovery`；打开 → 显示端口范围（必填校验）+ 跳过存活开关。

---

## 7. 校验与联动规则

### 7.1 校验规则（前端即时 + 保存前汇总；后端二次校验）

| 字段 | 规则 | 提示 |
|---|---|---|
| 计划名称 | 必填 | 计划名称不能为空 |
| 并发数 | 整数 1–500 | 并发需为 1–500 的整数 |
| 速率/秒 | 整数 1–5000 | 速率需为 1–5000 的整数 |
| 超时/秒 | 整数 1–600 | 超时需为 1–600 秒 |
| 重试次数 | 整数 0–10 | — |
| 单主机错误上限 | 整数 0–100 | — |
| 单目标每秒请求数 | 仅节流=自定义时；整数 1–100 | — |
| 代理 | 空或 `http(s)://` / `socks5://` URL | 代理地址格式不正确 |
| 自定义请求头 | 每行 `Key: Value`，Key 非空 | 第 N 行格式应为 `Key: Value` |
| 端口范围 | `80,443,8000-9000`；端口 1–65535；区间起≤止 | 端口范围格式不正确 |
| OOB 适配器 | 枚举；为空则其调优项禁用 | — |
| OOB 收尾等待 | -1 / 0 / 正整数 | 收尾等待需为 -1、0 或正整数 |
| 严重性 | 空=全部 | — |
| 目标（临时） | 至少 1 行有效 | 请至少填写一个目标 |
| 目标（项目） | 必须选项目 | 请选择项目；项目无资产时后端拦截 |
| 频率/时间 | 时间 HH:MM；每月第 N 天限 1–28 | — |

### 7.2 联动矩阵

| 触发 | 影响 |
|---|---|
| 端口扫描 = 关 | 隐藏并清空 `ports` / `skip_host_discovery` |
| OOB 适配器 = 空 | OOB 调优 5 项禁用且不下发 |
| 节流 ≠ 自定义 | 隐藏 `req_limit_per_target` |
| 目标来源 = 项目 | 隐藏临时目标框；反之隐藏项目下拉 |
| 频率 = 每小时 | 只显示间隔小时；清空 `at_time` / `weekday` |
| 频率 = 每天 | 只显示时间；清空 `interval_hours` / `weekday` |
| 频率 = 每周 | 显示星期 + 时间；清空 `interval_hours` |
| 频率 = 每月 | 显示"第 N 天" + 时间 |
| 所属实例 = 同伴 | 目标来源若为"项目"给出提示（远程派发不支持按项目派发，沿用现有约束） |

---

## 8. 时间计划模块

### 8.1 现有能力

`hourly`（每 N 小时）/ `daily`（每天 HH:MM）/ `weekly`（每周几 HH:MM）。后端 `normalizeSchedule` + `computeNextRun` 已实现，`next_run_at` 精确到分钟。

### 8.2 本次新增

| 频率 | 说明 | 前端 | 后端改动 |
|---|---|---|---|
| 每月 `monthly` | 每月第 N 天 HH:MM（N=1–28，避免月末缺失） | 新增选项 + "第 N 天"输入 | `freqMonthly`、`normalizeSchedule`、`computeNextRun`（`AddDate(0,1,0)` 后校正）、`scheduleSaveRequest` 校验 |

### 8.3 预留（不在本期）

- **每月最后一天**（`monthly_last`）：值为 29/30/31 时的语义补充。
- **自定义 Cron**（高级）：新增 `freq='cron'` + `cron` 字段；`computeNextRun` 走 cron 解析器。schema 预留 `cron` 字段位，UI 默认隐藏。

### 8.4 交互

- 频率下拉：每小时 / 每天 / 每周 / **每月**。
- 切换频率时按 7.2 联动清理无关字段，并**实时预览**自然语言："下次执行：2026-10-08 09:00（每 1 天）"。
- 展示 `next_run_at` / `last_run_at`，与列表一致。

---

## 9. 可扩展性

1. **Schema 驱动**：新增参数 = 在 `scan-params.schema.ts` 加一条 + 后端 `ScanCreateRequest` 加字段。表单渲染、序列化、校验、联动、说明文案全部自动生效，不改两侧页面。
2. **版本号**（**未实施**）：原计划给计划存储加 `scan_schema_version`。当前 `scanParamsFromScheduleOptions` 已按字段逐项回落到默认值，老计划（缺字段）可直接读取，暂未引入版本号。
3. **分组可配**：分组顺序/默认展开由 schema 控制，未来可无损重排。
4. **模板/策略复用**：`scanStrategy` 与计划快照共用同一模型，未来"从策略建计划""把计划另存为策略"零成本。
5. **i18n**：label/hint 从 schema 取 key，接现有 `locales/*.json`。

---

## 10. 一致性保证（后端）

| 项 | 措施 |
|---|---|
| 字段名 | 统一 `web_fingerprint` / `port_scan`；serializer 单一来源 |
| 校验 | 后端 `schedulesSaveHandler` 已用 `resolveScanTargets` 预校验目标；建议再加数值范围校验，与前端一致 |
| 执行 | 计划起跑仍走 `launchScheduledScan → launchScan`，参数口径不变 |
| 项目派发 | 远程实例不支持按项目派发：保存时对"项目 + 同伴实例"组合报错，而非静默失败 |
| 快照语义 | 计划执行时**不**读基线，只用落库快照；避免"建计划后改了策略导致行为漂移" |

---

## 11. 测试用例

| ID | 场景 | 步骤 | 期望 |
|---|---|---|---|
| T-01 | 参数覆盖矩阵 | 遍历第 4.3 节全部字段 | 新建计划表单均存在对应控件，且能配置 |
| T-02 | 往返一致 | 配置 → 保存 → 重新打开 | 表单值与保存前逐字段一致（含默认项） |
| T-03 | 序列化等价 | 同一 `ScanParams`，分别在 mode=overrides / snapshot 下导出 | 语义等价（立即扫描仅省略等基线项） |
| T-04 | 字段名统一 | 打开 Web 指纹 + 端口扫描并保存 | 落库为 `web_fingerprint` / `port_scan`，且执行生效 |
| T-05 | 联动-端口 | 关端口扫描 | `ports`/`skip_host_discovery` 不显示且不下发 |
| T-06 | 联动-OOB | 清空 OOB 适配器 | 5 项调优禁用且不下发；`enable_oob` 不下发 |
| T-07 | 联动-节流 | 节流改为非自定义 | `req_limit_per_target` 隐藏且不下发 |
| T-08 | 频率联动 | hourly→daily→weekly→monthly 切换 | 无关字段被清理，`next_run_at` 正确 |
| T-09 | 每月边界 | 每月 31 日 / 2 月 | 按 1–28 限制拦截；月末语义提示 |
| T-10 | 校验-数值 | 并发 0 / 99999 | 即时红字 + 保存被拦截并定位 |
| T-11 | 校验-代理 | 填 `abc` | 格式错误提示 |
| T-12 | 校验-请求头 | 填 `foo`（无冒号） | 报"第 N 行格式应为 Key: Value" |
| T-13 | 校验-端口 | `9000-8000` | 起≤止 校验失败 |
| T-14 | 目标校验 | 项目模式不选项目 / 空目标 | 保存拦截，定位到目标区 |
| T-15 | 老计划兼容 | 读取缺字段的旧计划 | 用默认值补齐，不报错 |
| T-16 | 端到端 | 建计划 → 立即执行 | 任务参数与计划快照一致，结果与手动扫描一致 |
| T-17 | 远程实例 | 同伴实例 + 项目目标 | 保存时明确报错或提示，不静默 |
| T-18 | 可扩展回归 | 新增一条 schema 字段 | 两侧自动出现，无页面改动 |

**自动化覆盖情况**（`npm test`）

| 文件 | 覆盖的用例 |
|---|---|
| `src/lib/scan/scan-params.spec.ts`（23 例，node） | T-02 往返一致（快照↔模型）、T-03 序列化等价、T-04 字段名统一、T-05/T-06/T-07 联动与下发口径、T-10/T-11/T-12/T-13 校验、T-15 老计划兼容、T-18 字段表 key/request 唯一 |
| `src/lib/components/scan/scan-params-form.svelte.spec.ts`（3 例，浏览器） | T-01 字段按 schema 渲染、T-05/T-06 联动在 UI 层生效 |
| `pkg/web/schedules_test.go` | T-08 频率无关字段归一、T-09 每月日收敛与跨月/跨年推进 |

未自动化：T-14/T-16/T-17 依赖运行中的后端，属手工回归。

---

## 12. 用户操作手册（面向使用者）

**新建一个每日巡检计划**
1. 左侧「计划扫描」→ 右上「新建计划」。
2. **基本信息**：填计划名称（如"客户A 每日巡检"），保持「启用」；「所属实例」选本机或某台同伴实例。
3. **扫描目标**：选「项目」（目标随项目维护，推荐）或「临时目标」（一行一个）。
4. **时间计划**：频率可选「每 N 小时 / 每天 / 每周 / 每月固定日期」。
   - 「每月固定日期」填「每月第几天（1–28）」+ 执行时间（限定 1–28：29–31 在部分月份不存在）。
   - 页面会显示"下次执行"预览。
5. **扫描参数**（可跳过，默认已是最常用配置）：
   - 常规微调：并发数、速率、超时，在「性能与并发」组。
   - 网络相关：代理、请求头、排序、Web 指纹、端口扫描，在「网络与请求」组。
   - 需要外带检测时：在「OOB 带外检测」选适配器。
   - 只跑部分 PoC：在「PoC 与范围」勾严重性，或手动选择具体 PoC。
   - 每个字段都有灰字说明；留空的项使用系统默认。
6. 点「保存」。列表出现该计划，显示**所属实例标签**、频率、上次/下次执行时间。
7. 想立刻验证：点卡片上的「立即执行」，到「扫描」页查看结果。

**常见问题**
- 参数改错了？重新打开计划编辑即可，已有历史结果不受影响。
- 为什么有的字段是灰的/不显示？它们依赖上面的开关（如端口范围依赖"端口扫描"、OOB 调优依赖"适配器"）。
- 保存或起扫时提示"参数不合法"？会同时弹出提示并**自动跳到出错字段**（该字段显示红字），例如代理地址格式、端口范围、请求头缺少冒号。
- 计划没按点跑？看卡片上的"上次"状态与错误提示（会员到期/实例离线会明确标注）。

---

## 13. 落地拆解与实施结果

**里程碑完成情况**

| 里程碑 | 状态 | 产出 |
|---|---|---|
| ① 模型 / 序列化 | 已完成 | `scan-params.types.ts`、`scan-params.schema.ts`、`scan-params.ts`（基线、适配器、`toScanOverrides`/`toScanSnapshot`/`toStrategyGroups`/`validateScanParams`）+ 23 个单测 |
| ② 共享组件 + 扫描设置接入 | 已完成 | `scan-params-form.svelte`、`poc-picker.svelte`；`quick-scan.svelte` 三个 Tab 换成组件、`buildOverrides` 收敛为一行 |
| ③ 计划接入 | 已完成 | `schedules/+page.svelte`：`Draft.scan: ScanParams`、`toScanSnapshot` 落库、参数区 5 分组 |
| ④ 每月频率 + 校验 | 已完成 | Go `freqMonthly`/`DayOfMonth`；前端实时校验 + 行内红字 + 保存/起扫拦截定位 |
| ⑤ 回归 + 文档 | 已完成 | 本节 + 第 14 节 |

**实际文件清单**

| 文件 | 说明 |
|---|---|
| `src/lib/scan/scan-params.types.ts` | `ScanParams` 模型、`ThrottleMode`/`ScanSort`、`parseHeaderLines` |
| `src/lib/scan/scan-params.schema.ts` | 字段表（分组/控件/默认/联动/校验/序列化口径）—— **唯一事实来源** |
| `src/lib/scan/scan-params.ts` | 基线、策略/计划适配器、序列化、校验、定位助手 |
| `src/lib/components/scan/scan-params-form.svelte` | 共享表单（渲染 + 实时校验 + `pocPicker` 插槽） |
| `src/lib/components/scan/poc-picker.svelte` | 手动选择 PoC（两处共用） |
| `src/routes/(app)/schedules/+page.svelte` | 计划接入 + 每月频率 + 保存校验 |
| `src/lib/components/scan/quick-scan.svelte` | 扫描设置接入 + 起扫校验 |
| `src/lib/api.ts` | `ScanScheduleOptions` 补全、`ScheduleFreq` 加 `monthly`、`day_of_month` |
| `pkg/web/schedules.go`、`pkg/web/schedules_test.go` | 每月频率的推算/归一与测试 |

**风险与对策（实施后回看）**

| 风险 | 结果 |
|---|---|
| 改造扫描设置抽屉引入回归 | 以「行为等价」落地：`toScanOverrides` 复刻原 `buildOverrides` 口径，由 T-03 锁定 |
| 老计划字段缺失 | `scanParamsFromScheduleOptions` 逐字段回落默认值，T-15 覆盖 |
| 计划与全局配置预期不符 | "计划=快照"已明确；「默认徽标」按各自基线标注是否改动 |
| 字段继续漂移 | 单一 `scan-params.schema.ts`；T-18 断言字段表 key/request 唯一 |

---

## 14. 实施状态、差异与未做项

**与设计文档的差异**

| 项 | 设计 | 实现 | 原因 |
|---|---|---|---|
| `ScanParams.headers` | `string[]` | `string`（多行文本） | 与既有 `headersText` 口径一致；序列化时 `parseHeaderLines` 拆成数组，免去表单里的数组↔文本桥接 |
| 共享组件参数 | `mode="overrides"/"snapshot"` | 无 `mode`，由调用方选序列化函数 | 组件不必知道下发口径，职责更单一 |
| 扫描设置的分组 | 设计 §5.2 的 5 组 | 保留原 4 Tab（性能=perf+throttle、网络=net+oob、PoC、预设） | 维持既有信息架构；分组标题在 Tab 内展示 |
| 严重性所在位置 | PoC 组 | PoC 组（从原「性能」Tab 移入） | 与计划侧对齐 |
| 「默认」徽标 | 有 | 有 | 立即扫描按「当前策略」、计划按内置默认值判定（`baseline` 属性） |
| 计划存储版本号 | `scan_schema_version` | 无 | 未实施 |

**未做项**

1. **`scan_schema_version`**：老计划靠 `scanParamsFromScheduleOptions` 逐字段回落已可读；未来出现"必须区分缺失与默认"的字段时再加。
2. **每月最后一天 / 自定义 Cron**：`freq` 已结构化，扩展点清晰（加枚举 + `computeNextRun` 加分支）。
3. **折叠内字段的定位**：出错字段若在「进阶参数」折叠中（未渲染），只弹 toast 不滚动；可在定位前自动展开所属折叠。
4. **「项目 + 远程实例」保存时拦截**：远程派发不支持按项目，目前仍是运行时提示（沿用快速扫描），未在保存入口前置拦截。
5. **两侧字段一致性的交叉断言**：目前只断言字段表自身唯一，未按 Go `ScanCreateRequest` 的 json tag 做交叉校验。

**回归结论（本次改动）**

- `svelte-check`（全项目）：0 errors
- `npm test`：27 passed（node 23 + 浏览器 3 + demo 1）
- `go build ./...`、`gofmt`、`go test ./pkg/web/`：通过
- 本次涉及的文件 eslint / prettier 均通过

> 仓库另存在与本方案无关的既有 lint/format 债务（`monaco-editor.svelte` 5 处 unused 变量、若干文件 prettier 未格式化），本次未处理。

---

## 15. 项目默认参数统一方案（已实施）

> 本节由「新建计划、编辑计划、新建项目、编辑项目里同样存在扫描参数配置，该如何设计」这一议题引出。
> §0–§12 是已实施的「计划 vs 扫描设置」方案；本节把项目侧也统一到同一份字段表与组件。

### 15.1 第三种语义

一共有三处编辑扫描参数，`ScanParamsForm` 已覆盖前两处，语义各不相同：

| 入口 | 编辑组件 | 序列化出口 | 语义 |
|---|---|---|---|
| 扫描设置（立即扫描） | `ScanParamsForm` | `toScanOverrides(p, 基线)` | 相对基线：与基线相同则不下发 |
| 新建/编辑计划 | `ScanParamsForm` | `toScanSnapshot(p)` | 绝对快照：全量落库 |
| 新建/编辑项目 | **手写 8 个字段** | 无 | 稀疏默认值：只带"改过的项" |

共同点只有一条：它们最终都产出 `ScanCreateRequest` 的字段。**项目侧是唯一没接入共享组件、也没有校验的入口。**

### 15.2 现状问题

| # | 问题 | 证据 |
|---|---|---|
| 1 | 项目参数区是手写的 8 个字段，与计划共用组件形成两份实现 | [projects/+page.svelte](file:///Users/zanbin/gowork/github/zan8in/afrog/afrogweb/src/routes/(app)/projects/+page.svelte#L506-L543) |
| 2 | 「严重等级」「OOB 适配器」退化为自由文本；扫描设置/计划早已改为勾选组与枚举下拉 | §3.3 的一致性缺陷，项目侧漏改 |
| 3 | 同一张表单两种覆盖语义：数值/文本"有值才覆盖"，三个开关**无条件覆盖** | [applyProject](file:///Users/zanbin/gowork/github/zan8in/afrog/afrogweb/src/lib/components/scan/quick-scan.svelte#L107-L125) |
| 4 | 字段宽度三档：编辑器 8 ⊂ `ProjectDefaults` 13 ⊂ `ScanParams` 全量（如 `proxy` 会被消费却无法编辑） | [projects.go](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/web/projects.go#L23-L37) |
| 5 | 无校验：`Number("abc")` → `NaN` → `null`，直接落到后端 `int` 字段 | [buildDefaults](file:///Users/zanbin/gowork/github/zan8in/afrog/afrogweb/src/routes/(app)/projects/+page.svelte#L109-L123) |
| 6 | 计划选「项目」时完全不吃项目默认值，与"选中项目即带入默认参数"的认知冲突 | [schedules 抽屉](file:///Users/zanbin/gowork/github/zan8in/afrog/afrogweb/src/routes/(app)/schedules/+page.svelte#L716-L739) |

### 15.3 已确认取舍

1. **字段范围**：与计划一致，全 5 组 + 进阶折叠。
2. **未指定语义**：稀疏，只存与内置默认 `SCAN_PARAMS_BASELINE` 不同的项。
3. **计划 × 项目**：计划只吃项目的**目标成员**，不吃项目默认参数。
4. **节奏**：先评审本设计，再实现。

### 15.4 稀疏口径（关键定义）

新增序列化出口 `toProjectDefaults(p, base = SCAN_PARAMS_BASELINE)`，与既有 `serialize()` 同构，**只改一处**：

| mode | `toScanOverrides` | `toProjectDefaults` |
|---|---|---|
| `relative`（数值） | `cur !== base` 才写 | 同左 |
| `flag`（开关） | 仅 `true` 才写 | **`cur !== base` 才写（含 false）** |
| `nonEmpty`（文本/数组） | 非空才写 | 同左 |
| `derived`（节流互斥、OOB 开关） | 由 `applyThrottle`/`applyOob` 处理 | 同左 |

`flag` 必须按 `!== base` 判定：否则无法表达"显式关闭一个默认开启的项"（默认 `webFingerprint=true`、`portScan=true`、`taskSmartTimeout=true`）。

**「默认」徽标在项目侧的含义**：显示「默认」= 与内置默认一致 = **不会写入项目**；徽标消失 = 该项已被项目覆盖。
三处徽标因此统一为"该字段未被改动"，差别只在"改动后落到哪里"：

| 位置 | 比较基线 | 「默认」的含义 |
|---|---|---|
| 扫描设置 | 当前策略 | 不会出现在 overrides 里 |
| 计划抽屉 | 内置默认 | 等于出厂默认 |
| 项目抽屉 | 内置默认 | 不会写入项目 defaults |

三处各用各的基线是刻意的：每屏的"默认"要回答的都是"这屏会不会把它写出去"。

### 15.5 界面

- 项目抽屉「默认参数」区整体换成 `ScanParamsForm`（`groups={['perf','throttle','net','oob','poc']}`、`baseline={SCAN_PARAMS_BASELINE}`），进阶项走已有折叠。
- 区域标题下补一句说明：「这些参数是选中该项目起扫时的初值；与默认一致的项不会被保存。」——落实"界面明示语义"。
- 保存前跑 `validateScanParams`，失败时用既有的 `focusScanParam` 定位（与计划侧同款体验）。
- 项目卡片摘要 `defaultsSummary` 改为按稀疏键生成，与表单口径一致。

### 15.6 数据与表示

关键前提：后端 `ProjectDefaults` 目前只被**透传**（原样存、原样回显），**不参与起扫参数组装**——起扫参数由前端 `applyProject` 预填表单后再走 `toScanOverrides` 下发。这一点决定了存储表示可以选得更简单。

| 路线 | 做法 | 评价 |
|---|---|---|
| A. 扩展类型化 `ProjectDefaults` | 补齐缺失字段，json tag 与请求体对齐 | Go 侧要多维护一张字段表，与 `scan-params.schema.ts` 漂移；且 `bool`/`int` + `omitempty` **无法表达"显式 false / 显式 0"**（默认开启的 Web 指纹要关掉、`max_host_error` 要设 0），必须全改指针 |
| **B. 稀疏的不透明对象（推荐）** | `Defaults` 仍是 JSON 对象，内容为「请求字段名 → 值」，只含被覆盖的键；前端 `toProjectDefaults` 写、`scanParamsFromProject` 读，后端仅透传 | 键存在即"显式设置"，天然规避 A 的零值歧义；不引入第二张字段表 |

兼容（按 B 路线）：

| 历史形态 | 读取处理 |
|---|---|
| `portscan` / `webprobe` | 并入 `port_scan` / `web_fingerprint`（沿用 `scanParamsFromScheduleOptions` 已有写法） |
| `severity` 为 CSV 字符串 | `splitCsv` 成数组 |
| `enable_oob=false` 且 `oob` 为空 | 视为关闭 OOB |

`applyProject` 重写为 `scanParamsFromProject(defaults)`：以**策略合并结果**为底，再用 defaults 稀疏覆盖，**删掉布尔的无条件覆盖**；与 `toProjectDefaults` 互为逆运算（参照 `scanParamsFromStrategyMerged` ↔ `toStrategyGroups` 的既有写法）。

### 15.7 与其它入口的关系

| 关系 | 结论 |
|---|---|
| 项目 ↔ 立即扫描 | 选中项目 → 预填表单（策略基线 + 项目覆盖）；用户再改动则走 `toScanOverrides` 下发，**项目本身不变** |
| 项目 ↔ 计划扫描 | 计划只取项目的**目标成员**；扫描参数以计划自身快照为准，不读项目默认值（§15.3-3）。在「选项目」处补一句说明 |
| 项目 ↔ 扫描策略 | 生效顺序：**策略合并基线 → 项目默认覆盖 → 用户当次改动**。策略是全局微调，项目是这个资产空间的口径 |

### 15.8 实现结果

| 步骤 | 内容 | 涉及 |
|---|---|---|
| 1 | `toProjectDefaults` / `scanParamsFromProject`（含 `portscan`/`webprobe`/CSV severity 兼容）+ 6 个单测 | `scan-params.ts`、`scan-params.spec.ts` |
| 2 | 项目抽屉换 `ScanParamsForm`（全 5 组 + `pocPicker`）+ 保存前校验与定位 + 区域说明文案 | `projects/+page.svelte` |
| 3 | `applyProject` 改为「策略基线 + 项目覆盖」，取消项目时回到基线 | `quick-scan.svelte` |
| 4 | `ProjectDefaults` 改为稀疏不透明对象（Go `map[string]any` + `MarshalJSON` 保证空值输出 `{}`） | `projects.go`、`api.ts` |
| 5 | 卡片摘要按稀疏键 + 字段表标签生成（新增参数无需改此处） | `projects/+page.svelte` |

> 回归：`npm test` 46 passed（`scan-params.spec.ts` 30 项含本次新增 6 项、`scan-params-form.svelte.spec.ts` 3 项）；`go build ./...`、`gofmt`、ESLint、Prettier 均通过。

### 15.9 未做项

1. 项目默认值不支持"按分组禁用"（例如只让项目管网络、不管性能）——当前是全组可覆盖。
2. 不支持"从项目一键生成计划"。
3. 不引入 `scan_schema_version`（沿用 §14 结论）。

---

## 附：交付物清单

| 交付物 | 位置 |
|---|---|
| 界面设计稿 | 第 5 节（信息架构 + 字段规范 + 分组表） |
| 交互流程图 | 第 6 节 + 内联流程图 |
| 参数配置逻辑说明 | 第 3–4、7–9 节（模型/序列化/联动/校验/扩展） |
| 用户操作手册 | 第 12 节 |
| 测试用例与覆盖情况 | 第 11 节 |
| 实施结果 / 差异 / 未做项 | 第 13–14 节 |
| 项目默认参数统一方案 | 第 15 节 |
