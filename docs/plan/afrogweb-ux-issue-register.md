# afrogweb 体验问题登记表

- 用途：把 afrogweb（`/Users/zanbin/gowork/github/zan8in/afrogweb`）+ 其 Go 后端（`/Users/zanbin/gowork/github/zan8in/afrog`）的体验/功能问题集中登记，明确**已修 / 待修 / 不修 / 暂缓**四种状态，避免"哪些修了、哪些不修"只存在于聊天记录里。
- 维护约定：
  1. 每条有**稳定 ID**（`UX-xx`），状态只在这四态之间流转，不删除条目。
  2. 修复后把状态改为「已修」，并在文末「变更记录」追加一行（日期 + ID）。
  3. 新增问题追加到「待修」并编号，不要插队改历史编号。
  4. 「证据锚点」写文件 + 行号；标 `⚠️未复核` 的条目表示来自静态走查、尚未逐行确认，动手前先复核。
- 相关设计文档：[afrog-web-schedule-scan-params-design.md](./afrog-web-schedule-scan-params-design.md)（计划扫描参数方案）

---

## 状态图例

| 状态 | 含义 |
|---|---|
| 待修 | 已确认、有明确修法，排队中 |
| 已修 | 已完成并通过校验 |
| 不修 | 有明确理由不做（含等待其它模块重构） |
| 暂缓 | 有价值但依赖靠后或需产品决策 |

---

## 一、待修

### 高优先级（会产生错误结论 / 白花钱 / 数据不可信）

| ID | 级别 | 问题 | 影响 | 证据锚点 |
|---|---|---|---|---|
| **UX-02** ✅已复核 | 严重 | **AI 额度先扣后用**，失败/超时/取消/重试都白扣 | 免费 20 次/月，一次失败+重试烧 2 次；全仓无退款逻辑 | [ai.go#L326-L344](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/web/ai.go#L326-L344)（`TryUseAIQuota` 在 `aiStreamCompletion` 之前） |
| **UX-04** ✅已复核 | 严重 | **SSE 断线重连漏事件** | 断线期间的命中与进度**永久丢失**、前端计数少计；后端已实现断点续传但没被用上 | [scan-store.svelte.ts#L1210-L1221](file:///Users/zanbin/gowork/github/zan8in/afrogweb/src/lib/stores/scan-store.svelte.ts#L1210-L1221)（onerror → close + 重建，`openScanEventsSSE(scanTaskId)` **未传 replay**） |
| **UX-07** ✅已复核 | 严重 | **会员状态「未知」未做三态**：`meFailed` 只被顶栏使用；`meLoaded=false` 期间多处按非会员渲染 | ① `/api/me` 持续失败时，台账/计划扫描/差异对比/通知四页**永远停在"加载中"**，无错误无重试；② 会员首屏会闪"假的会员锁 / 去激活会员" | `+layout.svelte` 只 `markMeFailed()` 不置 `meLoaded`；`ledger` / `schedules` / `diff-view` / `notify-settings` 只判 `meLoaded`；`app-sidebar` / 概览台账卡 / 报告导出与处置区 / 任务与项目导出 / 集群编辑按钮只判 `isCurated` |

### 中优先级（规模、契约与静默失败）

| ID | 级别 | 问题 | 影响 | 证据锚点 |
|---|---|---|---|---|
| **UX-03** ⚠️未复核 | 中等 | AI 配额用尽只给「重试」，**没有「去激活会员」** | 后端文案让用户去升级，前端却无入口 | `ai.go:331-334` vs `ai-stream-sheet.svelte` 的 `needsSetup` 只认 `not_configured` |
| **UX-05** ⚠️未复核 | 中等 | 导出**静默截断 20000 行** | 用户拿到"完整报告"其实少了数据，提示只藏在文件内容里 | [sqlitex.go#L546](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/db/sqlite/sqlitex.go#L546) `ExportRowLimit = 20000`；前端下载链路不读 `Truncated` 标记 |
| **UX-06** ✅已复核 | 严重 | **导出全内存**：全量读 → 全量渲染 → 全量写，前端再读成 blob | 最多 2 万行 × 每行含请求/响应全文，链路里同时存在 3~4 份副本 → 点导出卡死/无响应 | [exports.go#L99-L129](file:///Users/zanbin/gowork/github/zan8in/afrog/pkg/web/exports.go#L99-L129)、`xlsx.go:63`、`export.ts:115` |
| **UX-08** ⚠️未复核 | 严重 | **`result` 表只增不减**：无任何清理/归档入口，也不 VACUUM | 数月持续扫描后磁盘与查询成本不可控 | 路由表无 `DELETE /reports`、无 retention；全仓无 `VACUUM` |
| **UX-09** ⚠️未复核 | 严重 | **台账一次请求对整表跑 3 遍 `GROUP BY`**，角标每 30s 再跑一遍 | 数万行起表现为"台账间歇加载失败 / 待确认数变 0" | `sqlitex.go:1032/1038/1054`；`nav.go:70-74` |
| **UX-10** ⚠️未复核 | 中等 | **导出权限三处三种交互**：报告页可点击去激活（已修）／项目页**静默置灰**／任务页**静默置灰** | 同一能力行为不一致，用户以为"功能坏了" | `reports/+page.svelte`（已改）vs `projects/+page.svelte` vs `scan/task-view.svelte` |
| **UX-11** ⚠️未复核 | 中等 | **远程派发对非会员整块消失**；集群「编辑节点」静默消失 | 能力**不可发现**，用户不知道有这功能、也不知去哪激活 | `cluster/remote-tasks.svelte`、`quick-scan.svelte`（执行节点选择器）、`cluster-panel.svelte:233` |
| **UX-12** ✅已复核 | 中等 | **静默失败与掩埋原因**：资产 `loadMore` **没有 catch**；资产错误面板用硬编码文案而非真实 `error`；非法端口**静默丢弃**；计划数 100 无前置提示 | 失败被伪装成"没有更多/没数据"；用户填错端口不会被告知 | [asset-store.svelte.ts#L111-L126](file:///Users/zanbin/gowork/github/zan8in/afrogweb/src/lib/stores/asset-store.svelte.ts#L111-L126)（无 catch）；`assets/+page.svelte` 错误面板；`portscan/iterator.go`；`schedules.go:666-668` |

### 低优先级（可访问性 / 国际化）

| ID | 级别 | 问题 | 影响 | 证据锚点 |
|---|---|---|---|---|
| **UX-13** ✅已复核 | 中等 | **a11y 缺口**：① `<html lang="en">` 而界面是中文；② 4 处关键输入无标签（含核心的「扫描目标」Textarea）；③ 全仓**无** `aria-live`/`role="status"`，列表加载/空/错误对读屏零感知；④ 多处 24–28px 图标按钮未用项目已有的 `extend-touch-target` | 读屏按英文音朗读中文；移动端易误触；长任务结束读屏无感知 | [app.html#L2](file:///Users/zanbin/gowork/github/zan8in/afrogweb/src/app.html#L2)；`quick-scan.svelte`（目标 Textarea）、`ledger`（备注）、`assets`（搜索）、`curated`（激活码）；`reports`/`assets`/`pocs` 列表无 `aria-live` |

**修复备注**
- UX-02：改为**成功返回后才扣额度**（或失败释放），并让同一次重试不重复计费。
- UX-04：重连时带上 `last_seq`（或用后端 `replay=1`），复用已实现的 3000 条缓冲。
- UX-07：把 `meFailed` 接进四个页面（失败态给"重试"而不是无限"加载中"）；所有门控判断改为 `!meLoaded → 加载中`。
- UX-06/UX-08/UX-09 属"数据长大才炸"，可分期：先做**提示与门槛**（UX-05/UX-12），再做**流式与清理**（UX-06/UX-08/UX-09）。

---

## 二、已修

| ID | 内容 | 证据 |
|---|---|---|
| F-01 | 共享 Button 增加 `loading` 三态，全站 23 个文件、140 处调用点统一 | `lib/components/ui/button/button.svelte` |
| F-02 | 「新建计划」扫描参数与「扫描设置」完全对齐：13 → 30 项、字段名统一为 `web_fingerprint`/`port_scan`、新增每月频率与实时校验 | `lib/scan/scan-params.*`、`lib/components/scan/scan-params-form.svelte`、`pkg/web/schedules.go` |
| F-03 | 修复 scan「资产发现」重试无效（`probesLoadedFor` 非响应式） | `scan/task-view.svelte` |
| F-04 | 计划列表与编辑页显示「所属实例」（离线也能显示友好名） | `routes/(app)/schedules/+page.svelte` |
| F-05 | 抽出共享「手动选择 PoC」组件，两处复用 | `lib/components/scan/poc-picker.svelte` |
| F-06 | **资产归档可逆**：新增「已归档」视图 + `include_archived` + 批量归档二次确认 + 取消归档 | `pkg/db/sqlite/asset.go`（`view=archived`）、`routes/(app)/assets/+page.svelte` |
| F-07 | **当前实例标识**：顶栏常驻实例芯片 | `lib/stores/server-info.svelte.ts`、`app-topbar.svelte` |
| F-08 | **会员身份降级自愈**：`/api/me` 由"4 次失败即永久放弃"改为快退避 + 30s 低频轮询；顶栏区分"会员状态未同步" | `routes/(app)/+layout.svelte`、`lib/stores/auth.svelte.ts` |
| F-09 | **术语收敛**：严重等级 / 漏洞 / 会员 / PoC 各统一一套；导航「Curated」→「会员中心」 | 全站文案、`lib/locales/zh.json` |
| F-10 | **会员门槛**：报告页导出菜单由静默禁用改为可点击跳转去激活 | `routes/(app)/reports/+page.svelte` |
| F-11 | **打通「证据→判定→归档」**：报告详情内可直接 AI 研判 + 写台账状态；后端详情 JOIN 台账；`POST /ledger/status` 的 `note` 改为可选（省略即保留原备注，修掉"静默清空备注"隐患） | `routes/(app)/reports/+page.svelte`、`pkg/web/handlers.go`、`pkg/db/sqlite/sqlitex.go` |
| F-12 | 导出回执带真实文件名（原为"报告已开始下载"） | `lib/export.ts` |
| F-13 | 概览统计卡可下钻（含非会员点台账卡直接去会员中心） | `routes/(app)/+page.svelte` |
| F-14 | 清理仓库既有 lint/format 债务（`monaco-editor.svelte` 未使用变量 + prettier 全量格式化），`npm run lint` 首次全绿 | — |
| F-15 | **OOB 假阴性可见化**（UX-01）：新增 `lib/oob.ts` 收敛「是否已配凭据」与后端英文状态（兼容 `(Not configured)`/`(incomplete configuration)`/`(Connection failed)` 三种措辞）；任务详情顶部红色告警条 + 统计卡「带外检测」中文化 + 「去设置」直达 `/settings#oob`；起扫（快速扫描）与保存计划时**前置提醒**（不阻断）。后端确认无需改动：`engine.getOOBStatus()` 早已把 `oob_enabled=false` + `ceyeio (Not configured)` 经 `scan_info` 事件下发，缺口在前端未消费 | `lib/oob.ts`、`lib/oob.spec.ts`（12 用例）、`scan/task-view.svelte`、`scan/quick-scan.svelte`、`routes/(app)/schedules/+page.svelte`、`settings/oob-settings.svelte` |

---

## 三、不修

| ID | 内容 | 理由 |
|---|---|---|
| N-01 | **PoC 编辑态串写**（编辑 A 时点列表项 B，保存会把 A 的 YAML 写进 B） | 已决定 PoCs 模块冻结、待重构时一并处理。**风险仍然存在**：在重构前，编辑中途不要点击左侧列表项 |
| N-02 | 精选 PoC 无会员门控 + `POST /pocs/curated/sync` 是**死接口**（后端无此路由） | 同属 PoCs 冻结，避免在即将重构的模块上做无用功 |
| N-03 | `themes.css` 声明 13 套主题但被强制 `mono`；`neutral` 枚举无对应样式 | 疑似有意收敛主题、不影响功能；仅登记 |

---

## 四、暂缓

| ID | 内容 | 暂缓原因 |
|---|---|---|
| P-01 | 报告 / 台账的**排序、页码跳转、每页条数切换** | 需后端新增排序参数，跨前后端 |
| P-02 | 报告**列表**行显示台账状态 | 详情已做（F-11），列表 JOIN 另做 |
| P-03 | 远程任务详情的「导出 / 在漏洞报告中查看全部」出口 | 需远程执行节点侧接口配合 |
| P-04 | 列表空态加 CTA、概览「最近扫描」下钻 | 体验加分项，非阻塞 |
| P-05 | 「打印为 PDF」的后续指引（一句话 toast） | 未纳入本轮 |
| P-06 | **i18n 全量英文补全**（业务页上万汉字，切换开关现被注释禁用） | 属产品级决策：是否做英文版 |
| P-07 | 台账体验包：批量改状态、备注脏值提示、`hit_count`/`first_seen` 列 | 建议作为一整包做，避免反复改同一文件 |
| P-08 | SSE 通道满时对 `result` 事件的丢弃策略（服务端 256 缓冲） | 与 UX-04 同源，建议一起评估 |

---

## 变更记录

| 日期 | 变更 |
|---|---|
| 2026-10-07 | 建立登记表；登记 F-01～F-14（本会话已修）、UX-01～UX-13（待修）、N-01～N-03（不修）、P-01～P-08（暂缓） |
| 2026-10-07 | 修复 UX-01（OOB 假阴性可见化）→ F-15，从「待修」移入「已修」；校验：`npm run lint` / `npm run check`（0 errors）/ `npx vitest run`（39 passed）全绿 |
