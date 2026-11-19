<!--
title: MCP 服务
slug: /docs/user-guide/mcp
lang: zh
summary: 用 `afrog mcp` 把观测、探测、验证与破坏性动作暴露成 MCP 工具，供 AI Agent 在策略、预算与审计约束下调用。
status: published
source: new
last_reviewed: 2026-11-14
-->

## 它是什么

`afrog mcp` 把 afrog 已有的能力暴露成一组 **MCP（Model Context Protocol）工具**，让 Claude Desktop、Claude Code、Cursor 或自建 Agent 直接调用：

- **看**：查命中、取证据、读攻击面子图（含端点与参数）、拉观测流
- **测**：发单次 HTTP 请求、探测端口、识别指纹、检索 PoC、校验 PoC 草稿
- **验**：跑单个 PoC 得到可重放证据
- **动**：执行弱口令/字典尝试（默认关闭）

设计取向是「Agent 只能提议，执行和证据留在 afrog」：所有工具调用都要先过策略、预算与作用域，拒绝时返回结构化原因，不会静默跳过。

## 启动

### stdio（最常用）

```bash
afrog mcp
```

适合由客户端作为子进程拉起，不需要端口。

### HTTP

```bash
afrog mcp -listen 127.0.0.1:16870 -token your-token
```

同一个监听同时提供两种入口：

| 路径 | 用途 |
| --- | --- |
| `/mcp` | Streamable HTTP（2025-03-26 起的主流客户端） |
| `/sse` + `/messages` | 经典 HTTP+SSE（旧客户端） |
| `/healthz` | 健康检查 |

安全约定：

- 默认只监听本机时可以不配 token；
- 监听 `0.0.0.0` 等非本机地址时**必须**提供 `-token`，否则拒绝启动；
- 鉴权支持 `Authorization: Bearer <token>` 或 `?token=`；
- 按 MCP 规范校验 `Origin`：浏览器带来的跨站来源一律 403（防 DNS rebinding）；不带 `Origin` 的原生客户端与 curl 不受影响。

## 客户端配置

以 stdio 为例（不同客户端字段名略有差异）：

```json
{
  "mcpServers": {
    "afrog": {
      "command": "afrog",
      "args": ["mcp", "-policy", "/etc/afrog/mcp-policy.yaml"],
      "timeout": 600
    }
  }
}
```

远程 HTTP 客户端填 URL 与鉴权头（`timeout` 同样适用）：

```json
{
  "mcpServers": {
    "afrog": {
      "url": "http://127.0.0.1:16870/mcp",
      "headers": { "Authorization": "Bearer your-token" },
      "timeout": 600
    }
  }
}
```

> **务必显式设置 `timeout`（单次工具调用超时）**。`scan.start` 一次并发扫一个技术栈可能要几分钟，`search` 留空跑全库更久；而多数客户端的默认工具超时只有 60 秒——不调大就会在长扫描跑到一半时被**客户端侧掐断**（现象是「工具调用超时/无响应」，但 afrog 子进程其实还在跑，白扣额度）。建议设成 **10 分钟**。
>
> 注意 `timeout` 的**字段名与单位因客户端而异**：Cline / Roo Code 用 `timeout`、以**秒**计（默认 60，上限 1 小时，故填 `600`）；部分客户端用**毫秒**（10 分钟 = `600000`）；也有客户端把超时放在图形界面里而不是 JSON（如 Cherry Studio 的「网络超时」）——不支持的客户端会直接忽略该字段。请按你所用客户端的文档换算。另外 `scan.start` 自身还有整批扫描的 `timeout_sec`（默认 300 秒、最大 1800 秒），客户端超时应不小于它。

## 策略

默认策略是 **只读**：刚拉起的服务不会自动获得发包能力。放宽策略有两条路，优先级为 `-policy` 参数 > `afrog-config.yaml` 的 `agent.policy`（即 Web 控制台保存的位置）> 只读默认：

```yaml
policy:
  mode: safe                  # readonly | safe | full
  allow: ["observe.*", "probe.*", "verify.*"]
  deny:  ["act.brute"]
  scope:
    allow_hosts: ["10.0.0.0/8", "*.corp.example"]
    deny_hosts:  ["10.0.0.1"]
    deny_paths:  ["/logout"]
  budget:
    requests: 2000
    duration: 30m             # 空闲窗口：连续这么久没有消耗额度的调用即开新会话
  destructive: false
  audit: true
```

用法：

```bash
afrog mcp                                     # 没传 -policy 时跟随 afrog-config.yaml 的 agent.policy
afrog mcp -policy ./agent-policy.yaml         # 显式指定，覆盖配置
afrog mcp -policy ./p.yaml -audit ./a.jsonl   # 同时指定审计文件
```

> 在 Web 控制台「Agent 工具面 → 策略与审计」保存后，路径会写进 `agent.policy`，因此客户端里不起眼的 `afrog mcp` 也会读到同一份策略；显式传入的 `-policy` 仍优先。

### 档位

| 档位 | 允许 | 典型场景 |
| --- | --- | --- |
| `readonly`（默认） | `observe.*`、`plan.*`、`poc.search`、`poc.draft`、`judge.*`、`learn.*`、`server.*` | 只让 Agent 读结果、做判断、写本地 advisory |
| `safe` | 在只读基础上加 `probe.*`、`scan.start`、`verify.replay`、`poc.submit` | 允许复测与验证，不改变目标状态 |
| `full` | 除显式 `deny` 外全部允许 | 受控环境下的完整评估 |

判定顺序固定为：`deny → allowlist → mode → destructive → scope`。**deny 永远优先**。

### 预算与审计

- `budget.requests` 是一次会话的请求额度，**只统计真正发包的动作**；读库、查证据这类只读调用既不扣额度，也不受任何预算限制。
- `budget.duration` 是**空闲窗口**（默认 10 分钟）：只要有消耗额度的调用成功，窗口就顺延；连续空闲这么久即判定会话结束，下一次调用自动开一个新会话、把额度补满。因此长驻服务（Web 服务、`afrog mcp -listen`）不会跑够一段时间就整体失效，也不必为了恢复额度去重启。
- 发包类动作（如 `scan.start`、`poc.submit`）会按候选 PoC 可能的请求数预留预算，而不是固定扣 1。
- `audit: true` 配合 `-audit audit.jsonl` 逐条记录「哪个动作、打哪、放行与否、剩余预算」。
- 拿不准还剩多少额度、当前是什么档位，调只读的 `server.status` 看 `requests_remaining` / `policy.mode`——它本身不计额度，比撞上 403/429 再回头猜更省事。

## 工具清单

| 工具 | 作用 | 需要的能力 |
| --- | --- | --- |
| `server.status` | 只读自省：返回本次会话的策略档位、剩余请求额度与空闲到期时间、作用域白/黑名单，以及服务与协议版本；不发包也不扣额度 | 只读 |
| `observe.findings` | 按项目、台账状态、严重级别列命中 | 只读 |
| `observe.evidence` | 按 result id 或 `evd_` 开头的证据 id 取证据 | 只读 |
| `observe.state` | 以资产为根返回攻击面子图（上下游、端点/参数、技术栈与候选 PoC、覆盖、命中数） | 只读 |
| `observe.observations` | 按 `seq` 游标增量拉取观测流：开放端口、Web 指纹、HTTP 事务、被动代理流量、TLS 证书、带外回连 | 只读 |
| `plan.next` | 把攻击面图压成下一步的 `Action` 提议（`scan.start` / `probe.fingerprint`），按确定性分数排序并附依据；同一源站的候选合并成一条 `scan.start`（`search` 为技术栈关键词）。`proposals` 为空表示该主体还没有可复现候选（先 `probe.*` 补观测，或改用 `poc.search`） | 只读 |
| `poc.search` | 按关键词与级别检索本机已有 PoC，返回真实存在的 id、本地路径，以及 `total`（命中总数）与 `truncated`（是否被 `limit` 截断）。**它等价于 `afrog -pl -s <keyword>`：扫描前先预检「本机有没有这个技术栈的 PoC」——结果为空就别扫，说明 afrog 没有该指纹/产品的漏洞**；关键词口径与 `-s` 完全一致（按逗号拆成多个词、任一命中 id/名称/标签即算命中），选检优先用指纹关键词（jquery、thinkphp、shiro），命中后把同一关键词交给 `scan.start`，没有线索时先 `plan.next`，`severity` 只作按级别的兜底粗筛（用户没指定等级就留空）。返回的 `conclusion` 显式区分两种情况：`has_poc`（本机有该关键词的 PoC）与 `no_poc_for_keyword`（本机没有，此时附 `guidance` 说明「afrog 暂无该产品的检测能力，**不能据此判定目标无漏洞**」，可换更通用的关键词，或征得用户同意后用空 `search`） | 只读 |
| `poc.draft` | 校验一份 PoC 草稿：结构、能力等级、请求量估算；可选落盘供 `poc.submit` 实跑使用 | 只读 |
| `poc.submit` | 在真实目标上受限实跑一份草稿并取证据，通过后放入待人工终审队列（`afrog poc approve/reject`） | `verify.*`（按草稿能力分级，`exec` 级还需 `destructive: true`） |
| `probe.http` | 发一次 HTTP 请求，返回状态、头、正文与耗时 | `probe.*` |
| `probe.port` | 单主机端口探测（默认 top，单次上限 65535 个），返回开放端口与服务指纹 | `probe.*` |
| `probe.fingerprint` | 单 URL 指纹识别：技术栈、WAF/CDN、跳转链与 TLS 摘要。返回的 `suggested_search` 是可直接透传的关键词串，由各技术栈的**标识词**（PoC 的规则 id、技术名及其连字符写法，**不含 category**——category 太宽，一搜一大片）拼成，与 afrog 自身的 `requires` 门控口径一致，模型不必再猜关键词；先用它 `poc.search` 预检，有结果再把同一串交给 `scan.start` 并发扫描。`favicon` 默认 `false`；当首页一个技术栈都没识别出来时会**自动补抓一次 favicon**（单独计 1 次预算）再匹配，返回里的 `favicon_fetched` 标明是否补抓过 | `probe.*` |
| `scan.start` | **取代逐个验证的主入口**：用一次子进程并发跑完某个技术栈（`search` 关键词）下的全部 PoC，返回可重放证据。`afrog` 按 `-s` 选 PoC（命中 id/名称/标签）；`search` 留空表示不加关键词、跑全库（没有指纹线索时的兜底，需先征得用户同意）。带关键词时，命中该关键词的指纹 PoC 不受 `severity` 限制也会被保留（但关键词是硬前提，不命中的指纹 PoC 照样被滤掉），于是指纹阶段照常运行、`requires` 按真实指纹放行——既不会有「单跑一个漏洞 PoC 被指纹门控跳过」的假阴性，也不会为 N 个候选发 N 次串行请求。反向 PoC 需要 `agent.oob`，未配置时明确报错（fail-closed）。返回里的 `library` 给出本机 PoC 库对该关键词的覆盖（`matched_pocs` 库中匹配总数，等价 `afrog -pl -s <关键词>` 的 Total；`executed_pocs` 本次实际执行数；两者都不是命中数），`conclusion` 显式区分三种结论：`hit`（有命中）、`no_finding`（本机有 PoC 但均未命中，或全被 `severity` 滤掉一条未执行）、`no_poc_for_keyword`（本机没有该关键词的 PoC）；后两种附 `guidance` 说明「**不等于目标无漏洞**」，并给出改关键词 / 去掉 `severity` / 征得同意跑全库的建议 | `scan.start` |
| `verify.replay` | 按证据 id 重放一次，比对 id/digest 判断旧结论是否仍成立 | `verify.*` |
| `act.brute` | 弱口令/字典尝试 | `full` + `destructive: true` |
| `act.oob_payload` | 铸一组带外回连地址（`filter` + DNS/HTTP 等），用于命令执行、XXE、SSRF 等需要反连回显的验证 | `full` + `destructive: true` |
| `act.oob_wait` | 等待一次带外回连，命中后返回证据并写入观测流（`oob_hit`） | `full` + `destructive: true` |
| `judge.brief` | 按 result id 或证据 id 取一条命中的研判材料：证据链、同目标周边观测、攻击面子图与已有研判意见 | 只读 |
| `judge.record` | 记录一条研判意见（`likely_true`/`likely_false`/`uncertain`）到 `judgement` 表，作为 advisory 供人工复核；**不改漏洞台账** | 只读（写本地 advisory） |
| `learn.brief` | 取调优素材：流水线指标（含自动入库率）、最近终审决议（含驳回原因）与待审调优建议 | 只读 |
| `learn.record` | 记录一条调优建议（`rule`/`threshold`/`other`）到 `learn_suggestion` 表，供人工审阅；**不自动应用任何 diff** | 只读（写本地 advisory） |

### 工具怎么选（AI 客户端也会收到同样的提示）

`afrog mcp` 在 `initialize` 里返回一段 `instructions`（MCP 规范的可选字段），客户端会把它并入模型上下文，用来告诉模型这套工具怎么用——否则最常见的两种误用是：逐个 PoC 串行慢验，以及指纹命中后不知道该去 `poc.search` 检索对应 PoC。要点与下表一致：

1. **先 `poc.search` 预检再 `scan.start`**：指纹识别后，`probe.fingerprint` 返回的 `suggested_search` 就是可直接透传的关键词串——先把它交给 `poc.search`（等价 `afrog -pl -s`）确认本机确实有这个技术栈的 PoC；结果非空就把**同一关键词**交给 `scan.start` 并发扫描，为空就别扫——afrog 没有该指纹/产品的漏洞。别自己把 `technologies` 映射成关键词（曾出现识别出 jQuery、却去搜 wordpress,nginx 之类根本没识别到的产品的情况）。自己写的 PoC 先用 `poc.draft`（`save: true`）落盘，再把返回的 `poc_path` 交给 `poc.submit` 受限实跑取证据。
2. **先让 `plan.next` 当主驾驶**：它按攻击面（端点 / 技术栈 / 已有结论）给出确定性的下一步——对还没指纹的 origin 提议 `probe.fingerprint`，对已识别技术栈的端点直接给出 `scan.start` 提议（`search` 为技术栈关键词，同一源站的多条候选会合并成一条），并自动跳过已出结论的组合；候选为空时再自己动手。
3. **别用「按 severity 挨个验」当默认策略**：`severity` 只按级别粗筛，与目标是否真的运行那个产品无关——那既白扣额度、又得不出可信「无漏洞」结论。用户没有指定等级就留空（即扫描所有等级）；正确姿势永远是「指纹 → `poc.search` 预检 → `scan.start`」。**没有任何指纹线索时**（`technologies` 为空、`plan.next` 也给不出关键词）：不要凭空编关键词，**先询问用户是否要用 afrog 扫描全部漏洞**，得到同意后再用**空 `search`** 调 `scan.start`（空关键词 = 不加过滤、跑全库所有 PoC，请求量与耗时都大得多）。`scan.start` 返回的 `conclusion` / `guidance` 会把「命中」「本机有 PoC 但未命中」「本机没有该关键词的 PoC」三种情况分开讲清楚——后两者都**不等于目标无漏洞**。
4. **只读工具**（`server.*` / `observe.*` / `plan.*` / `poc.search` / `poc.draft` / `judge.*` / `learn.*`）不发包、不扣预算；`probe.*` / `scan.start` / `verify.replay` / `poc.submit` / `act.*` 会发包并按请求数扣会话额度——`scan.start` 一次并发跑完一个技术栈的 PoC，远比逐个 `verify` 省时省额度。拿不准当前什么档位、还剩多少额度，先看 `server.status`。

### 协议层：客户端还会拿到哪些提示

除了工具清单本身，`afrog mcp` 按 MCP 规范给客户端一系列结构化提示，让「哪些能自动放行、哪些要确认、下一步试什么」不必靠模型猜：

- **`instructions`**（`initialize` 返回）：一段用法说明，客户端会并入模型上下文，要点即上文「工具怎么选」。
- **协议版本协商**：客户端报的版本在支持集（`2024-11-05` / `2025-03-26` / `2025-06-18`）内就沿用，否则回 afrog 支持的最新版，而不是原样复述一个并不会说的版本。
- **`title` 与 `annotations`**（每个工具）：`title` 是给人看的短标签；`annotations` 是提示性标注——`readOnlyHint` 与 afrog 自己的只读判定完全一致（`server.*` / `observe.*` / `plan.*` / `poc.search` / `poc.draft` / `judge.*` / `learn.*`），`openWorldHint` 标出会向外部目标发包的工具，`destructiveHint` 只给 `act.brute`、`poc.submit`。它们**只是提示、不参与门控**：放行与否仍由策略与预算决定。
- **`outputSchema` 与 `structuredContent`**：返回结构稳定的工具（如 `server.status`、`poc.search`、`plan.next`）声明 `outputSchema`，调用结果里会附 `structuredContent`，客户端可直接按 schema 取值；返回大对象的工具不声明，避免同一份 payload 在 `content` 与 `structuredContent` 里各塞一遍。
- **进度通知**（`notifications/progress`）：客户端在 `tools/call` 的 `_meta.progressToken` 里声明要进度时，长调用（如 `act.oob_wait` 等回连）会按秒上报「已等多久 / 上限」；Streamable HTTP 是一次 POST 一问一答、没有中途推送的地方，因此该传输不推进度。
- **取消**（`notifications/cancelled`）：客户端按 `requestId` 取消某一次调用时，afrog 精确取消那一次，而不是把整条连接一起断掉；stdio 这类可并发读写的持久连接才支持中途取消。

### 证据长什么样

每条命中都可以取到一份可重放证据：

```json
{
  "id": "evd_...",
  "digest": "sha256:...",
  "poc_id": "redis-weak-login",
  "target": "10.0.0.5:6379",
  "steps": [{ "role": "confirm", "matched": true }],
  "replay": {
    "command": "afrog verify --poc redis-weak-login --target 10.0.0.5:6379",
    "deterministic": true
  },
  "confidence": "certain"
}
```

证据 id 由内容算出：同一条命中在任何节点、任何任务里都得到同一个 `evd_`，Agent 之间可以直接传引用。集群回填时证据会随命中一起搬到发起端，因此远端命中的 `observe.evidence` 也能查到。

### 观测流长什么样

证据回答「这条命中凭什么成立」，观测流回答「过程中还看到了什么」。它是只追加的事件序列，用 `seq` 做游标：

```json
{
  "seq": 1024,
  "id": "obs_...",
  "project_id": "",
  "source": "http",
  "kind": "http_transaction",
  "subject": "http://10.0.0.5/login",
  "ts": "2026-11-14T10:00:00Z",
  "payload": {
    "method": "GET",
    "url": "http://10.0.0.5/login",
    "status": 200,
    "matched": true,
    "latency_ms": 41,
    "request_excerpt": "GET http://10.0.0.5/login\nAccept: */*",
    "response_excerpt": "HTTP/1.1 200 OK\nServer: nginx/1.25.3\n\n..."
  }
}
```

- 已记录七类：`port_open`（端口扫描）、`tech`（Web 指纹）、`http_transaction`（`probe.*` / `verify.*` 实际发出的请求）、`http_passive`（被动代理看到的真实流量）、`tls`（https 证书摘要）、`oob_hit`（带外回连）、`dns`（主机名解析）。
- `http_passive` 只留元数据（方法、URL、状态码、类型、字节数），不存报文；它按「方法 + URL + 状态码」去重，因此同一接口换参数值会各自成条。被动观测先于检测发布：即使这条流量随后被判重复、跳过或丢弃，事件仍然成立。
- `tls` 记录签发者、主体、到期时间与 SAN；`oob_hit` 记录被目标打回来的 filter 与所属 PoC，回连时间与来源 IP 不参与去重。
- `dns` 记录 Web 目标主机名解析到的地址集合（目标本身是 IP 字面量时不产生），地址顺序不参与去重。
- 检索方式：`next_seq` 直接作为下一次的 `since_seq`；另可按 `sources`、`kinds`、`subject`、`project_id` 过滤。`subject_under: true` 把 `subject` 当子树根（主机含端口、端点含参数），不做纯前缀匹配。
- `observe.state` 里，端点下游会出现 `tech:<名字>` 与 `poc:<id>` 两类派生节点（边类型 `tech` / `candidate`）：前者是识别到的技术栈，后者是 PoC `info.requires` 命中的现成候选，只表示「值得验证」。从 hostport 看完整链路需要 `depth: 4`。
- 同一事实重扫不会新增行：id 由内容算出并按 `(project_id, id)` 去重，可以当作稳定引用。
- 观测流是**尽力而为**的旁路证据：写入异步、缓冲满时丢尾部并计数，单库默认保留 20 万行（`afrog-config.yaml` 的 `observe.max_rows`，`0` 表示不限），不存原始报文（片段上限 2 KB）。

## REST 入口（/api/v1）

同一个 Web 服务还提供与 MCP 同名同语义的 REST 接口，便于不支持 MCP 的脚本直接调用。返回的 payload 与 MCP 工具一致（不套 `success/message` 信封），鉴权沿用 Web 控制台登录态。只读查询是一批固定路径的 GET；其余工具（写动作 `probe.*` / `verify.*` / `act.*` / `poc.submit`，以及本地 advisory `judge.*` / `learn.*`）统一走一个 `POST /api/v1/call`。

| 方法 | 路径 | 对应工具 |
| --- | --- | --- |
| GET | `/api/v1/observe/findings` | `observe.findings` |
| GET | `/api/v1/observe/evidence/{id}` | `observe.evidence` |
| GET | `/api/v1/observe/state` | `observe.state` |
| GET | `/api/v1/observe/observations` | `observe.observations` |
| GET | `/api/v1/plan/next` | `plan.next` |
| GET | `/api/v1/poc/search` | `poc.search` |
| POST | `/api/v1/call` | 任意工具（写动作面） |
| GET | `/api/v1/health` | 探活（无需登录） |

查询参数与工具入参同名：`project_id`、`status`、`severity`、`page`、`limit`、`subject`、`depth`、`direction`、`since_seq`、`sources`、`kinds`、`subject_under`、`keyword`。列表参数同时支持 `?k=a&k=b` 与 `?k=a,b`。

```bash
# 密码见 afrog web 启动日志中的「Web访问密码」
TOKEN=$(curl -s -X POST http://127.0.0.1:16868/api/login \
  -H 'Content-Type: application/json' \
  -d '{"password":"<Web访问密码>"}' | jq -r '.token')

curl -s "http://127.0.0.1:16868/api/v1/observe/observations?since_seq=0&limit=20" \
  -H "Authorization: Bearer $TOKEN"
```

`POST /api/v1/call` 是与 MCP 完全同源的工具调用入口：请求体为 `{"name": "<工具名>", "arguments": {...}}`，返回体与 MCP 工具一致。它和 MCP（stdio/SSE/streamable）**共用同一份策略、预算与审计**，因此脚本直连 REST 也不会绕过限额——策略判定、预算扣减、审计落盘的路径完全相同。错误码按语义区分：策略拒绝 `403`、预算耗尽 `429`、未知工具 `404`、参数错误 `400`。

```bash
# 写动作面：调用任意工具（示例为一次受限验证）
curl -s -X POST "http://127.0.0.1:16868/api/v1/call" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"scan.start","arguments":{"target":"https://example.com","search":"thinkphp"}}'
```

写动作面（REST / gRPC）与 `afrog mcp`（未显式传 `-policy`/`-audit` 时）的策略与审计同源，都来自 `afrog-config.yaml` 的 `agent` 段；**不配置即沿用只读默认**——默认不获得发包能力：

```yaml
agent:
  policy: /path/to/agent-policy.yaml   # 策略 YAML；留空表示只读默认策略
  audit: /path/to/audit.jsonl          # 判定审计 JSONL；留空表示不记录
  oob: ceyeio                          # 工具面的反连适配器（取值同 CLI -oob）；凭据取自 reverse 段，留空则 act.oob_* 不可用
```

`agent.policy` 与 `afrog mcp -policy` 的格式完全一致（见上文「策略与预算」），Web 控制台保存的也正是这个字段。与 CLI 的一次性进程不同，Web 服务是长驻进程，`budget.requests` 是整个进程共享的一份会话额度、跨请求累计扣减，与 `afrog mcp -listen` 的长驻语义一致；它不会「用满就永久失效」，连续空闲 `budget.duration` 后自动开新会话补满。

`agent.oob` 只在需要带外回连时才配：它指定反连适配器（`ceyeio` / `dnslogcn` / `alphalog` / `xray` / `revsuit` / `interactsh`，取值与 CLI `-oob` 一致），凭据复用 `reverse` 段（见配置参考「reverse 是什么」）。配置后 `act.oob_payload` 铸地址、`act.oob_wait` 等回连；`scan.start` / `poc.submit` 跑反向 PoC（含 `{{oob.*}}` 或 `oobCheck`）时也走它——只把适配器名下发给子进程，子进程复用 `reverse` 凭据。留空则这几处都明确报「未配置」，而不是静默等待一个不会来的回连——反向 PoC 不会因此被悄悄判成「未命中」。

## gRPC 入口（AgentService）

不支持 HTTP 的场景（其它语言、集群内调用、未来的编排器）可以用 gRPC 直接调用同一批工具。控制面服务由 `afrog serve` 启动：

```bash
afrog serve -listen :16869 -api-token your-token
```

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-listen` | `:16869` | gRPC 监听地址（Web UI 用 16868，控制面用相邻端口） |
| `-api-token` | 随机生成 | 控制台 API token；留空则随机生成并在启动时打印 |
| `-max-running` | 并发扫描上限 | 同时运行的任务数 |
| `-event-buffer` | 事件窗口 | 每个任务保留的事件条数上限 |

同一个监听上有两组服务：

| 服务 | 职责 |
| --- | --- |
| `afrog.v1.AfrogScanner` | 扫描任务：提交、事件流、状态、结果、节点管理 |
| `afrog.v1.AgentService` | 工具面：`ListTools` / `Invoke`，与 MCP 同名同义 |

`AgentService` 与 MCP `tools/list` / `tools/call` 一一对应：

| gRPC 方法 | 对应 MCP | 入参 / 返回 |
| --- | --- | --- |
| `ListTools` | `tools/list` | 返回每个工具的 `name`、`description`、`input_schema_json`（入参 JSON Schema 的 JSON 编码） |
| `Invoke` | `tools/call` | 入参 `name` + `arguments_json`（工具入参的 JSON 编码，空视为无参数），返回 `result_json`（与 MCP / REST 返回体逐字一致） |

工具入参与返回值都用 **JSON 透传**：工具契约只在 `pkg/mcp` 维护一份，proto 不镜像一套 schema，避免两份真相漂移（与 `Evidence.native_json` 同一理由）。

`AgentService` 与 MCP / REST **共用同一个 `policy.Gate`**：同一份工具注册表、同一套策略判定、预算扣减与审计落盘。策略与审计同样来自 `afrog-config.yaml` 的 `agent` 段，**不配置即只读默认**——控制面默认不发包。长驻进程同样共享一份会话额度，空闲超时后自动补满。

错误码与 REST 语义一致：

| 情形 | gRPC | REST |
| --- | --- | --- |
| 策略拒绝 | `PermissionDenied` | `403` |
| 预算耗尽 | `ResourceExhausted` | `429` |
| 未知工具 | `NotFound` | `404` |
| 参数错误 | `InvalidArgument` | `400` |

以 `grpcurl` 调用（鉴权头为 `authorization: Bearer <token>`）：

```bash
# 列工具
grpcurl -H 'authorization: Bearer your-token' \
  -plaintext 127.0.0.1:16869 afrog.v1.AgentService/ListTools

# 调工具（示例：读攻击面子图）
grpcurl -H 'authorization: Bearer your-token' -plaintext \
  -d '{"name":"observe.state","arguments_json":"{\"subject\":\"example.com\"}"}' \
  127.0.0.1:16869 afrog.v1.AgentService/Invoke
```

## 典型流程

1. `observe.findings` 拿到一条可疑命中；
2. `observe.evidence` 读证据，确认判定依据与复现命令；
3. 需要复测时用 `scan.start`（按技术栈关键词并发跑一批，或 `probe.http` 发一次请求）验证；
4. 需要复核旧结论时用 `verify.replay`，只给证据 id：重放成功但 digest 变了，说明目标行为或 PoC 已经变化；
5. `observe.state` 看这个端点所在资产还暴露了哪些上下游与未覆盖面；
6. 需要「过程事实」而不只是结论时，用 `observe.observations` 按 `since_seq` 增量拉取：开放端口、指纹、主动请求的往返、被动流量、证书与带外回连都在里面；
7. 不知道该先试哪条 PoC 时用 `plan.next`：它按确定性分数给出 `scan.start` / `probe.fingerprint` 提议与依据（同一源站的候选合并成一条 `scan.start`），只读、零预算，选中的那条仍需再走一次 `scan.start` / `probe.*` 的策略与预算门控；
8. 让模型写出草稿后，先 `poc.draft` 校验（`save: true` 落盘），再用 `poc.submit` 在一台真实目标上受限实跑取证据；拿到证据的候选进入待人工终审队列，由人在 CLI 用 `afrog poc approve/reject` 决定是否入库。

已有可疑命中但还没有现成 PoC 时，可以让模型写出草稿，先 `poc.draft` 校验（`save: true` 落盘），再把它返回的 `poc_path` 交给 `poc.submit` 受限实跑。草稿的判定仍然只发生在实跑，`poc.draft` 不发任何请求。

### 候选 PoC 的收口：`poc.submit` 与 `afrog poc`

`poc.submit` 把草稿在真实目标上跑一次（受限实跑：并发 1、限速 10、命中即停），**只有拿到证据才进队列**；拿不到证据的候选不会入库。入队后状态是 `pending`，入库动作只能由人在 CLI 发起——模型没有「自己写进 PoC 目录」的路径。

```bash
afrog poc pending [--json]            # 列出待审候选（默认子命令）
afrog poc list --status approved      # 按状态列出：pending|approved|rejected
afrog poc show <id> --json            # 查看一条候选详情（含草稿路径、证据 id/digest）
afrog poc approve <id>                # 批准并写入 ~/.config/afrog/pocs-my
afrog poc reject <id> -note "误报"     # 驳回，保留草稿与原因
afrog poc stats [--json]              # 流水线指标：自动入库率等

afrog learn list [--status s]         # 调优建议的人工审阅：list/show/accept/reject
```

- 同 id 的草稿被重新 `poc.submit` 时会刷新内容并**回到 `pending`**：YAML 变了，旧证据不再代表它。
- `approve` 会挡掉与非 my 来源（curated / local / append / builtin）同 id 的候选，避免写进 `pocs-my` 后被去重优先级静默忽略。
- 入库路径与 Web 控制台「新建 PoC」一致，都是 `~/.config/afrog/pocs-my`。

### 研判与调优的收口：`judge.*` / `learn.*`

决策面里「Judge / Learner」两个角色同样只产出 advisory，落库位置与漏洞台账**分表隔离**：

- `judge.brief` 取研判材料（证据链 + 同目标观测 + 子图 + 已有意见），模型研判后用 `judge.record` 记录意见到 `judgement` 表（`likely_true`/`likely_false`/`uncertain`）。这份意见只供人工复核，**不改漏洞台账**。
- `learn.brief` 取学习素材（流水线指标 + 终审流水 + 既有建议），模型据 `afrog poc stats` 的入库率与驳回原因给出调优建议，用 `learn.record` 落到 `learn_suggestion` 表。
- `afrog learn accept <id>` **只记录人的决策**：afrog 不解析、不自动应用 diff，规则/阈值变更仍由人走正常代码流程。

## 注意事项

- **`act.brute` 是破坏性动作**：默认拒绝，必须 `mode: full` 且 `destructive: true`。建议同时用 `scope` 与较小的 `budget` 收口。
- `max_requests` 只约束 YAML `brute` 字典；JS/Go PoC 在脚本内部循环发包，外部既数不出也拦不住，只能靠 `timeout` 与预算兜底。
- 工具读取的是本机 `~/.config/afrog/afrog.db`，与 Web 控制台、命令行共享同一份数据。
- 没有证据的旧命中（本功能上线前产生的）`observe.evidence` 会返回未找到，这属于预期行为。

> **← 上一篇：** [定时与计划扫描](./09-scheduled-scans.md) ｜ **本手册首页：** [afrog 简介](./01-overview.md) ｜ **下一篇 →：** [小白教程：把你的 AI 客户端接入 afrog](./11-mcp-quickstart.md)
