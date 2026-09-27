# afrog 扫描能力服务协议（gRPC）PRD

## 1. 背景

`afrog -web` 目前在同进程内直接调用 `pkg/sdk`（`pkg/web/scans.go` 的 `sdk.New(...)`）。新版 SDK 文档已明确：

> 同一进程内不支持多个扫描器并行运行。HTTP 客户端、限速器和协议探测缓存都是进程级全局状态，并行的扫描器会互相覆盖代理、超时和速率配置。

而 Web 端默认允许 6 个并发任务（`AFROG_MAX_RUNNING_TASKS`，见 `pkg/web/scans.go`），即**并发扫描会互相污染参数**。同时：

- 进度数字出现「命令行 `tasks=3626` / Web `3630`」这类口径不一致，因为进度数据来自 SDK 估算、引擎计数、阶段计数三个层次（SDK 测试注释已承认「pre-execution task estimate rarely matches the exact number of tasks run」）。
- 前端 `ScanTask` 已预留 `serverTaskId` / `serverBaseUrl` / `serverInstanceId` 字段，`restore()` 也会汇总多个实例的 `active_task_ids`，但后端 `instances` API 只是返回自身的桩实现。
- 渗透场景下，目标常位于只有某台跳板机可达的内网，**需要让扫描器在目标的网络位置运行**。

因此本次将 afrog 从「命令行工具 / 进程内库」升级为「**可被 Web、其他语言、未来的 AI 编排的扫描能力服务**」。

## 2. 范围

### 2.1 本批交付（第一、二、三层）

| 层 | 内容 |
|---|---|
| 第一层 | 进程隔离执行器、`-json-stream` 事件流、常驻 gRPC 服务、异步任务模型、鉴权与配额 |
| 第二层 | Web 后端接入新服务（前端零改动）、启用前端已有的多实例字段 |
| 第三层 | `afrog agent` 跨服务器节点、节点管理、结果汇聚、跨节点控制 |

### 2.2 本批不做

- MCP 适配层（第四层）——但 proto 需为其预留公开接口
- 多租户 / 用户体系（仍是单密码登录 + token）
- 调度策略、节点自动伸缩、集群自愈
- 结果跨节点去重合并
- **PoC 集中下发**：节点使用本机 PoC；curated 各自授权（授权绑定设备指纹，一个 key 不能铺满集群）
- Web 前端主视觉改造（按 `afrog-web-scan-ux-prd.md` 独立推进）

## 3. 术语

| 术语 | 含义 |
|---|---|
| 控制面（console） | 常驻服务，负责任务提交、节点管理、事件汇聚、结果落库、对外 gRPC API |
| 节点（node） | 实际执行扫描的位置。本机也是一种节点（`node = local`） |
| 任务（task） | 一次扫描，拥有全局唯一 `task_id` |
| 事件（event） | 任务产生的一条流式消息（状态/进度/结果等） |
| 执行器（executor） | 统一抽象：本地进程执行器、远程节点执行器 |

## 4. 架构

### 4.1 本机模式

```
Web 前端 ──HTTP/SSE──▶ 控制面 ──gRPC──▶ 本地执行器 ──spawn──▶ afrog ... -json-stream
                                                              （每任务一进程）
```

### 4.2 跨服务器模式

```
Web 前端 ──HTTP/SSE──▶ 控制面 ◀──gRPC 双向流（agent 主动出站）── afrog agent
                         │                                          │
                         │                                     spawn 子进程
                         ▼                                          ▼
                     sqlite（报告）                        afrog ... -json-stream
```

### 4.3 核心原则

1. **每任务一进程**：彻底规避 SDK 的进程级全局状态冲突，崩溃互不影响。
2. **事件语言单一来源**：`-json-stream` 的 NDJSON 与 proto `ScanEvent` 字段一一对应，两者不得私自加字段。
3. **控制面是唯一真源**：节点无状态，任务与结果以控制面为准。
4. **公开接口长期稳定**：`AfrogScanner` 的 v1 只做兼容性演进（只加字段、不改语义）。

## 5. 事件模型

一条事件由「信封 + 载荷」构成，信封负责路由与可靠性，载荷负责业务语义。

| 字段 | 类型 | 说明 |
|---|---|---|
| `v` | string | 协议版本，当前 `"1"`。节点与协议版本不匹配时拒绝并提示升级 |
| `node` | string | 节点 ID，本机为 `local` |
| `task` | string | 任务 ID |
| `seq` | uint64 | **任务内单调递增**，断线续订时用于去重与补发 |
| `ts_ms` | int64 | 事件产生时间（毫秒） |
| `body` | oneof | 见下表 |

| 载荷 | 触发时机 | 关键字段 |
|---|---|---|
| `StatusEvent` | 状态变化 | `status`：`queued`/`starting`/`running`/`paused`/`completed`/`failed`/`cancelled` |
| `ScanInfoEvent` | 开始执行前上报一次 | `total_targets`、`total_pocs`、`total_scans`、`oob_enabled`、`oob_status` |
| `ProgressEvent` | 扫描级进度（约 1s） | `percent`、`finished`、`total`、`rate`、`elapsed_ms` |
| `PhaseEvent` | 阶段进度 | `phase`：`host_discovery`/`portscan`/`webprobe`/`vuln`；`status`、`finished`、`total`、`percent` |
| `ResultEvent` | 命中漏洞 | `severity`、`poc_id`、`poc_name`、`target`、`evidence`（请求/响应，供落库） |
| `PortEvent` | 开放端口 | `host`、`port` |
| `WebProbeEvent` | Web 探测 | `url`、`status`、`title`、`fingerprint` |
| `HostEvent` | 资产发现（存活主机） | `host` |
| `LogEvent` | 诊断日志 | `level`、`text` |
| `DoneEvent` | 任务结束 | `status`、`summary`（命中分布、耗时、实际执行数） |
| `ErrorEvent` | 任务级错误 | `code`、`message` |

### 5.1 可靠性与重连

- 控制面为每个任务维护 `seq` 单调计数器，节点上报的事件必须携带 `seq`。
- 客户端（含 agent）记录 `last_ack_seq`。断线重连后通过 `StreamEvents(from_seq)` 请求补发。
- 控制面为每个任务保留**有限窗口**的事件缓冲（默认最近 5000 条或 10 分钟），窗口外只能通过 `GetStatus` / `GetResults` 获取汇总，不再补发。

### 5.2 术语统一（解决当前数字不一致）

- `ProgressEvent.total` 定义为**引擎下发的任务数**（与命令行 `tasks=` 同源）。
- `DoneEvent.summary.executed` 为**实际执行数**（可能与 `total` 有少量出入，SDK 已声明）。
- 前端只允许展示 `total` 并标注「约」，不允许再引入第二个分母。

## 6. proto 草案

```proto
syntax = "proto3";
package afrog.v1;

// ==================== 公开接口（第三方语言 / 未来 MCP 适配层） ====================
service AfrogScanner {
  rpc SubmitScan(SubmitScanRequest) returns (SubmitScanResponse);
  rpc StreamEvents(StreamEventsRequest) returns (stream ScanEvent);
  rpc GetStatus(GetStatusRequest) returns (GetStatusResponse);
  rpc GetResults(GetResultsRequest) returns (GetResultsResponse);
  rpc Control(ControlRequest) returns (ControlResponse);
  rpc ListCapabilities(ListCapabilitiesRequest) returns (ListCapabilitiesResponse);
}

// ==================== 内部接口（节点 ↔ 控制面） ====================
service AfrogAgent {
  // 用一次性注册令牌换取长期凭据
  rpc Register(RegisterRequest) returns (RegisterResponse);
  // 建立双向流：控制面在流内下发任务/控制，agent 在同一流内回传事件
  rpc Connect(stream AgentMessage) returns (stream ConsoleMessage);
}

// -------------------- 扫描规格（与 CLI 参数一一对应） --------------------
message ScanSpec {
  repeated string targets = 1;

  // PoC 选择
  string poc_source = 2;          // default | curated | my
  repeated string poc_ids = 3;
  string poc_file = 4;
  string search = 5;
  string severity = 6;            // 例："high,critical"

  // 性能
  int32 concurrency = 10;
  int32 rate_limit = 11;
  int32 timeout_seconds = 12;
  int32 retries = 13;
  bool smart = 14;

  // 网络
  string proxy = 15;
  repeated string headers = 16;
  bool follow_redirects = 17;

  // 前置阶段
  bool port_scan = 18;
  string ports = 19;
  bool skip_host_discovery = 20;
  bool web_fingerprint = 21;

  // OOB
  bool enable_oob = 22;
  string oob_adapter = 23;
  string oob_key = 24;
  string oob_domain = 25;

  // 任务元信息
  string task_name = 30;
  repeated string labels = 31;
  string node_selector = 32;      // 标签表达式；空表示本机执行
}

// -------------------- 事件 --------------------
message ScanEvent {
  string v = 1;
  string node = 2;
  string task = 3;
  uint64 seq = 4;
  int64 ts_ms = 5;
  oneof body {
    StatusEvent status = 10;
    ProgressEvent progress = 11;
    PhaseEvent phase = 12;
    ResultEvent result = 13;
    PortEvent port = 14;
    WebProbeEvent webprobe = 15;
    LogEvent log = 16;
    DoneEvent done = 17;
    ErrorEvent error = 18;
    HostEvent host = 19;
    ScanInfoEvent scan_info = 20;
  }
}

message StatusEvent  { string status = 1; }
message ScanInfoEvent{ int32 total_targets = 1; int32 total_pocs = 2;
                       int32 total_scans = 3; bool oob_enabled = 4;
                       string oob_status = 5; }
message ProgressEvent{ int32 percent = 1; int64 finished = 2; int64 total = 3;
                       int32 rate = 4; int64 elapsed_ms = 5; }
message PhaseEvent   { string phase = 1; string status = 2;
                       int64 finished = 3; int64 total = 4; int32 percent = 5; }
message ResultEvent  { string severity = 1; string poc_id = 2; string poc_name = 3;
                       string target = 4; Evidence evidence = 5; }
message PortEvent    { string host = 1; int32 port = 2; }
message WebProbeEvent{ string url = 1; int32 status = 2; string title = 3;
                       string fingerprint = 4; }
message HostEvent    { string host = 1; }
message LogEvent     { string level = 1; string text = 2; }
message DoneEvent    { string status = 1; Summary summary = 2; }
message ErrorEvent   { string code = 1; string message = 2; }

message Evidence {
  repeated Exchange exchanges = 1;
  map<string, string> extractors = 2;
}
message Exchange { string request = 1; string response = 2; bool matched = 3; }

message Summary {
  int64 executed = 1;             // 实际执行任务数
  int64 found = 2;
  map<string, int64> by_severity = 3;
  int64 elapsed_ms = 4;
}

// -------------------- 公开接口消息 --------------------
message SubmitScanRequest  { ScanSpec spec = 1; }
message SubmitScanResponse { string task_id = 1; string node = 2; }

message StreamEventsRequest{ string task_id = 1; uint64 from_seq = 2; }
message GetStatusRequest   { string task_id = 1; }
message GetStatusResponse  { string status = 1; ProgressEvent progress = 2;
                             Summary summary = 3; bool pausable = 4; string node = 5; }
message GetResultsRequest  { string task_id = 1; string severity = 2;
                             int32 page = 3; int32 page_size = 4;
                             DetailLevel detail = 5; }
message GetResultsResponse { repeated ResultEvent items = 1; int64 total = 2;
                             int32 page = 3; int32 page_size = 4; }
enum DetailLevel { SUMMARY = 0; FULL = 1; }

message ControlRequest  { string task_id = 1; ControlAction action = 2; }
message ControlResponse { bool ok = 1; string message = 2; }
enum ControlAction { PAUSE = 0; RESUME = 1; CANCEL = 2; }

message ListCapabilitiesRequest  {}
message ListCapabilitiesResponse { string version = 1; string protocol_version = 2;
                                   int32 poc_count = 3; bool curated = 4;
                                   bool pausable = 5; repeated string nodes = 6; }

// -------------------- 内部接口消息 --------------------
message RegisterRequest {
  string register_token = 1;      // 一次性注册令牌
  string node_name = 2;
  string version = 3;             // afrog 版本
  string protocol_version = 4;    // 协议版本
  string hostname = 5;
  string os_arch = 6;
  repeated string labels = 7;     // 节点标签，如 ["intranet-a"]
}
message RegisterResponse {
  string node_id = 1;
  string node_secret = 2;         // 长期凭据，agent 侧以 0600 权限落盘
}

message AgentMessage {
  oneof body {
    Heartbeat heartbeat = 1;
    ScanEvent event = 2;
    TaskAck ack = 3;
  }
}
message ConsoleMessage {
  oneof body {
    HeartbeatAck heartbeat_ack = 1;
    AssignTask assign = 2;
    ControlRequest control = 3;
    Revoke revoke = 4;
  }
}
message Heartbeat   { int64 ts_ms = 1; int32 active_tasks = 2; }
message HeartbeatAck{ int64 ts_ms = 1; }
message AssignTask  { string task_id = 1; ScanSpec spec = 2; uint64 from_seq = 3; }
message TaskAck     { string task_id = 1; uint64 last_seq = 2; }
message Revoke      { string reason = 1; }
```

## 7. 认证模型

采用**共享 token + 可撤销注册令牌**。

### 7.1 凭据类型

| 凭据 | 用途 | 生命周期 |
|---|---|---|
| 控制台 API token | 外部客户端调用 `AfrogScanner` | 长期，可在控制台轮换 |
| 注册令牌（register token） | 节点首次注册 | **一次性 + 短 TTL（默认 30 分钟）+ 可撤销** |
| 节点凭据（node_secret） | 节点建流与续期 | 长期，可单独撤销 |

### 7.2 注册流程

1. 控制台生成注册令牌（记录在本地凭据库，含 TTL 与使用状态）。
2. 节点执行 `afrog agent --console <host:port> --token <register-token>`。
3. 节点调 `Register`，控制面校验令牌（存在、未过期、未使用）→ 签发 `node_id` + `node_secret` 并标记令牌已用。
4. 节点将凭据写入本地文件（权限 `0600`，参考现有 `pkg/curated` 的授权文件实践）。
5. 节点用 `node_secret` 调 `Connect` 建立双向流。
6. 控制台可随时撤销 `node_id`：节点在下次心跳收到 `Revoke` 后被拒绝，需重新注册。

### 7.3 传输与凭据携带

- 凭据通过 gRPC metadata 传递：`authorization: Bearer <token|node_secret>`。
- 内网可先跑无 TLS；跨公网建议启用 TLS。proto 的凭据字段**预留扩展位**，未来可新增 mTLS 而不改语义。

## 8. 执行器抽象

```go
type ScanExecutor interface {
    Start(ctx context.Context, taskID string, spec *ScanSpec) (ScanHandle, error)
}

type ScanHandle interface {
    Events() <-chan *ScanEvent   // 统一事件流
    Pause() error
    Resume() error
    Cancel() error
    Done() <-chan struct{}
}
```

| 实现 | 说明 |
|---|---|
| `LocalProcessExecutor` | `os.Executable()` 拉起自身，参数由 `ScanSpec` 映射为 CLI 参数，读取 stdout 的 NDJSON |
| `RemoteNodeExecutor` | 通过 gRPC 把任务派发给节点，事件从双向流回流 |

**关键收益**：`-json-stream` 的输出格式与 `ScanEvent` 同构，因此本地模式只是「把网络连接换成管道」，两条路径共用同一个事件解析器。

### 8.1 节点侧控制映射

| 控制动作 | Unix | Windows |
|---|---|---|
| PAUSE | `SIGSTOP` | 不支持，返回 `UNIMPLEMENTED` |
| RESUME | `SIGCONT` | 不支持 |
| CANCEL | `SIGTERM` → 超时后 `SIGKILL` | `taskkill` |

`GetStatus.pausable` / `ListCapabilities.pausable` 需如实上报，前端据此禁用按钮。

## 9. 与现有代码的衔接

| 位置 | 改动 |
|---|---|
| `proto/afrog/v1/afrog.proto` | 第 6 节 proto 的落地文件，生成 `afrog.pb.go` / `afrog_grpc.pb.go`。重新生成：`cd proto/afrog/v1 && go generate ./...`（需 protoc + protoc-gen-go + protoc-gen-go-grpc） |
| `pkg/scantask` | 控制面任务层：受理扫描、并发排队、驱动执行器、维护带 `seq` 的事件窗口与订阅分发。不关心传输，gRPC 与 Web 共用 |
| `pkg/scanapi` | `AfrogScanner` 的 gRPC 实现（6 个 RPC）+ 凭据拦截器 + `afrog serve` 子命令实现 |
| `cmd/afrog` | 新增 `-json-stream` 输出模式（stdout 仅承载 NDJSON，其余输出改道 stderr）；由执行器拉起时优先采用 `AFROG_TASK_ID` 作为任务 ID；新增 `serve` 子命令（在参数解析前分流，因为 goflags 不支持子命令） |
| `pkg/scanstream` | 新增事件信封与 NDJSON 读写（`Writer`/`Parse`），字段与第 5、6 节逐字对齐 |
| `pkg/jsonstream` | `-json-stream` 模式的钩子装配（`RedirectLogs` 把人类可读输出改道 stderr；`Attach` 把引擎回调接到 `scanstream.Writer`）。放在库包而非 `cmd/afrog` 目录下，是为了让文档里的 `go run cmd/afrog/main.go` / `go build -o afrog cmd/afrog/main.go` 这类单文件构建继续可用 |
| `pkg/executor` | 新增执行器抽象与 `LocalProcess`：`Spec` 映射 CLI 参数、解析子进程 stdout 的 NDJSON、暂停/继续/取消、注入 `AFROG_TASK_ID`、每个任务一个独立临时工作目录 |
| `pkg/db/sqlite` | 新增 `SelectPageByTask` / `CountByTask`，供 `GetResults` 按 `task_id` 分页查询结果 |
| `pkg/db/db.go` | `TaskID` 优先取环境变量 `AFROG_TASK_ID`，未设置时维持自生成逻辑，使子进程写库结果归属父任务 |
| `pkg/web/scans.go` | 扫描不再走 `sdk.New`，改为经 `ScanExecutor` 起子进程；`pkg/web/scan_exec.go` 把 NDJSON 事件翻译为前端既有的 SSE 事件（前端零改动）。**尚未切到 `pkg/scantask`，见第 11 节** |
| `pkg/web/types.go` | `ScanStatusData` 新增 `error`，用于回传子进程启动失败等原因 |
| `pkg/web/handlers.go` | `instancesListHandler` 从桩实现改为遍历真实节点（第三层） |
| `pkg/web/webpath`（前端构建产物） | 无需改动 |
| 前端 `scan-store` | 已支持 `serverTaskId` / `serverBaseUrl` / `serverInstanceId`，启用即可 |
| 前端 `scan-progress.ts` | 继续作为进度展示的唯一口径来源 |

### 9.1 本地进程执行器实现要点

- **stdout 解析**：必须用 `bufio.Reader.ReadBytes('\n')`（或给 `bufio.Scanner` 显式设置 ≥8MB 的 buffer）。`bufio.Scanner` 默认单行上限 64KB，超长的请求/响应证据行会触发 `ErrTooLong` 导致整条事件丢失。
- **stderr 必须持续读取**：子进程 stderr 管道写满会阻塞子进程，需独立 goroutine 读完。
- **退出顺序**：先读完 stdout，再 `cmd.Wait()`，最后关闭 `Done()` 通道，保证结尾的 `done` 事件不会因进程退出而丢失。
- **任务 ID 传递**：执行器以 `AFROG_TASK_ID=<task_id>` 注入子进程环境变量（追加到 `os.Environ()`），`pkg/db/db.go` 优先采用它，使子进程写 sqlite 的结果与父任务关联；未设置时行为不变。
- **暂停/取消**：Unix 用 `SIGSTOP`/`SIGCONT` 暂停/继续，`SIGTERM`→宽限期内未退出再 `SIGKILL`；Windows 不支持暂停，返回 `UNIMPLEMENTED`（对应 `ErrPauseUnsupported`）。
- **参数映射的边界**：`poc_ids` / `poc_source` 不对应 CLI flag，需由调用方先解析为具体 PoC 路径并通过 `poc_file`（`-P`）传入，与 `pkg/web/scans.go` 的现有做法一致；`follow_redirects` 与 OOB 的 key/domain 也没有对应 flag（OOB 凭据来自子进程的 `afrog-config.yaml`，`-oob` 只选择适配器）。
- **强制附加的开关**：`buildArgs` 无条件追加 `-json-stream`（事件流是执行器的唯一输出通道）与 `-disable-output-html`。子进程由机器驱动，结果已写入 sqlite 并经事件流回传，若不禁用 HTML 输出则每次扫描都会在控制面进程的工作目录里堆出报告文件。
- **独立工作目录**：`LocalProcess` 默认给每个任务创建临时工作目录并在进程退出后删除。afrog 会往工作目录写 HTML 报告与 `afrog-resume-*.afg` 状态文件（每 10 秒一次），若继承控制面进程的 CWD，长时间运行的服务器目录会被持续污染。
- **写库归属**：子进程自身会通过 `pkg/db/sqlite`（`addx`）把命中写入与控制面同一个 sqlite（WAL + `busy_timeout`），任务 ID 取自 `AFROG_TASK_ID`。因此控制面**不得**再自己落库一遍，否则同一条命中会写入两次。
- **并发验收**：`pkg/executor` 的 `TestLocalProcessSmoke_ConcurrentSpecsDoNotInterfere`（需 `AFROG_EXECUTOR_SMOKE=1`）同时拉起 3 个并发数/限速/目标数各异的真实 afrog 子进程，断言事件信封的 task ID 无串流、结果无串扰、`scan_info` 反映各自规格。
- **控制面侧的映射**：`pkg/web/scan_exec.go` 负责 `ScanCreateRequest → Spec` 与 `Event → SSE` 两层翻译。SSE 事件名与字段刻意保持与旧 SDK 路径完全一致，从而满足 F6「前端零改动」。

### 9.2 控制面实现要点（`pkg/scantask` + `pkg/scanapi`）

- **seq 由控制面分配**：节点上报的 `seq` 不直接透传，控制面在写入事件窗口时重新编号（从 1 起、任务内连续）。这样 `StreamEvents(from_seq)` 的补发语义只依赖控制面的计数器，与节点实现无关。
- **状态由控制面拥有**：执行器上报的 `status` 事件被忽略并丢弃（排队/暂停/收尾都由控制面决定），避免子进程的 `starting`/`running` 与 `paused` 等状态互相矛盾。
- **事件窗口**：每个任务保留最近 `EventBuffer`（默认 5000）条事件。请求的位置早于窗口时，先推一条 `seq=0` 的 `error` 事件（`code=events_truncated`）再用 `GetStatus`/`GetResults` 兜底；`seq=0` 的控制面通知不参与客户端去重。
- **慢订阅者**：订阅通道写满即判定 `ErrSlowSubscriber` 并断开（对应 `ResourceExhausted`），客户端带上 `last_seq` 重连即可补齐——这正是 F4 的机制，而不是静默丢事件。
- **任务 ID 唯一性**：ID 形如 `20260927-00001-c67bc7`，末段是进程随机后缀。序号只是进程内计数器，重启后会从 1 重来；少了后缀，同一天里先后来起的进程会生成同一个 ID，而 sqlite 的命中是按 `task_id` 关联的，旧任务的命中会被算到新任务头上。
- **pausable 如实上报**：Windows 平台恒为 false；排队中（还没有进程）与已结束的任务同样为 false。
- **OOB 凭据明确拒绝**：`SubmitScan` 收到 `oob_key`/`oob_domain` 时返回 `InvalidArgument` 并提示去节点的 `afrog-config.yaml` 配置，而不是静默忽略一个安全相关的参数。
- **结果落库归属**：本机任务由子进程自己写 sqlite（见 9.1）；远程节点扫出的命中必须由控制面按 `ResultEvent.evidence` 写入，否则结果留在节点不上报。

## 10. 验收标准

- **F1** 同时运行 3 个不同代理/限速/并发的扫描，参数互不干扰，结果无串扰。（已在 `pkg/executor` 的 `TestLocalProcessSmoke_ConcurrentSpecsDoNotInterfere` 中自动化）
- **F2** `afrog -t <target> -json-stream` 可实时逐行输出事件，字段与 `ScanEvent` 一致。
- **F3** 外部客户端（grpcurl / Python）能提交扫描并实时接收事件。
  - 实现：`afrog serve --listen :16869 [--api-token <token>]`（留空则随机生成并打印），凭据走 `authorization: Bearer <token>`。
  - 已自动化：`pkg/scanapi` 的 bufconn 用例 + `TestSmoke_RealBinarySubmitStreamReconnectResults`（真实 afrog 子进程，需 `AFROG_SCANAPI_SMOKE=1`），后者同时覆盖「子进程写库 → 控制面按 task_id 查到结果」。
- **F4** 客户端断线后重连，事件不丢不重（依赖 `seq`）。
  - 已自动化：`TestSubscribe_FromSeqReplaysExactlyTheMissingEvents`（对每个切点都验证一遍）与 `TestStreamEvents_ReconnectResumesWithoutLossOrDuplicate`（真实 gRPC 流，中途取消后再用 `from_seq` 续订）。
- **F5** 无凭据调用被拒；超并发配额返回明确错误。
  - 已完成的部分：共享 token 校验（一元与流式两路拦截器）已生效，无凭据/错凭据返回 `Unauthenticated`。
  - 待办：注册令牌与 `node_secret`（7.2 的注册流程）、配额错误语义。目前超出并发上限是**排队**而不是报错（状态为 `queued`），这一点需要与「明确错误」的验收口径对齐后再定。
- **F6** 现有 Web 扫描页功能全部照旧可用（前端零改动）。
- **F7** 任务列表能显示任务来自哪个节点。
- **F8** NAT 后的节点能主动连上控制面并出现在节点列表。
- **F9** 能把一个扫描按标签派发到指定节点执行。
- **F10** 远程节点扫出的漏洞直接出现在 Web 报告页。
- **F11** 在 Web 上暂停/取消远程任务真实生效（Windows 节点如实显示不可暂停）。

## 11. 后续（不在本批）

- **第二层（下一步）**：把 `pkg/web` 从自带的 `TaskManager` 迁到 `pkg/scantask`，让 Web 与 gRPC 共用同一份任务与事件；相应地启用前端已有的 `serverTaskId` / `serverBaseUrl` / `serverInstanceId`，并把 `instancesListHandler` 从桩实现改成真实节点列表。迁移后 `pkg/web` 里那套「日期-序号」任务 ID 会一并换成 9.2 的唯一 ID 方案。
- **第三层**：`afrog agent`（节点侧双向流出站）、节点注册与撤销、按标签派发、跨节点暂停/取消。
- **MCP 适配层**：`afrog-mcp` 提供 5 个 tool（`scan_start` / `scan_status` / `scan_results` / `poc_search` / `scan_cancel`），传输支持 stdio 与 Streamable HTTP。因 `AfrogScanner` 已定义，适配层只需做参数翻译。
- AI 场景的安全阀：目标 allowlist、配额、审计日志、高危动作人工确认。
- 结果跨节点去重与合并。
- PoC 集中下发与节点级授权管理。
- 任务与事件窗口的淘汰策略：目前任务及其事件缓冲在控制面进程内长期保留（尚未实现按时间/数量回收）。
