<!--
title: MCP 使用教程
slug: /docs/user-guide/mcp-tutorial
lang: zh
summary: 面向使用者的 afrog MCP 上手教程：用 `afrog mcp -listen` 起一个常驻 HTTP 服务，接入 AI 客户端，验证连通，再按需放开策略档位。
status: published
source: new
last_reviewed: 2026-11-24
-->

## 这份教程带你做什么

用一个常驻的 **afrog MCP 服务**，让 Claude、Cursor、Cline、VS Code 这类 AI 客户端直接读你的 afrog 结论、看攻击面、探端口、验 PoC——全程受 afrog 的策略、预算与审计约束。

**推荐方式**：只跑**一个常驻 HTTP 服务**，所有客户端都连它。`afrog mcp` 的 stdio 方式也能用，但那样每个客户端都会各起一个 afrog 进程，配置与资源更分散。

> 想按客户端逐个照抄配置？另见 [小白教程：把你的 AI 客户端接入 afrog](./11-mcp-quickstart.md)。

## 前置条件

- 已安装 afrog，终端里能直接执行 `afrog`。
- 已有一个可用的 AI 客户端（Claude Desktop、Cherry Studio、Cursor、VS Code、Cline、Windsurf、Claude Code 等，任选其一）。

## 第 1 步：启动服务

```bash
afrog mcp -listen 127.0.0.1:16870 -token your-token
```

- `-token` 是**你自己定义的一串口令**（共享密钥），不是固定值。生成方法：macOS / Linux 用 `openssl rand -hex 32`，Windows PowerShell 用 `[guid]::NewGuid().ToString('N')`。
- 同一个监听同时提供两种传输：`http://127.0.0.1:16870/mcp`（Streamable HTTP，推荐）与 `http://127.0.0.1:16870/sse`（旧版客户端）。
- 健康检查：`curl http://127.0.0.1:16870/healthz` 返回 `ok` 即服务正常。
- 监听**本机之外**的地址（如 `0.0.0.0:16870`）**必须**带 `-token`，否则 afrog 会拒绝启动。

## 第 2 步：接入 AI 客户端

在客户端里填 URL 并带上 token：

```json
{
  "mcpServers": {
    "afrog": {
      "url": "http://127.0.0.1:16870/mcp",
      "headers": { "Authorization": "Bearer your-token" }
    }
  }
}
```

> 各客户端字段名不一样（`url` 与 `serverUrl` 不同、是否需要 `type` 不同，VS Code 顶层键是 `servers`）。逐个客户端的配置见 [小白教程第 3 步](./11-mcp-quickstart.md#第-3-步接入你的客户端)。

Claude Code 一条命令即可：

```bash
claude mcp add --transport http afrog -s user http://127.0.0.1:16870/mcp \
  --header "Authorization: Bearer your-token"
```

## 第 3 步：验证

在客户端里提问：

> 用 afrog 列出最近的漏洞命中，最多 5 条。

看到它调用 `observe.findings` 并返回结果就算通了——**返回空列表也算通**。

## 第 4 步：让 Agent 真正扫描（选择档位）

MCP **默认只读**：刚拉起的服务完全不会对目标发包。Agent 能做什么由 `policy.mode` 决定。**想要真正的「全漏洞扫描」，必须把 `mode` 设为 `full`**——停在更低档位都会缺东西：

| `mode` | Agent 可以…… | 缺什么 |
| --- | --- | --- |
| `readonly`（默认） | 只能读：命中、证据、攻击面、观测流；检索 / 校验 PoC；看服务状态 | **一切发包能力**——不能探端口、不能识别指纹、不能扫描、不能验证 |
| `safe` | 发包探测（`probe.*`：HTTP / 端口 / 指纹）、跑 PoC（`scan.start`，含 JS 脚本 PoC）、重放证据（`verify.replay`）、提交 PoC（`poc.submit`） | **主动攻击能力**——`act.*` 里的弱口令爆破（`act.brute`）与主动 OOB（`act.oob_payload` / `act.oob_wait`） |
| `full` | 以上全部，**再加** `act.*` | 无——能力完整，afrog 能干的全都能干 |

- **停在 `readonly`**：一条漏洞也扫不到。
- **停在 `safe`**：能探测、能扫描、能验证，但**缺 `act.*` 主动攻击能力**，覆盖不到这一类。
- **只有 `full` 能力上无缺口**，这就是「真正的全漏洞扫描」必须用 `full` 的原因。
- 注意：**`full` 还不是终点**——`destructive` 是与档位正交的独立开关，默认 `false`：`act.brute`、主动 OOB，以及提交 JS/Go（exec 级）PoC 的 `poc.submit`，还额外要求 `destructive: true`；`scan.start` 属 declarative，不受该开关影响。

### 推荐：用 Web 控制台可视化配置（`afrog -web`）

不想手写 YAML，就用内置的 Web 控制台点选——它改的是**同一份策略**，保存后对 MCP 服务立刻生效。

1. **启动控制台**（另开一个终端）：

   ```bash
   afrog -web
   ```

   默认监听 `:16868`，启动后终端会打印本次访问密码：`[INF] Web访问密码: xxxxxxxxxxxxxxxx`。

2. **浏览器登录**：打开 `http://127.0.0.1:16868`，用上一步打印的密码登录。

3. **进入页面**：左侧导航 **Agent → 策略与审计**。

4. **按需设置**（对照上文档位表）：
   - 「能力档位」选 **`full`**——要做真正的全漏洞扫描；只想探测 / 扫描、不涉及爆破可选 `safe`；
   - 需要弱口令爆破这类**破坏性动作**时，再打开「破坏性动作」开关；
   - 「范围限制」用 `allow_hosts` 把目标收在你的授权范围内；
   - 「会话预算」按需调整（留空即回落默认：5000 次 / 10 分钟）。

5. **保存**：点「保存」，提示 **「已保存，立即生效（会话预算随之重置）」**。页面会把策略写成 `agent-policy.yaml`，并把路径回写进 `afrog-config.yaml` 的 `agent` 段。

> **Web 控制台与 `afrog mcp` 读的是同一份策略**：在页面里保存后，MCP 服务**下一次工具调用即刻生效**——既不用重启 `afrog mcp`，也不用重启控制台。

> 反连适配器（`agent.oob`）不在本页编辑，仍在 `afrog-config.yaml` 里设置。该页面的完整说明见 [Web 控制台：Agent 工具面](../web/12-agent.md)。

**也可以直接手写策略文件**（与 Web 控制台保存的是同一份）：

```yaml
# agent-policy.yaml —— 全漏洞扫描用 full；要爆破再打开 destructive: true
policy:
  mode: full                       # readonly（默认）| safe | full
  scope:
    allow_hosts: ["10.0.0.0/8"]    # 无论什么档位，都用 scope 收住范围
```

```bash
afrog mcp -listen 127.0.0.1:16870 -token your-token -policy ./agent-policy.yaml
```

## 几个关键提醒

- **把客户端单次工具超时调到 10 分钟左右**：扫描一跑可能好几分钟，而多数客户端默认只有 60 秒。
- **全端口扫描、全库扫描都支持**：想跑全端口直接说「对 `<主机>` 做全端口扫描」即可（工具会用 `ports: "full"`）；PoC 关键词留空就是全库扫描。
- 只读调用不扣额度；发包类调用从会话额度（默认 5000）里预留，空闲 10 分钟自动补满。随时可调只读的 `server.status` 查看剩余额度。

## 深入阅读

- [小白教程：把你的 AI 客户端接入 afrog](./11-mcp-quickstart.md)——逐个客户端的配置与排错速查。
- [MCP 服务（详细参考）](./10-mcp.md)——工具清单、策略与预算机制、HTTP 部署与安全约定。

> **← 上一篇：** [小白教程：把你的 AI 客户端接入 afrog](./11-mcp-quickstart.md) ｜ **本手册首页：** [afrog 简介](./01-overview.md) ｜ **文档首页 →：** [afrog 文档](../index.md)
