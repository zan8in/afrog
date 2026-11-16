<!--
title: 小白教程：把你的 AI 客户端接入 afrog
slug: /docs/user-guide/mcp-quickstart
lang: zh
summary: 从零开始把 afrog 接进常见 AI 客户端：先确认版本，再跑通 afrog mcp，然后按客户端逐一填配置并验证通过，最后按需放开发包能力。
status: published
source: new
last_reviewed: 2026-11-15
-->

## 这份教程带你做什么

一句话：**让 Claude、Cursor 这类 AI 客户端，能直接读到你 afrog 扫出来的漏洞。**

afrog 通过 [`afrog mcp`](./10-mcp.md) 把自己变成一台 MCP 服务器；你的 AI 客户端作为「客户端」连上来，就能调用 afrog 的工具去查命中、取证据、看攻击面。

跟着走完，你会依次做到四件事：

1. 确认本机的 afrog 是不是「带 MCP 的新版」；
2. 手跑一次 `afrog mcp`，亲眼看到它能应答；
3. 在你正在用的客户端里填好配置，**验证到工具真的被调用**；
4. 明白「默认只能看、不能打」是怎么回事，以及想放开时怎么放开。

> 不想敲命令？Web 控制台左侧「Agent 工具面 → 快速上手」有同一份教程的图形化版本，每一步都能一键复制配置。

全程只需要一个终端和一个 AI 客户端，不需要写代码。

## 第 0 步：先确认你的 afrog 是新版

MCP 是后来加进 afrog 的能力。老版本里**根本没有 `mcp` 这个子命令**，配了也连不上，还容易卡住不报错。先花 5 秒验证：

```bash
afrog mcp -h
```

看到下面这段（输出在标准错误里）就对了：

```text
Usage of afrog mcp:
  -audit string
    	策略审计日志路径（JSONL）；留空不记录
  -listen string
    	以 HTTP+SSE 方式监听（如 127.0.0.1:16870）；留空走 stdio
  -policy string
    	策略 YAML 路径；留空使用只读默认策略
  -token string
    	SSE 模式的访问 token；监听非本机地址时必须提供
```

**如果是下面这几种情况，说明你用的是旧版**：

- 提示 `unknown command`、`flag provided but not defined`；
- 什么都不显示，或者看起来「卡住了」；
- 开始真的去扫描一个叫 `mcp` 的目标。

换一个新版即可：到 [GitHub Releases](https://github.com/zan8in/afrog/releases) 下载对应系统的压缩包，解压后把可执行文件放到一个固定目录：

| 系统 | 压缩包 |
| --- | --- |
| Windows | `afrog_windows_amd64.zip`（解压出 `afrog.exe`） |
| macOS（Apple 芯片） | `afrog_darwin_arm64.tar.gz` |
| macOS（Intel） | `afrog_darwin_amd64.tar.gz` |
| Linux | `afrog_linux_amd64.tar.gz` |

已经装过 afrog、只想升级的，一条命令就够：

```bash
afrog -update
```

### 顺手记下 afrog 的绝对路径

后面所有客户端配置里的 `command` 都要填这一步的路径：

```bash
# macOS / Linux
which afrog

# Windows（PowerShell 或 CMD）
where afrog
```

例如 macOS 上输出 `/usr/local/bin/afrog`，Windows 上输出 `C:\tools\afrog\afrog.exe`，视你的环境而定。

**为什么要绝对路径？** 因为 GUI 客户端（Claude Desktop、Cursor、Cherry Studio 等）不是从你的终端启动的，**继承不到你 shell 里的 PATH**。填 `afrog` 三个字母经常报 `spawn ENOENT`，填绝对路径最稳。

## 第 1 步：手跑一次 `afrog mcp`（30 秒冒烟）

```bash
afrog mcp
```

敲下去之后**它看起来像卡住了——这是正常的**，别急着 Ctrl+C。

`afrog mcp` 是一个长驻进程：它从标准输入读一行 JSON、往标准输出写一行 JSON，然后继续等下一行。终端里没有对话对象，它自然就静静等着。日常使用时，这个「对话对象」由 AI 客户端来扮演。

想立刻确认它是活的，用一条命令模拟一个客户端，连发两条 MCP 请求。

**macOS / Linux（bash / zsh）**

```bash
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
| afrog mcp 2>/dev/null
```

**Windows（PowerShell）**

```powershell
$req1 = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
$req2 = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
$req1, $req2 | & afrog mcp 2>$null
```

正常会输出两行 JSON：

```json
{"jsonrpc":"2.0","id":1,"result":{"capabilities":{"tools":{"listChanged":false}},"instructions":"afrog 把本机的扫描结论、攻击面与 PoC 能力暴露成一组工具…","protocolVersion":"2024-11-05","serverInfo":{"name":"afrog","version":"..."}}}
{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"act.brute",...},{"name":"judge.brief",...}, ...]}}
```

- 第一行是握手成功，`instructions` 是服务端下发的用法说明（客户端会并入模型上下文，见 [MCP 服务 · 工具怎么选](./10-mcp.md)）；
- 第二行是工具清单，**一共 21 个工具**（`server.*` / `observe.*` / `probe.*` / `verify.*` / `act.*` / `poc.*` / `plan.*` / `judge.*` / `learn.*`）。

看到这两行，说明 afrog 这一侧已经完全就绪，剩下的只是「怎么让客户端连上来」。

> 注意：日志被刻意写在标准错误（stderr）上，标准输出（stdout）只跑协议。所以上面 macOS / Linux 用 `2>/dev/null`、Windows 用 `2>$null` 丢掉日志，只留协议数据。如果好奇，把这一段去掉就能看到日志了。

## 第 2 步：先搞懂「默认只能看，不能打」

接入之前必须知道这条，否则你会在客户端里看到一堆「被拦截」而一头雾水。

afrog 的 MCP 默认策略是 **只读（readonly）**：一个刚被拉起来的服务，不会自动获得对目标发包的能力。

| 档位 | Agent 能做什么 | 什么时候用 |
| --- | --- | --- |
| `readonly`（默认） | 查命中、取证据、看攻击面、检索 PoC、记录研判与建议 | 只想让 AI 帮你「读懂结果」 |
| `safe` | 在只读基础上，允许探测与验证（`probe.*` / `verify.*`） | 想让 AI 复测、验证一条可疑命中 |
| `full` | 除显式禁止外全部允许，含执行类与破坏性动作 | 受控的授权目标上 |

**所以测试阶段用默认配置就够**——只读工具已经能证明「接上了」。想放开，见第 5 步。

## 第 3 步：接入你的客户端

### 3.0 通用规则（先看这四条）

1. **`command` 一律填绝对路径**（第 0 步查到的结果）。
2. **一次只加一个 server**，名字建议就叫 `afrog`，方便对照。
3. **改完配置必须重启客户端**，多数客户端不会热加载。
4. **验证话术统一**：接好后在对话里直接说
   > 用 afrog 列出最近的漏洞命中，最多 5 条。

   看到它调用 `observe.findings` 并返回结果，就算通过。

下面按市面主流的客户端分类，挑你正在用的那一节照着做即可。

---

### 3.1 Claude Desktop（桌面端）

**打开配置文件**

菜单栏 `Claude → Settings → Developer → Edit Config`，它会直接帮你打开目标文件。文件路径是：

| 系统 | 路径 |
| --- | --- |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

**填入配置**（把 `/usr/local/bin/afrog` 换成你的绝对路径）

```json
{
  "mcpServers": {
    "afrog": {
      "command": "/usr/local/bin/afrog",
      "args": ["mcp"]
    }
  }
}
```

**重启**：从菜单栏 `Quit` 完全退出（关窗口不算），再重新打开 Claude Desktop。

**验证**

- 新开一个对话，输入框下方的「工具」图标里应该能看到 `afrog`；
- 直接问：「用 afrog 列出最近的漏洞命中，最多 5 条」，它会弹出授权提示，允许后返回结果。

**想走远程 HTTP**：Claude Desktop 的 JSON 主要面向本地 stdio，远程要用 `mcp-remote` 把 HTTP 桥接成 stdio（本机需有 Node.js，且前面得先跑起 HTTP 服务，见第 6 步）：

```json
{
  "mcpServers": {
    "afrog": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote", "http://127.0.0.1:16870/mcp",
        "--header", "Authorization: Bearer your-token"
      ]
    }
  }
}
```

---

### 3.2 Cherry Studio（桌面端，中文界面）

**添加**

`设置 → MCP 服务器 → 添加服务器`，类型选 **标准输入（stdio）**：

| 字段 | 填什么 |
| --- | --- |
| 名称 | `afrog` |
| 命令 | `/usr/local/bin/afrog`（绝对路径） |
| 参数 | `mcp` |

如果上一步已经写好了 JSON，也可以点右上角 `从 JSON 导入`，把 3.1 那段 `mcpServers` 配置粘进去。

**启用**：保存后，把服务器列表里 `afrog` 右侧的开关打开。

**验证**：展开 `afrog` 条目应能看到 21 个工具；在对话界面选中「启用 MCP」，然后提问「用 afrog 列出最近的漏洞命中」。

**想走远程 HTTP**：同样在「添加服务器」里，类型改选 **可流式传输的 HTTP**（或 **SSE**），其余按表填：

| 字段 | 填什么 |
| --- | --- |
| 类型 | 可流式传输的 HTTP（对应 `/mcp`）或 SSE（对应 `/sse`） |
| URL | `http://127.0.0.1:16870/mcp` |
| 请求头 | `Authorization: Bearer your-token` |

---

### 3.3 Cursor（编辑器）

**写入配置**

- 全局（所有项目都能用）：`~/.cursor/mcp.json`
- 只给某个项目用：项目根目录下 `.cursor/mcp.json`

内容与 3.1 完全一致，顶层键是 `mcpServers`：

```json
{
  "mcpServers": {
    "afrog": {
      "command": "/usr/local/bin/afrog",
      "args": ["mcp"]
    }
  }
}
```

**验证**

打开 `Cursor Settings → MCP`，`afrog` 条目应显示为绿点并标注工具数量；在 **Agent 模式**的对话里提问即可（普通补全模式不会调用工具）。

> 两个文件里出现同名 server 时，项目内的 `.cursor/mcp.json` 会**整条覆盖**全局的，不会合并。

**想走远程 HTTP**：把条目换成 `url` 形式（Cursor 的远程条目只需 `url`，不用 `type`）：

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

---

### 3.4 VS Code（GitHub Copilot Chat）

**写入配置**

在项目里新建 `.vscode/mcp.json`：

```json
{
  "servers": {
    "afrog": {
      "type": "stdio",
      "command": "/usr/local/bin/afrog",
      "args": ["mcp"]
    }
  }
}
```

> **最容易踩的坑**：VS Code 的顶层键是 `servers`，其它客户端是 `mcpServers`。写错了不会报错，就是不生效。

**验证**

保存后条目上方会出现 `Start` 的 code lens，点一下等它显示 `Running with 21 tools`；也可以在命令面板执行 `MCP: List Servers` 查看状态，然后在 Copilot Chat 里提问。

**想走远程 HTTP**，把条目换成：

```json
{
  "servers": {
    "afrog": {
      "type": "http",
      "url": "http://127.0.0.1:16870/mcp",
      "headers": { "Authorization": "Bearer your-token" }
    }
  }
}
```

---

### 3.5 Cline（VS Code 扩展）

**打开配置**：在 Cline 面板顶部点 `MCP Servers` 图标 → `Configure` 选项卡 → `Configure MCP Servers`，会打开 `cline_mcp_settings.json`。

**填入**（顶层键是 `mcpServers`）：

```json
{
  "mcpServers": {
    "afrog": {
      "command": "/usr/local/bin/afrog",
      "args": ["mcp"],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

**验证**：MCP Servers 面板里应出现 `afrog` 及其工具数；在对话里提问并允许调用。

**想走远程 HTTP**：把条目换成 `type: "streamableHttp"`（Cline 里这是推荐值；只支持旧传输的场合改成 `"sse"` 并把 URL 指向 `/sse`）：

```json
{
  "mcpServers": {
    "afrog": {
      "type": "streamableHttp",
      "url": "http://127.0.0.1:16870/mcp",
      "headers": { "Authorization": "Bearer your-token" },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

---

### 3.6 Windsurf（编辑器）

**打开配置**

- macOS / Linux：`~/.codeium/windsurf/mcp_config.json`
- Windows：`%USERPROFILE%\.codeium\windsurf\mcp_config.json`

也可以在 Cascade 面板的 MCP 图标里点 `Configure` 打开它。

**填入**（顶层键是 `mcpServers`）：

```json
{
  "mcpServers": {
    "afrog": {
      "command": "/usr/local/bin/afrog",
      "args": ["mcp"]
    }
  }
}
```

**验证**：保存后在 MCP 面板点 `Refresh`，`afrog` 应显示为已连接；在 Cascade 对话里提问。

**想走远程 HTTP**：把条目换成下面这样——注意 Windsurf 的字段是 `serverUrl`，**不是** `url`：

```json
{
  "mcpServers": {
    "afrog": {
      "serverUrl": "http://127.0.0.1:16870/mcp"
    }
  }
}
```

---

### 3.7 Claude Code（命令行）

Claude Code 不用手写 JSON，一条命令搞定：

```bash
# -s user 表示对所有项目生效；想只给当前项目用，可省略 -s 或改成 -s local
claude mcp add afrog -s user -- afrog mcp
```

**验证**

```bash
claude mcp list          # 列表里应出现 afrog
claude                   # 进入会话后执行 /mcp，应显示 afrog 已连接及工具列表
```

之后直接提问「用 afrog 列出最近的漏洞命中」即可。

**想走远程 HTTP**：换成 `--transport http`（只支持旧传输的场合改成 `--transport sse` 并把 URL 指向 `/sse`）：

```bash
claude mcp add --transport http afrog -s user http://127.0.0.1:16870/mcp \
  --header "Authorization: Bearer your-token"
```

---

## 第 4 步：怎么算「测试通过」

不用猜，按这三层依次确认，每一层都过了才叫通过：

| 层次 | 怎么看 |
| --- | --- |
| 1. 连接 | 客户端的 MCP 面板里 `afrog` 是已连接状态，能看到 **21 个**工具 |
| 2. 调用 | 提问后，客户端明确显示它调用了 afrog 的某个工具 |
| 3. 数据 | 返回真实数据：有命中就是 `{"items":[...], "total":N, ...}`；数据库里没数据时是 `{"items":[], "total":0, ...}` |

**「返回空列表」也算通过。** 那说明链路全通了，只是本机台账里还没有命中记录——先跑一次扫描（`afrog -t <目标>` 或 Web 控制台发起扫描），再回来问一次就有内容了。

如果任一层次卡住，对照下一节排错。

## 第 5 步：想让 Agent 真正「发包」

只读够用就可以跳过这一步。当你需要 AI 复测一条命中时，得放宽策略。

策略来源只有一处，CLI 和 Web 读的是**同一份**：

| 启动方式 | 策略来源 |
| --- | --- |
| `afrog mcp` / `afrog mcp -listen` | 优先 `-policy` 参数；没传就读 `afrog-config.yaml` 的 `agent.policy` |
| Web 控制台（`afrog -web`） | 读 `afrog-config.yaml` 的 `agent.policy` |
| 都没配 | 只读默认，不会自动获得发包能力 |

两条路挑一条即可，显式 `-policy` 永远优先于配置文件。

**方式 A：用 Web 控制台改**（推荐，可视化）

`afrog -web` 启动控制台（默认 `:16868`，密码在启动日志里），进入左侧「Agent 工具面 → 策略与审计」，把能力档位从 `readonly` 调到 `safe` 或 `full`，点保存。控制台会把策略写到 `~/.config/afrog/agent-policy.yaml`，并把路径记进 `afrog-config.yaml` 的 `agent.policy`——客户端里的 `afrog mcp` 下次启动就会读它，所以保存后让客户端重新拉起 MCP 进程（重启客户端即可）。

**方式 B：直接给客户端加 `-policy`**（适合一个客户端配一套独立策略）

把下面存成 `agent-policy.yaml`：

```yaml
policy:
  mode: safe                  # readonly | safe | full
  allow: ["observe.*", "probe.*", "verify.*"]
  deny:  ["act.brute"]        # deny 永远优先
  scope:
    allow_hosts: ["10.0.0.0/8"]   # 只允许这几个网段
    deny_hosts:  []
    deny_paths:  ["/logout"]
  budget:
    requests: 2000            # 一次会话的请求额度；留空回落默认 5000
    duration: 30m             # 空闲窗口；留空回落默认 10 分钟
  destructive: false
  audit: true
```

然后把客户端配置的 `args` 改成：

```json
"args": ["mcp", "-policy", "/绝对路径/agent-policy.yaml", "-audit", "/绝对路径/audit.jsonl"]
```

改完**重启客户端**生效（`-audit` 同理：没传就用 `afrog-config.yaml` 的 `agent.audit`）。加了 `-audit` 之后，每次「放行还是拒绝」都会逐条写进 JSONL，排查起来很方便。

> 提示：档位放得越开，越要记得用 `scope.allow_hosts` 和 `budget` 收住范围，别让 Agent 在整个网段里乱跑。

## 第 6 步：走 HTTP（多个客户端共享一个 afrog）

stdio 模式下每个客户端都会各起一个 `afrog mcp` 进程。如果你想让多个客户端（或远端机器上的客户端）共用同一台 afrog，改用 HTTP：

```bash
afrog mcp -listen 127.0.0.1:16870 -token your-token
```

`-token` 不是哪里能查到的固定值，而是**你自己定义的一串口令**（共享密钥）：服务端 `-token` 写什么，客户端的 `Authorization: Bearer` 就写什么，两边一致才放行。建议用一段长随机串，例如 macOS / Linux 执行 `openssl rand -hex 32`，Windows PowerShell 执行 `[guid]::NewGuid().ToString('N')`。

- 客户端里填 `url`，并带上 `Authorization: Bearer <你的-token>`；
- 想确认服务活着：`curl http://127.0.0.1:16870/healthz` 返回 `ok`；
- 想监听**本机之外的地址**（如 `0.0.0.0:16870`）**必须**带 `-token`，否则 afrog 会拒绝启动；只监听 `127.0.0.1` 时即便不带 `-token` 也能启动（等于不鉴权，仅限本机访问）。

afrog 在同一个监听上同时提供两种传输，客户端按自己支持的选：

| 传输 | 端点 | 说明 |
| --- | --- | --- |
| Streamable HTTP | `http://127.0.0.1:16870/mcp` | 现行规范，推荐 |
| HTTP+SSE | `http://127.0.0.1:16870/sse` | 2024 旧版，只有部分客户端还只认它 |

各客户端字段名不一样（`url` / `serverUrl`，是否要 `type` 也不同），逐个见第 3 步里每个小节末尾的「想走远程 HTTP」。

两个正常现象，别当成故障：

- 用浏览器直接打开 `http://127.0.0.1:16870/mcp` 会返回 **405**。这是对的——这个入口只接受 POST，不支持 GET。
- 不带 token 请求会返回 **401**。

## 第 7 步：进阶速览（按需）

前 6 步能让你「接上并用起来」。下面四件事是接上之后最常被问到的，各用一句话说清，细节见文末链接。

### 审计日志：出问题先看它

每次工具调用「放行还是拒绝」都会逐条写成一行 JSONL，排查权限问题时它最直接。

```bash
# 指定审计文件；也可写进 afrog-config.yaml 的 agent.audit
afrog mcp -policy ./agent-policy.yaml -audit ./audit.jsonl
```

- 策略里写 `audit: true` 才会开启记录；
- 图形界面在「Agent 工具面 → 策略与审计」用表格看：最近 200 条（上限 1000），每行是时间、动作、目标、放行/拒绝、命中规则、原因与剩余预算。

### 策略档位与 scope：既放开能力，又收住范围

默认只读；要发包就调档位，同时**一定要用 `scope` 把目标限死**，别让 Agent 在整张网里跑。

```yaml
policy:
  mode: safe                 # readonly（默认）| safe | full
  deny: ["act.brute"]        # deny 永远优先
  scope:
    allow_hosts: ["10.0.0.0/8"]
```

- 判定顺序固定为 `deny → allowlist → mode → destructive → scope`；
- 图形界面保存后会回写进 `afrog-config.yaml` 的 `agent.policy`，所以客户端里不起眼的 `afrog mcp` 也读同一份。

### 预算与 429：会话额度

`budget.requests` 是**一次会话**的请求额度（默认 5000），用满后发包类动作会被拒绝并返回 **429**；但只要**连续空闲** `budget.duration`（默认 10 分钟）就会自动开一次新会话、把额度补满，**不需要重启进程**。

- 报 429：要么把 `budget.requests` 调大，要么停一会儿等下一次消耗额度的调用自动开新会话；
- **只读动作不扣额度**：`server.*` / `observe.*` / `plan.*` / `judge.*` / `learn.*` / `poc.search` / `poc.draft` 这类不产生网络请求的调用完全不消耗额度，也不受空闲窗口影响（想知道还剩多少额度，直接调只读的 `server.status`）；
- 被策略拒绝（403）**不消耗预算**；`scan.start` / `poc.submit` 这类按候选 PoC 可能的请求数**预留**预算，不是固定扣 1；
- 长驻进程（Web 服务、`afrog mcp -listen`）的额度是**整个进程共享的会话额度**，跨客户端累计扣减，同样靠空闲超时自动补满。

### OOB 反连：反向 PoC 的前提

命令执行、XXE、SSRF 这类「目标不会直接回显、只能靠带外回连确认」的验证，要先配好反连平台。

```yaml
# afrog-config.yaml
agent:
  oob: ceyeio        # ceyeio | dnslogcn | alphalog | xray | revsuit | interactsh
```

- 凭据复用 `reverse` 段；没配时 `scan.start` / `poc.submit` 遇到反向 PoC 会**明确报错**（fail-closed），而不是静默判为「未命中」；
- `plan.next` 给出的候选若带 `requires_oob: true`，说明它靠带外回连下结论，执行前先把 `agent.oob` 准备好。

**深读：** [MCP 服务](./10-mcp.md)（策略 / 预算与审计 / 工具清单 / REST / gRPC）｜[配置文件](./05-configuration.md)（`agent` 与 `reverse` 字段）｜[Agent 工具面](../web/12-agent.md)（图形界面的人审队列、工具台、策略与审计）

## 排错速查

| 症状 | 原因 | 解决 |
| --- | --- | --- |
| 客户端里根本看不到 afrog | 配置写错 / 没重启客户端 | 检查 JSON 语法与顶层键（VS Code 是 `servers`，其余是 `mcpServers`），然后完全重启客户端 |
| 报 `spawn afrog ENOENT` / 命令找不到 | `command` 写了 `afrog` 而非绝对路径 | 换成第 0 步查到的绝对路径（macOS / Linux 用 `which afrog`，Windows 用 `where afrog`） |
| `afrog mcp -h` 报 unknown command | afrog 是旧版，没有 MCP | 到 GitHub Releases 下载新版，或执行 `afrog -update`（见第 0 步） |
| 终端里 `afrog mcp` 卡住不动 | 这是正常行为，它在等标准输入 | 不要 Ctrl+C；用第 1 步的冒烟命令验证 |
| 工具列出来了，但全显示「被拦截」 | 默认策略是只读 | 见第 5 步放宽档位 |
| 调用报 401 | HTTP 模式的 token 不对 | 客户端 `Authorization: Bearer <token>` 与服务端 `-token` 保持一致 |
| 调用报 429 | 本次会话的请求额度用尽了 | 提高 `budget.requests`，或空闲 `budget.duration` 后自动开新会话补满 |
| 调用报 403 | 被策略拒绝（可能是 `deny` 或 `scope`） | 看客户端返回的规则名与原因，改策略后重启 |
| 提示需要配置反连（OOB） | 跑的是反向 PoC，但没配 `agent.oob` | 在 `afrog-config.yaml` 的 `agent.oob` 里配反连适配器 |
| 返回空列表 | 本机台账里还没有命中 | 先跑一次扫描，再问一次 |

## 下一步

- 每个工具具体做什么、入参怎么填、返回值长什么样 → [MCP 服务](./10-mcp.md)
- 在图形界面里用人审队列、工具台、策略面板 → [Agent 工具面（MCP）](../web/12-agent.md)
- 脚本直连（不装 MCP 客户端）→ [MCP 服务 · REST 入口](./10-mcp.md)

> **← 上一篇：** [MCP 服务](./10-mcp.md) ｜ **本手册首页：** [afrog 简介](./01-overview.md) ｜ **文档首页 →：** [afrog 文档](../index.md)
