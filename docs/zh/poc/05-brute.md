<!--
title: brute 机制
slug: /docs/poc/brute
lang: zh
summary: afrog PoC brute 参考，帮助你判断什么时候该遍历，以及 mode、commit、continue 怎么组合。
status: published
source: docs/afrog-poc-guide.md, docs/tutorial/rumen-dao-rutu/05-poc-advanced.md
last_reviewed: 2026-09-16
-->

`brute` 用于让一条规则按一组候选值重复执行。

这页最适合解决三类问题：

- 我现在到底需不需要 `brute`
- `clusterbomb` 和 `pitchfork` 该怎么选
- `commit`、`continue` 到底会留下哪一次命中的结果

如果你只需要验证单个值，不要急着上 `brute`；如果你需要遍历一组候选输入，它就是最自然的工具。

## 先判断什么时候该用

推荐使用 `brute` 的场景：

- 路径字典探测
- 用户名 / 密码组合
- 先提取多个 ID，再逐个验证
- 某个参数需要从多个候选值里枚举

不一定需要 `brute` 的场景：

- 只验证一个固定参数
- 只提取第一个值就够了
- 没有“列表”或“组合”的需求

## 适合什么场景

最常见的几类用法：

- 路径字典探测
- 弱口令或默认口令组合验证
- 先提取多个 ID，再逐个验证

## 常用字段

- `mode`
- `commit`
- `continue`

以及一个或多个待遍历变量，例如：

```yaml
brute:
  user:
    - admin
    - test
```

### 字段速查

| 字段 | 是否常用 | 作用 | 默认值 |
| --- | --- | --- | --- |
| `mode` | 常用 | 控制如何遍历多个变量 | `clusterbomb` |
| `commit` | 常用 | 控制命中后保留哪组结果 | `winner` |
| `continue` | 常用 | 命中后是否继续跑完 | `false` |
| 自定义变量 | 必需 | 被遍历的候选列表 | 无 |

## 默认行为

如果你只写 payload 变量，没有显式写 `mode`、`commit`、`continue`，默认等价于：

```yaml
brute:
  mode: clusterbomb
  commit: winner
  continue: false
  p:
    - /
    - /jeecg-boot
```

这意味着：

- 默认按 `clusterbomb` 遍历
- 命中后保留第一组命中的变量、请求和响应
- 默认命中即停
- 如果只有一个变量，本质上就是按列表顺序逐个尝试

## 先记住这三个核心问题

### 1. 我要不要全组合

- 要全组合：`clusterbomb`
- 要一一配对：`pitchfork`

### 2. 命中后是停还是继续

- 想尽快结束：`continue: false`
- 想跑完整个列表：`continue: true`

### 3. 最终留下哪次命中

- 留第一次：`winner` / `first`
- 留最后一次：`last`
- 只关心命中，不关心具体变量：`none`

## `mode`

### `clusterbomb`

适合笛卡尔积遍历。

如果你有：

- 多个用户名
- 多个密码

它会做全组合尝试。

### `pitchfork`

适合按索引一一配对遍历。

比如：

- 第 1 个用户名配第 1 个密码
- 第 2 个用户名配第 2 个密码

### 怎么选更快

大多数“账号 + 密码字典”场景默认优先 `clusterbomb`；只有当两组列表天然一一对应时，才更适合 `pitchfork`。

## `commit`

`commit` 控制命中后变量如何保留。

### `winner`

保留第一组命中的变量、请求和响应。

### `first`

当前实现与 `winner` 等价，也保留第一次命中的结果。

### `last`

如果有多次命中，最终保留最后一次命中的结果。

### `none`

不保留 brute 变量本身，但保留命中的请求和响应。适合“只关心命中，不关心具体枚举值”的场景。

## `continue`

- `false`：命中即停
- `true`：继续跑完整个列表

## 组合理解

- `winner/first + continue: false`：命中即停，保留当前命中
- `winner/first + continue: true`：继续遍历，但最终保留第一次命中
- `last + continue: true`：继续遍历，最终保留最后一次命中
- `none`：不会把 brute 变量提交到全局变量

## 最常见的两种写法

### 单变量枚举

```yaml
rules:
  r0:
    brute:
      p:
        - /
        - /admin
        - /console
    request:
      method: GET
      path: '{{p}}'
    expression: response.status == 200
```

这种情况下，本质上就是按顺序逐个尝试。

### 多变量组合

```yaml
rules:
  r0:
    brute:
      mode: clusterbomb
      user:
        - admin
        - test
      pass:
        - admin
        - 123456
    request:
      method: POST
      path: /login
      body: 'u={{user}}&p={{pass}}'
    expression: response.status == 200 && response_text.icontains("welcome")
```

这种情况下会跑用户名和密码的笛卡尔积。

## 静态列表示例

```yaml
rules:
  r0:
    brute:
      mode: clusterbomb
      commit: winner
      continue: false
      user:
        - admin
        - test
        - guest
    request:
      method: GET
      path: /?user={{user}}
    expression: response.status == 200 && response_text.icontains("welcome")

expression: r0()
```

## 动态列表示例

`brute` 不只支持 YAML 里写死的列表，也支持引用运行期表达式结果，只要最终能求值为字符串列表。

```yaml
rules:
  r0:
    request:
      method: GET
      path: /api/templates
    expression: response.status == 200
    output:
      id_matches: '"\"id\":\"(?P<tid>[0-9]+)\"".bsubmatchall(response.body)'

  r1:
    brute:
      mode: clusterbomb
      commit: winner
      continue: false
      template_id: id_matches["tid"]
    request:
      method: GET
      path: /api/check?id={{template_id}}
    expression: response.status == 200 && response_text.icontains("success")

expression: r0() && r1()
```

## 运行时保护

字典或组合过大时，`brute` 会自我克制，避免一条规则发出过多请求：

- **`--brute-max-requests`**：限制**每条规则** `brute` 的最大请求数，默认 `5000`，设为 `0` 表示不限制
- **截断标记**：一旦被上限截断，会记录一个 `__brute_truncated_<规则名>` 布尔标记（例如 `__brute_truncated_r0`）

也就是说，当一条规则的组合数超过上限时，它不会跑完整个列表，而是停在上限处并留下截断标记。排查「字典里明明有这组凭据却没命中」时，先确认是不是被截断了，必要时调大 `--brute-max-requests`。

## 使用建议

1. 只需要单值时，不必使用 `brute`
2. 中文页面或已解码文本，提取时优先考虑 `submatchall(response_text)`
3. 验证型 PoC 通常优先用 `continue: false`
4. `winner` 和 `first` 当前可以视为同义配置
5. 动态列表来自提取结果时，先确认提取函数返回的是列表结构

## 最容易踩的坑

### 提取结果不是列表

如果你给 `brute` 的不是字符串列表，而是单个字符串或结构不对的值，运行效果就会和预期不一致。

### 本来只需要一个值，却上了 brute

很多 PoC 其实用 `submatch` 拿一个值就够，不需要额外引入遍历逻辑。

### `continue: true` 导致请求量超预期

当列表很大时，`continue: true` 会把所有组合都跑完，成本明显增加。

> **← 上一篇：** [requires 指纹门控](./04-requires.md) ｜ **本手册首页：** [PoC 编写快速开始](./01-quickstart.md) ｜ **下一篇 →：** [OOB 带外检测](./06-oob.md)
