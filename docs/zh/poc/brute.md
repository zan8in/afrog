---
title: brute 机制
slug: /docs/poc/brute
lang: zh
summary: 介绍 afrog PoC 中 brute 的遍历模式、默认行为和动态列表用法。
status: draft
source: docs/afrog-poc-guide.md, docs/tutorial/rumen-dao-rutu/05-poc-advanced.md
last_reviewed: 2026-09-15
---

`brute` 用于让某条规则按一组候选值重复执行，常见于路径探测、用户名密码组合、动态提取 ID 后逐个验证等场景。

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

## 使用建议

1. 只需要单值时，不必使用 `brute`
2. 中文页面或已解码文本，提取时优先考虑 `submatchall(response_text)`
3. 验证型 PoC 通常优先用 `continue: false`
4. `winner` 和 `first` 当前可以视为同义配置

## 相关文档

- [PoC 语法参考](./syntax.md)
- [PoC 编写快速开始](./quickstart.md)
